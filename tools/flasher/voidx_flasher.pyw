# Namoid Flasher - installs firmware on the Namoid pedal (ESP32-S3 on the VoidX DSP module) without Claude.
#
# Safety rules, enforced in code:
#   - only ESP32-S3 application images are written, and only at the start of an app partition read from
#     the pedal's own partition table (never the bootloader, never the partition table, never data areas);
#   - the image must fit inside that partition;
#   - before writing, the partition's current content is saved to backups\ (a restorable .bin);
#   - the whole flash is never erased (no erase_flash) and eFuses are never touched (no espefuse);
#   - esptool verifies what it wrote.
#
# Ships as a single Namoid-Flasher.exe (built on GitHub Actions with PyInstaller): nothing to install.
# It also runs as a script with Python 3, esptool 4.8 and pyserial.

import os
import re
import struct
import sys
import threading
import time
from datetime import datetime

# next to the .exe (single-file build) or to this script
HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
BACKUPS = os.path.join(HERE, "backups")
BAUD = 460800                     # 921600 is not reliable on this board
PT_ADDR, PT_LEN = 0x8000, 0xC00

# firmware projects and where they belong (esp_app_desc_t project_name -> partition label)
KNOWN = {
    "namoid": ("ota_0", "Pedal"),
    "namoid_launcher": ("factory", "Launcher (firmware selector)"),
    "vx_amp": ("ota_0", "Pedal (before the Namoid name)"),
    "vx_launcher": ("factory", "Launcher (before the Namoid name)"),
}
LABELS = {"factory": "Launcher", "ota_0": "Pedal", "ota_1": "Audio interface", "ota_2": "Didactic"}


# ---------------------------------------------------------------- pure logic (testable without hardware)
def parse_ptable(raw):
    """ESP-IDF partition table -> list of dicts (label, type, subtype, offset, size)."""
    parts = []
    for i in range(0, len(raw) - 31, 32):
        e = raw[i:i + 32]
        magic = struct.unpack_from("<H", e, 0)[0]
        if magic == 0xEBEB or magic == 0xFFFF:
            break
        if magic != 0x50AA:
            raise ValueError("partition table not readable (entry %d)" % (i // 32))
        typ, sub, off, size = struct.unpack_from("<BBII", e, 2)
        label = e[12:28].split(b"\0")[0].decode("ascii", "replace")
        parts.append({"label": label, "type": typ, "subtype": sub, "offset": off, "size": size})
    if not parts:
        raise ValueError("empty partition table")
    return parts


def app_parts(parts):
    return [p for p in parts if p["type"] == 0]


def inspect_image(data):
    """Checks an ESP32-S3 app image. Returns dict(project, version, size) or raises ValueError."""
    if len(data) < 0x100:
        raise ValueError("file too small to be a firmware")
    if data[0] != 0xE9:
        raise ValueError("not an ESP application image (missing 0xE9 header)")
    chip_id = struct.unpack_from("<H", data, 12)[0]
    if chip_id != 9:
        raise ValueError("image is for another chip (id %d), the pedal is an ESP32-S3 (id 9)" % chip_id)
    magic = struct.unpack_from("<I", data, 0x20)[0]
    if magic != 0xABCD5432:
        raise ValueError("application description missing: is this a bootloader or a raw dump?")
    d = app_desc(data)
    d["size"] = len(data)
    return d


def app_desc(head):
    """esp_app_desc_t (at 0x20 of an app image): project, version, build date/time, ELF SHA-256."""
    t = lambda a, b: head[a:b].split(b"\0")[0].decode("ascii", "replace").strip()
    return {"project": t(0x50, 0x70), "version": t(0x30, 0x50), "time": t(0x70, 0x80), "date": t(0x80, 0x90),
            "idf": t(0x90, 0xB0), "sha": head[0xB0:0xD0].hex()}


def known_files():
    """firmware .bin next to the program, by ELF SHA-256 (to say which file is on the pedal)"""
    out = {}
    for d in (os.path.join(HERE, "firmware"), HERE, os.path.join(HERE, "..", "firmware")):   # also VoidX-Lab\\firmware
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            if n.lower().endswith(".bin"):
                try:
                    with open(os.path.join(d, n), "rb") as f:
                        out.setdefault(inspect_image(f.read(0x100))["sha"], n)
                except (OSError, ValueError):
                    pass
    return out


def is_blank(data):
    return all(b == 0xFF for b in data[:4096])


def check_plan(img, part):
    """Raises ValueError if img (inspect_image result) cannot go into part."""
    if part["type"] != 0:
        raise ValueError("%s is not a firmware partition" % part["label"])
    if img["size"] > part["size"]:
        raise ValueError("firmware is %d KB, partition %s holds %d KB" % (img["size"] // 1024, part["label"], part["size"] // 1024))
    if part["offset"] < 0x10000 or part["offset"] % 0x10000:
        raise ValueError("unexpected partition address 0x%X" % part["offset"])


# ---------------------------------------------------------------- esptool
# esptool runs inside this program (also in the single .exe): its output goes to the log window.
def esptool_cmd(port, *args, after="hard_reset"):
    return ["--chip", "esp32s3", "-p", port, "-b", str(BAUD), "--before", "default_reset", "--after", after] + list(args)


FORBIDDEN = re.compile(r"erase_flash|erase-flash|erase_region|erase-region|burn|efuse|write_flash_status|write-flash-status")


class _LogWriter:
    """file-like object: whole lines to the log; '\r' lines (progress) overwrite each other"""
    def __init__(self, log):
        self.log, self.buf = log, ""

    def write(self, s):
        for ch in s:
            if ch in "\r\n":
                if self.buf.strip():
                    self.log(self.buf, replace=(ch == "\r"))
                self.buf = ""
            else:
                self.buf += ch
        return len(s)

    def flush(self):
        pass


def run(args, log):
    if any(FORBIDDEN.search(a) for a in args):            # last line of defence
        raise RuntimeError("blocked command: " + " ".join(args))
    import contextlib
    import esptool
    log("> esptool " + " ".join(args))
    w = _LogWriter(log)
    try:
        with contextlib.redirect_stdout(w), contextlib.redirect_stderr(w):
            esptool.main(args)
    except SystemExit as e:
        if e.code not in (0, None):
            raise RuntimeError("esptool stopped (code %s): see the log" % e.code)
    except Exception as e:
        raise RuntimeError("esptool: %s" % e)
    finally:
        w.write("\n")


def list_ports():
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    out = []
    for p in list_ports.comports():
        tag = ""
        if p.vid == 0x303A:
            tag = "ESP32-S3 USB"
        elif p.vid in (0x1A86, 0x10C4, 0x0403):
            tag = "USB-serial"
        out.append((p.device, "%s  %s" % (p.device, tag or (p.description or ""))))
    return out


def read_pedal(port, log):
    """one connection: partition table + the header of every firmware partition (which firmware, which version).
    Only reads; at the end the pedal restarts normally."""
    import contextlib
    from esptool.cmds import detect_chip
    w = _LogWriter(log)
    esp = None
    try:
        with contextlib.redirect_stdout(w), contextlib.redirect_stderr(w):
            esp = detect_chip(port, 115200, "default_reset", False, 7)
            if esp.CHIP_NAME != "ESP32-S3":
                raise RuntimeError("this is a %s, not the pedal's ESP32-S3" % esp.CHIP_NAME)
            esp = esp.run_stub()
            esp.change_baud(BAUD)
            parts = parse_ptable(esp.read_flash(PT_ADDR, PT_LEN))
            for p in app_parts(parts):
                h = esp.read_flash(p["offset"], 0x100)
                if is_blank(h):
                    p["fw"] = None
                else:
                    try:
                        p["fw"] = inspect_image(h)
                    except ValueError:
                        p["fw"] = {"bad": True}
            esp.hard_reset()
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError("could not read the pedal: %s" % e)
    finally:
        w.write("\n")
        try:
            if esp is not None:
                esp._port.close()
        except Exception:
            pass
    return parts


def describe(fw, files):
    if fw is None:
        return "empty"
    if fw.get("bad"):
        return "not a valid firmware"
    s = "%s %s, built %s %s" % (fw["project"], fw["version"], fw["date"], fw["time"])
    if fw["sha"] in files:
        s += "  =  %s" % files[fw["sha"]]
    return s


def backup_part(port, part, log):
    name = "%s_%s_0x%X.bin" % (datetime.now().strftime("%Y%m%d_%H%M%S"), part["label"], part["offset"])
    path = os.path.join(BACKUPS, name)
    log("Backing up %s (%d KB) to backups\\%s" % (part["label"], part["size"] // 1024, name))
    run(esptool_cmd(port, "read_flash", hex(part["offset"]), hex(part["size"]), path), log)   # then the pedal restarts normally
    if os.path.getsize(path) != part["size"]:
        raise RuntimeError("backup incomplete: nothing was written")
    return path


def flash(port, part, path, log):
    run(esptool_cmd(port, "write_flash", hex(part["offset"]), path), log)   # flash mode/size: kept as they are


# ---------------------------------------------------------------- GUI
def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    os.makedirs(BACKUPS, exist_ok=True)
    root = tk.Tk()
    root.title("Namoid Flasher")
    root.geometry("720x560")
    st = {"parts": None, "file": None, "img": None, "busy": False}

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text="1. Port").grid(row=0, column=0, sticky="w")
    port_var = tk.StringVar()
    port_cb = ttk.Combobox(frm, textvariable=port_var, state="readonly")
    port_cb.grid(row=0, column=1, sticky="ew", padx=6)
    ports = []

    def refresh_ports():
        nonlocal ports
        ports = list_ports()
        port_cb["values"] = [d for _, d in ports]
        if ports:
            best = next((i for i, (_, d) in enumerate(ports) if "ESP32" in d or "USB-serial" in d), 0)
            port_cb.current(best)
    ttk.Button(frm, text="Refresh", command=refresh_ports).grid(row=0, column=2)

    ttk.Label(frm, text="2. Firmware").grid(row=1, column=0, sticky="w", pady=6)
    file_lbl = ttk.Label(frm, text="no file chosen", foreground="#666")
    file_lbl.grid(row=1, column=1, sticky="w", padx=6)

    ttk.Label(frm, text="3. Install into").grid(row=2, column=0, sticky="w")
    part_var = tk.StringVar()
    part_cb = ttk.Combobox(frm, textvariable=part_var, state="readonly")
    part_cb.grid(row=2, column=1, sticky="ew", padx=6)

    bk_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(frm, text="Back up the partition first (recommended)", variable=bk_var).grid(row=3, column=1, sticky="w", pady=4)

    btns = ttk.Frame(frm)
    btns.grid(row=4, column=0, columnspan=3, sticky="ew", pady=6)
    go_btn = ttk.Button(btns, text="Install firmware")
    go_btn.pack(side="right")

    log_box = tk.Text(frm, height=18, font=("Consolas", 9), wrap="word")
    log_box.grid(row=5, column=0, columnspan=3, sticky="nsew")
    frm.rowconfigure(5, weight=1)
    ttk.Label(frm, text="Close the VoidX-Lab bridge first: only one program can use the port. "
                        "The pedal keeps its presets, captures and IRs.", foreground="#666", wraplength=680).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

    prog = {"on": False}

    def log(t, replace=False):
        def f():
            if replace and prog["on"]:                     # progress lines overwrite each other
                log_box.delete("end-2l", "end-1l")
            prog["on"] = replace
            log_box.insert("end", t + "\n")
            log_box.see("end")
        root.after(0, f)

    def port():
        i = port_cb.current()
        return ports[i][0] if 0 <= i < len(ports) else None

    def part_choices():
        if not st["parts"]:
            return []
        return app_parts(st["parts"])

    def fill_parts():
        ch = part_choices()
        part_cb["values"] = ["%s  -  %s  (0x%X, %d KB)" % (p["label"], LABELS.get(p["label"], ""), p["offset"], p["size"] // 1024) for p in ch]
        want = KNOWN.get(st["img"]["project"], (None,))[0] if st["img"] else None
        idx = next((i for i, p in enumerate(ch) if p["label"] == want), -1)
        if idx >= 0:
            part_cb.current(idx)
        else:
            part_cb.set("")

    def worker(fn):
        if st["busy"]:
            return
        st["busy"] = True
        go_btn.state(["disabled"])

        def t():
            try:
                fn()
            except Exception as e:
                log("ERROR: %s" % e)
                root.after(0, lambda: messagebox.showerror("Namoid Flasher", str(e)))
            finally:
                st["busy"] = False
                root.after(0, lambda: go_btn.state(["!disabled"]))
        threading.Thread(target=t, daemon=True).start()

    def choose():
        p = filedialog.askopenfilename(title="Choose a firmware", initialdir=os.path.join(HERE, "firmware"),
                                       filetypes=[("Firmware", "*.bin"), ("All files", "*.*")])
        if not p:
            return
        with open(p, "rb") as f:
            data = f.read()
        try:
            img = inspect_image(data)
        except ValueError as e:
            messagebox.showerror("Namoid Flasher", "%s\n\n%s" % (os.path.basename(p), e))
            return
        st["file"], st["img"] = p, img
        where = KNOWN.get(img["project"], (None, "unknown project: choose where it goes"))[1]
        file_lbl.config(text="%s  -  %s, %d KB  (%s)" % (os.path.basename(p), img["project"], img["size"] // 1024, where), foreground="")
        log("Firmware: %s, project %s, version %s, built %s %s, %d KB" % (os.path.basename(p), img["project"], img["version"], img["date"], img["time"], img["size"] // 1024))
        fill_parts()
    ttk.Button(frm, text="Choose...", command=choose).grid(row=1, column=2)

    def read_table():
        pt = port()
        if not pt:
            raise RuntimeError("no port: connect the pedal with USB and press Refresh")
        log("Reading the pedal on %s..." % pt)
        st["parts"] = read_pedal(pt, log)
        files = known_files()
        log("On the pedal:")
        for p in st["parts"]:
            line = "  %-9s 0x%06X  %5d KB  %-16s" % (p["label"], p["offset"], p["size"] // 1024, LABELS.get(p["label"], ""))
            if "fw" in p:
                line += describe(p["fw"], files)
            log(line)
        if st["img"]:
            same = [p["label"] for p in st["parts"] if (p.get("fw") or {}).get("sha") == st["img"]["sha"]]
            log("The chosen file is " + ("already installed in " + ", ".join(same) if same else "not on the pedal yet") + ".")
        root.after(0, fill_parts)
    ttk.Button(btns, text="Read pedal", command=lambda: worker(read_table)).pack(side="left")

    def install():
        pt = port()
        if not pt:
            raise RuntimeError("no port: connect the pedal with USB and press Refresh")
        if not st["file"]:
            raise RuntimeError("choose a firmware file first")
        if not st["parts"]:
            read_table()
        ch = part_choices()
        i = part_cb.current()
        if not (0 <= i < len(ch)):
            raise RuntimeError("choose where to install it (step 3)")
        part = ch[i]
        with open(st["file"], "rb") as f:
            data = f.read()
        img = inspect_image(data)                          # file may have changed since it was chosen
        check_plan(img, part)
        want = KNOWN.get(img["project"], (None,))[0]
        if want and want != part["label"]:
            ok = []
            ev = threading.Event()
            root.after(0, lambda: (ok.append(messagebox.askyesno("Namoid Flasher",
                "This is a '%s' firmware, normally installed into %s.\nInstall it into %s anyway?" % (img["project"], want, part["label"]))), ev.set()))
            ev.wait()
            if not ok[0]:
                log("Cancelled.")
                return
        if (part.get("fw") or {}).get("sha") == img["sha"]:
            log("Note: %s already holds this same firmware; installing it again anyway." % part["label"])
        if bk_var.get():
            backup_part(pt, part, log)
        log("Installing into %s at 0x%X..." % (part["label"], part["offset"]))
        t0 = time.time()
        flash(pt, part, st["file"], log)
        log("Done in %.0f s: firmware written and verified, the pedal restarts." % (time.time() - t0))
        root.after(0, lambda: messagebox.showinfo("Namoid Flasher", "Firmware installed and verified."))
    go_btn.config(command=lambda: worker(install))

    refresh_ports()
    log("Namoid Flasher. Steps: choose the port, choose a firmware, check where it goes, Install.")
    log("Backups are saved in: " + BACKUPS)
    root.mainloop()


def selftest():
    """for the build machine: everything the .exe needs is inside (no pedal, no window)"""
    lines = []
    try:
        import tkinter  # noqa: F401
        import esptool
        from esptool.loader import StubFlasher
        from serial.tools import list_ports  # noqa: F401
        st = StubFlasher("esp32s3")
        lines.append("esptool %s, esp32s3 stub %d bytes" % (esptool.__version__, len(st.text)))
        try:
            run(["--chip", "esp32s3", "erase_flash"], lambda *a, **k: None)
            lines.append("FAIL: erase_flash not blocked")
        except RuntimeError:
            lines.append("erase_flash blocked")
        ok = not any(l.startswith("FAIL") for l in lines)
    except Exception as e:
        lines.append("FAIL: %r" % (e,))
        ok = False
    with open(os.path.join(HERE, "selftest.txt"), "w") as f:
        f.write("\n".join(lines) + "\n" + ("OK" if ok else "FAILED") + "\n")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    gui()
