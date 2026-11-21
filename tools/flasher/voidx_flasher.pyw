# VoidX Flasher - installs firmware on the VoidX pedal (ESP32-S3) without Claude.
#
# Safety rules, enforced in code:
#   - only ESP32-S3 application images are written, and only at the start of an app partition read from
#     the pedal's own partition table (never the bootloader, never the partition table, never data areas);
#   - the image must fit inside that partition;
#   - before writing, the partition's current content is saved to backups\ (a restorable .bin);
#   - the whole flash is never erased (no erase_flash) and eFuses are never touched (no espefuse);
#   - esptool verifies what it wrote.
#
# Ships as a single VoidX-Flasher.exe (built on GitHub Actions with PyInstaller): nothing to install.
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
    "vx_amp": ("ota_0", "Pedal"),
    "vx_launcher": ("factory", "Launcher (firmware selector)"),
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
    version = data[0x30:0x50].split(b"\0")[0].decode("ascii", "replace")
    project = data[0x50:0x70].split(b"\0")[0].decode("ascii", "replace")
    return {"project": project, "version": version, "size": len(data)}


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


def read_ptable(port, log):
    tmp = os.path.join(BACKUPS, "_ptable.bin")
    run(esptool_cmd(port, "read_flash", hex(PT_ADDR), hex(PT_LEN), tmp), log)   # then the pedal restarts normally
    with open(tmp, "rb") as f:
        return parse_ptable(f.read())


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
    root.title("VoidX Flasher")
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
                root.after(0, lambda: messagebox.showerror("VoidX Flasher", str(e)))
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
            messagebox.showerror("VoidX Flasher", "%s\n\n%s" % (os.path.basename(p), e))
            return
        st["file"], st["img"] = p, img
        where = KNOWN.get(img["project"], (None, "unknown project: choose where it goes"))[1]
        file_lbl.config(text="%s  -  %s, %d KB  (%s)" % (os.path.basename(p), img["project"], img["size"] // 1024, where), foreground="")
        log("Firmware: %s, project %s, version %s, %d KB" % (os.path.basename(p), img["project"], img["version"], img["size"] // 1024))
        fill_parts()
    ttk.Button(frm, text="Choose...", command=choose).grid(row=1, column=2)

    def read_table():
        pt = port()
        if not pt:
            raise RuntimeError("no port: connect the pedal with USB and press Refresh")
        log("Reading the partition table from the pedal on %s..." % pt)
        st["parts"] = read_ptable(pt, log)
        for p in st["parts"]:
            log("  %-9s 0x%06X  %5d KB  %s" % (p["label"], p["offset"], p["size"] // 1024, LABELS.get(p["label"], "")))
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
            root.after(0, lambda: (ok.append(messagebox.askyesno("VoidX Flasher",
                "This is a '%s' firmware, normally installed into %s.\nInstall it into %s anyway?" % (img["project"], want, part["label"]))), ev.set()))
            ev.wait()
            if not ok[0]:
                log("Cancelled.")
                return
        if bk_var.get():
            backup_part(pt, part, log)
        log("Installing into %s at 0x%X..." % (part["label"], part["offset"]))
        t0 = time.time()
        flash(pt, part, st["file"], log)
        log("Done in %.0f s: firmware written and verified, the pedal restarts." % (time.time() - t0))
        root.after(0, lambda: messagebox.showinfo("VoidX Flasher", "Firmware installed and verified."))
    go_btn.config(command=lambda: worker(install))

    refresh_ports()
    log("VoidX Flasher. Steps: choose the port, choose a firmware, check where it goes, Install.")
    log("Backups are saved in: " + BACKUPS)
    root.mainloop()


if __name__ == "__main__":
    gui()
