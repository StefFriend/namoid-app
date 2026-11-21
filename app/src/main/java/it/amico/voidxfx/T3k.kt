package it.amico.voidxfx

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * TONE3000: scelta di una cattura (o di un IR) dal catalogo e download nell'app, che poi la manda al pedale.
 *
 * Flusso (API v1, OAuth 2.0 con PKCE): la pagina di TONE3000 si apre nel browser con prompt=select_tone; l'utente
 * accede, sceglie un tone e TONE3000 torna all'app con namoid://t3k?code=...&state=...&tone_id=...
 * Il codice si scambia con un token (salvato, con il refresh), poi si leggono i modelli del tone e, su richiesta,
 * si scarica il file del modello scelto (model_url con il token).
 *
 * Serve la chiave pubblica dell'app (client_id), creata dall'utente nelle impostazioni del suo account TONE3000
 * con namoid://t3k tra gli indirizzi di ritorno. Nessuna chiave segreta nell'app.
 * Tutte le risposte tornano alla pagina come window.t3k(evento, json).
 */
class T3k(private val act: Activity, private val js: (String) -> Unit) {
    companion object {
        const val BASE = "https://www.tone3000.com/api/v1"
        const val REDIRECT = "namoid://t3k"
    }
    private val io = Executors.newSingleThreadExecutor()
    private val prefs = act.getSharedPreferences("t3k", Context.MODE_PRIVATE)

    private fun emit(ev: String, o: JSONObject) = js("window.t3k && window.t3k(${JSONObject.quote(ev)}, ${o})")
    private fun err(msg: String) = emit("error", JSONObject().put("msg", msg))
    private fun b64url(b: ByteArray) = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    /** apre la scelta di un tone; format: "nam" o "ir" */
    fun select(clientId: String, format: String) {
        if (clientId.isBlank()) { err("no TONE3000 key"); return }
        val rnd = SecureRandom()
        val v = ByteArray(48).also { rnd.nextBytes(it) }
        val verifier = b64url(v)
        val challenge = b64url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
        val state = b64url(ByteArray(16).also { rnd.nextBytes(it) })
        prefs.edit().putString("cid", clientId.trim()).putString("ver", verifier).putString("state", state).putString("fmt", format).apply()
        val u = StringBuilder("$BASE/oauth/authorize?response_type=code")
            .append("&client_id=").append(enc(clientId.trim()))
            .append("&redirect_uri=").append(enc(REDIRECT))
            .append("&code_challenge=").append(challenge)
            .append("&code_challenge_method=S256")
            .append("&state=").append(state)
            .append("&prompt=select_tone&menubar=true&preview=true")
            .append("&format=").append(if (format == "ir") "ir" else "nam")
        if (format != "ir") u.append("&architecture=2")
        try { act.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(u.toString())).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        catch (e: Exception) { err("no browser to open TONE3000") }
    }

    /** ritorno da TONE3000 (deep link). true se era per noi */
    fun handle(uri: Uri?): Boolean {
        if (uri == null || (uri.scheme != "namoid" && uri.scheme != "voidxfx") || uri.host != "t3k") return false
        val error = uri.getQueryParameter("error")
        val code = uri.getQueryParameter("code")
        val tone = uri.getQueryParameter("tone_id")
        if (uri.getQueryParameter("canceled") == "true") { emit("canceled", JSONObject()); return true }
        if (error != null) { err("TONE3000: $error"); return true }
        if (uri.getQueryParameter("state") != prefs.getString("state", null)) { err("TONE3000: the answer does not match the request, try again"); return true }
        io.execute {
            try {
                if (code != null) exchange(code)
                if (tone == null) { emit("login", JSONObject()); return@execute }
                emit("busy", JSONObject().put("msg", "Reading the tone…"))
                val t = get("$BASE/tones/$tone")
                val fmt = prefs.getString("fmt", "nam") ?: "nam"
                val m = get("$BASE/models?tone_id=$tone&page_size=100" + if (fmt == "ir") "" else "&architecture=2")
                emit("models", JSONObject().put("tone", t).put("models", m).put("fmt", fmt))
            } catch (e: Exception) { err("TONE3000: " + (e.message ?: "connection error")) }
        }
        return true
    }

    /** scarica un modello (model_url) e lo passa alla pagina in base64 */
    fun download(url: String, name: String) {
        io.execute {
            try {
                if (!url.startsWith("https://")) throw Exception("bad download address")
                val b = getBytes(url)
                emit("file", JSONObject().put("name", name).put("b64", Base64.encodeToString(b, Base64.NO_WRAP)))
            } catch (e: Exception) { err("Download failed: " + (e.message ?: "connection error")) }
        }
    }

    fun logout() { prefs.edit().remove("at").remove("rt").remove("exp").apply() }
    fun loggedIn() = prefs.getString("rt", null) != null

    /* ---------------- HTTP ---------------- */
    private fun exchange(code: String) {
        val o = post("$BASE/oauth/token", "grant_type=authorization_code&code=${enc(code)}&code_verifier=${enc(prefs.getString("ver", "") ?: "")}" +
                "&redirect_uri=${enc(REDIRECT)}&client_id=${enc(prefs.getString("cid", "") ?: "")}")
        save(o)
    }
    private fun refresh(): Boolean {
        val rt = prefs.getString("rt", null) ?: return false
        return try {
            save(post("$BASE/oauth/token", "grant_type=refresh_token&refresh_token=${enc(rt)}&client_id=${enc(prefs.getString("cid", "") ?: "")}")); true
        } catch (e: Exception) { logout(); false }
    }
    private fun save(o: JSONObject) {
        val at = o.optString("access_token")
        if (at.isEmpty()) throw Exception(o.optString("error_description", o.optString("error", "no token")))
        prefs.edit().putString("at", at).putString("rt", o.optString("refresh_token", prefs.getString("rt", "") ?: ""))
            .putLong("exp", System.currentTimeMillis() + 1000L * o.optLong("expires_in", 3600)).apply()
    }
    private fun token(): String {
        if (System.currentTimeMillis() > prefs.getLong("exp", 0) - 60000) refresh()
        return prefs.getString("at", null) ?: throw Exception("sign in to TONE3000 again")
    }
    private fun open(url: String, auth: Boolean): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 15000; c.readTimeout = 60000
        c.setRequestProperty("Accept", "application/json")
        if (auth) c.setRequestProperty("Authorization", "Bearer " + token())
        return c
    }
    private fun read(c: HttpURLConnection): ByteArray {
        val code = c.responseCode
        val s = if (code in 200..299) c.inputStream else (c.errorStream ?: throw Exception("HTTP $code"))
        val out = ByteArrayOutputStream()
        s.use { it.copyTo(out) }
        if (code !in 200..299) {
            val t = String(out.toByteArray(), Charsets.UTF_8)
            val m = try { JSONObject(t).let { it.optString("error_description", it.optString("message", it.optString("error", ""))) } } catch (e: Exception) { "" }
            throw HttpErr(code, if (m.isNotEmpty()) m else "HTTP $code")
        }
        return out.toByteArray()
    }
    private class HttpErr(val code: Int, msg: String) : Exception(msg)
    private fun getBytes(url: String): ByteArray = try { read(open(url, true)) } catch (e: HttpErr) {
        if (e.code == 401 && refresh()) read(open(url, true)) else throw e
    }
    private fun get(url: String) = JSONObject(String(getBytes(url), Charsets.UTF_8))
    private fun post(url: String, form: String): JSONObject {
        val c = open(url, false)
        c.requestMethod = "POST"; c.doOutput = true
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        c.outputStream.use { it.write(form.toByteArray(Charsets.UTF_8)) }
        return JSONObject(String(read(c), Charsets.UTF_8))
    }
}
