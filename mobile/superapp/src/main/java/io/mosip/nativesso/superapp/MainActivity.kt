package io.mosip.nativesso.superapp

import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.lifecycle.lifecycleScope
import io.mosip.nativesso.core.AppIdentity
import io.mosip.nativesso.core.BuildConfig
import io.mosip.nativesso.core.Jose
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/** Login screen ("Sign in with eSignet") and home screen of the Super App. */
class MainActivity : AppCompatActivity() {
    private lateinit var root: LinearLayout
    private val session by lazy { SuperAppSession.get(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 48) }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        root.removeAllViews()
        val active = session.activeSession()
        if (active == null) renderLogin(session.hasExpiredSession()) else renderHome(active)
    }

    private fun renderLogin(expired: Boolean) {
        title("eSignet Super App")
        if (expired) text("Your session has expired. Sign in again to keep sibling apps signed in.")
        button("Sign in with eSignet") {
            lifecycleScope.launch {
                val url = withContext(Dispatchers.IO) { runCatching { session.startLogin(SuperAppSession.LOGIN_SCOPE) } }
                url.onSuccess { CustomTabsIntent.Builder().build().launchUrl(this@MainActivity, Uri.parse(it)) }
                    .onFailure { text("Could not start sign-in: ${it.message}") }
            }
        }
        text("\nClient setup (register this public key for ${BuildConfig.SUPER_CLIENT_ID}):", bold = true)
        val jwk = session.clientPublicJwk.toString()
        mono(jwk)
        button("Copy public JWK") { copy("client-jwk", jwk) }
        text("Signing certificate SHA-256:\n${AppIdentity.signerFingerprint(this)}")
    }

    private fun renderHome(s: org.json.JSONObject) {
        title("Signed in")
        text("Subject: ${s.optString("sub")}")
        text("Scopes: ${s.optString("scope")}")
        text("Authentication: ${s.optString("acr")}")
        text("Session id (sid): ${s.optString("sid").take(8)}…")
        text("Native SSO: " + if (s.optString("device_secret").isNotEmpty()) "enabled (device_secret held securely)" else "not enabled")
        text("Session valid until: ${DateFormat.getDateTimeInstance().format(Date(s.optLong("id_token_exp") * 1000))}")
        val profile = text("")
        button("Load profile (userinfo, DPoP)") {
            lifecycleScope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching { session.client.userinfo(s.getString("access_token"), session.proofs) }
                }
                profile.text = r.fold({ (status, body) -> "userinfo HTTP $status\n" + describe(body) }, { "userinfo failed: ${it.message}" })
            }
        }
        button("Sign out") { session.logout(); render() }
    }

    /** userinfo may be a JWS (eSignet signs it); show its claims, never the raw token. */
    private fun describe(body: String): String =
        if (body.count { it == '.' } == 2) runCatching { Jose.claims(body).toString(2) }.getOrDefault("(unreadable)") else body

    private fun title(t: String) = text(t, bold = true).apply { textSize = 22f }
    private fun text(t: String, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = 15f; setPadding(0, 12, 0, 12); if (bold) setTypeface(typeface, Typeface.BOLD); root.addView(this)
    }
    private fun mono(t: String) = text(t).apply { typeface = Typeface.MONOSPACE; textSize = 11f }
    private fun button(label: String, onClick: (View) -> Unit) = Button(this).apply {
        text = label; setOnClickListener(onClick); root.addView(this)
    }
    private fun copy(label: String, value: String) =
        (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(label, value))
}
