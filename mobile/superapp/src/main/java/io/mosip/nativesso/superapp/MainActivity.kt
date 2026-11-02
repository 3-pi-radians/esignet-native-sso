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
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

/**
 * Login screen ("Sign in with eSignet") and home screen of the Super App. Keystore and encrypted
 * storage work (key generation, decryption) always runs off the main thread.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 48) }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh(message: String? = null) {
        lifecycleScope.launch {
            val state = withContext(Dispatchers.IO) {
                val session = SuperAppSession.get(this@MainActivity)
                val active = session.activeSession()
                if (active != null) ScreenState(active, null, null)
                else ScreenState(null, session.clientPublicJwk.toString(), AppIdentity.signerFingerprint(this@MainActivity))
            }
            root.removeAllViews()
            if (state.session == null) renderLogin(state, message) else renderHome(state.session)
        }
    }

    private data class ScreenState(val session: JSONObject?, val clientJwk: String?, val signerFingerprint: String?)

    private fun renderLogin(state: ScreenState, message: String?) {
        title("eSignet Super App")
        message?.let { text(it).apply { setTextColor(0xFFB3261E.toInt()) } }
        button("Sign in with eSignet") {
            lifecycleScope.launch {
                val url = withContext(Dispatchers.IO) {
                    runCatching { SuperAppSession.get(this@MainActivity).startLogin(SuperAppSession.LOGIN_SCOPE) }
                }
                url.onSuccess { CustomTabsIntent.Builder().build().launchUrl(this@MainActivity, Uri.parse(it)) }
                    .onFailure { refresh("Could not start sign-in: ${it.message}") }
            }
        }
        text("\nClient setup (register this public key for ${BuildConfig.SUPER_CLIENT_ID}):", bold = true)
        val jwk = state.clientJwk.orEmpty()
        text(jwk).apply { typeface = Typeface.MONOSPACE; textSize = 11f }
        button("Copy public JWK") {
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("client-jwk", jwk))
        }
        text("Signing certificate SHA-256:\n${state.signerFingerprint}")
    }

    private fun renderHome(s: JSONObject) {
        title("Signed in")
        text("Subject: ${s.optString("sub")}")
        text("Scopes: ${s.optString("scope")}")
        text("Authentication: ${s.optString("acr")}")
        text("Session id (sid): ${s.optString("sid").take(8)}…")
        text("Native SSO: " + if (s.optString("device_secret").isNotEmpty())
            "enabled (device_secret held encrypted; sibling apps can sign in)" else "not enabled")
        text("Signed in at: ${DateFormat.getDateTimeInstance().format(Date(s.optLong("signed_in_at") * 1000))}")
        val profile = text("")
        button("Load profile (userinfo, DPoP)") {
            lifecycleScope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching {
                        val session = SuperAppSession.get(this@MainActivity)
                        val at = session.renewAccessToken() ?: return@runCatching null
                        session.client.userinfo(at, session.proofs)
                    }
                }
                r.fold({ res ->
                    if (res == null) refresh("Your eSignet session has ended. Sign in again.")
                    else profile.text = "userinfo HTTP ${res.first}\n" + describe(res.second)
                }, { profile.text = "userinfo failed: ${it.message}" })
            }
        }
        button("Sign out") {
            lifecycleScope.launch {
                withContext(Dispatchers.IO) { SuperAppSession.get(this@MainActivity).logout() }
                refresh()
            }
        }
    }

    /** userinfo may be a JWS (eSignet signs it); show its claims, never the raw token. */
    private fun describe(body: String): String =
        if (body.count { it == '.' } == 2) runCatching { Jose.claims(body).toString(2) }.getOrDefault("(unreadable)") else body

    private fun title(t: String) = text(t, bold = true).apply { textSize = 22f }
    private fun text(t: String, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = 15f; setPadding(0, 12, 0, 12); if (bold) setTypeface(typeface, Typeface.BOLD); root.addView(this)
    }
    private fun button(label: String, onClick: (View) -> Unit) = Button(this).apply {
        text = label; setOnClickListener(onClick); root.addView(this)
    }
}
