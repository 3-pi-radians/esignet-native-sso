package io.mosip.nativesso.childapp

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
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.lifecycle.lifecycleScope
import io.mosip.nativesso.core.BuildConfig
import io.mosip.nativesso.core.Jose
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Child App: "Sign in" uses Native SSO through the Super App; no UIN/OTP entry when it succeeds.
 * Keystore and encrypted storage work always runs off the main thread.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var root: LinearLayout
    private val session get() = ChildSession.get(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 48) }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render(message: String? = null) {
        lifecycleScope.launch {
            val (active, jwk) = withContext(Dispatchers.IO) {
                val s = session.activeSession()
                s to (if (s == null) session.clientPublicJwk.toString() else "")
            }
            root.removeAllViews()
            if (active == null) renderLogin(message, jwk) else renderHome(active)
        }
    }

    private fun renderLogin(message: String?, jwk: String) {
        title("eSignet Child App")
        message?.let { text(it).apply { setTextColor(0xFFB3261E.toInt()) } }
        button("Sign in") { signIn(listOf("openid", "email")) }
        button("Sign in (also request phone)") { signIn(listOf("openid", "email", "phone")) }
        text("\nClient setup (register this public key for ${BuildConfig.CHILD_CLIENT_ID}):", bold = true)
        text(jwk).apply { typeface = Typeface.MONOSPACE; textSize = 11f }
        button("Copy public JWK") {
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("client-jwk", jwk))
        }
    }

    private fun signIn(requested: List<String>) {
        val status = text("Signing in with your eSignet Super App session…")
        lifecycleScope.launch {
            when (val outcome = withContext(Dispatchers.IO) { session.signInWithSso(requested) }) {
                SsoOutcome.SignedIn -> render()
                is SsoOutcome.Failed -> render(outcome.reason)
                is SsoOutcome.NeedsConsent -> askConsent(outcome, status)
            }
        }
    }

    /** Bonus: the Super App's consent does not cover these scopes, so ask the user. */
    private fun askConsent(outcome: SsoOutcome.NeedsConsent, status: TextView) {
        AlertDialog.Builder(this)
            .setTitle("Additional permission needed")
            .setMessage("This app is asking for more than you shared with the Super App:\n\n" +
                outcome.additional.joinToString("\n") { "• $it" } +
                "\n\nApprove to review and confirm on eSignet's consent screen, or continue with only what you already shared.")
            .setPositiveButton("Review on eSignet") { _, _ ->
                lifecycleScope.launch {
                    val requested = outcome.granted + outcome.additional
                    withContext(Dispatchers.IO) { runCatching { session.startConsentFlow(requested) } }
                        .onSuccess { CustomTabsIntent.Builder().build().launchUrl(this@MainActivity, Uri.parse(it)) }
                        .onFailure { render("Could not start consent: ${it.message}") }
                }
            }
            .setNegativeButton("Continue without") { _, _ ->
                status.text = "Signing in with the scopes you already shared…"
                signIn(outcome.granted)
            }
            .setCancelable(false)
            .show()
    }

    private fun renderHome(s: org.json.JSONObject) {
        title("Signed in silently")
        text(if (s.optString("proof_source") == ChildSession.PROOF_SUPER)
            "Native SSO: signed in with your Super App session, no UIN or OTP needed."
        else "Signed in after granting additional consent on eSignet.")
        text("Subject: ${s.optString("sub")}")
        text("Scopes: ${s.optString("scope")}")
        text("Authentication: ${s.optString("acr")}")
        text("Shared session (sid): ${s.optString("sid").take(8)}…")
        text("Token type: ${s.optString("token_type")} (sender-constrained)")
        val profile = text("")
        button("Load profile (userinfo, DPoP)") {
            lifecycleScope.launch {
                val r = withContext(Dispatchers.IO) { runCatching { session.userinfo() } }
                profile.text = r.fold({ (code, body) ->
                    "userinfo HTTP $code\n" + if (body.count { it == '.' } == 2)
                        runCatching { Jose.claims(body).toString(2) }.getOrDefault("(unreadable)") else body
                }, { "userinfo failed: ${it.message}" })
            }
        }
        button("Sign out") {
            lifecycleScope.launch {
                withContext(Dispatchers.IO) { session.logout() }
                render()
            }
        }
    }

    private fun title(t: String) = text(t, bold = true).apply { textSize = 22f }
    private fun text(t: String, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = 15f; setPadding(0, 12, 0, 12); if (bold) setTypeface(typeface, Typeface.BOLD); root.addView(this)
    }
    private fun button(label: String, onClick: (View) -> Unit) = Button(this).apply {
        text = label; setOnClickListener(onClick); root.addView(this)
    }
}
