package io.mosip.nativesso.childapp

import android.content.Context
import android.net.Uri
import io.mosip.nativesso.core.BuildConfig
import io.mosip.nativesso.core.DPoP
import io.mosip.nativesso.core.IdTokenValidator
import io.mosip.nativesso.core.Jose
import io.mosip.nativesso.core.KeystoreKey
import io.mosip.nativesso.core.OAuthClient
import io.mosip.nativesso.core.OAuthException
import io.mosip.nativesso.core.Pkce
import io.mosip.nativesso.core.ProofProvider
import io.mosip.nativesso.core.Scopes
import io.mosip.nativesso.core.SecureStore
import io.mosip.nativesso.core.SsoContract
import io.mosip.nativesso.core.TokenResult
import io.mosip.nativesso.core.fetchJwks
import org.json.JSONObject

sealed interface SsoOutcome {
    data object SignedIn : SsoOutcome
    /** The requested scopes go beyond what the user granted the Super App: ask for consent. */
    data class NeedsConsent(val additional: List<String>, val granted: List<String>) : SsoOutcome
    data class Failed(val reason: String) : SsoOutcome
}

/** The Child App's own session (its own tokens, encrypted), obtained silently via Native SSO. */
class ChildSession private constructor(private val context: Context) {
    private val clientKey = KeystoreKey.rsa(context, CLIENT_KEY_ALIAS)
    private val store = SecureStore(context, "child-session")
    private val pending = SecureStore(context, "child-pending")
    private val sso = SsoClient(context)
    val client = OAuthClient(BuildConfig.ISSUER, BuildConfig.CHILD_CLIENT_ID, clientKey)
    val clientPublicJwk: JSONObject get() = clientKey.clientRegistrationJwk(context)

    /** Silent sign-in: fetch id_token + device_secret + DPoP proof from the Super App, then exchange. */
    suspend fun signInWithSso(requested: List<String>): SsoOutcome = try {
        sso.use { service ->
            val artifacts = service.ssoArtifacts
            artifacts.getString(SsoContract.KEY_ERROR)?.let { return@use SsoOutcome.Failed(explain(it)) }
            val idToken = artifacts.getString(SsoContract.KEY_ID_TOKEN).orEmpty()
            val deviceSecret = artifacts.getString(SsoContract.KEY_DEVICE_SECRET).orEmpty()
            val firstProof = artifacts.getString(SsoContract.KEY_DPOP_PROOF).orEmpty()
            val granted = Scopes.parse(artifacts.getString(SsoContract.KEY_GRANTED_SCOPE))
            val scopes = Scopes.forExchange(requested)

            val res = client.nativeSsoExchange(idToken, deviceSecret, scopes, firstProof, sso.remoteProofs(service))
            when {
                res.ok -> { persist(res, nonce = null, proofSource = PROOF_SUPER); SsoOutcome.SignedIn }
                res.error == "interaction_required" ->
                    SsoOutcome.NeedsConsent(Scopes.notGranted(scopes, granted - Scopes.DEVICE_SSO), granted - Scopes.DEVICE_SSO)
                res.error == "invalid_grant" -> SsoOutcome.Failed(
                    "The Super App session can no longer be used (${res.errorDescription}). Sign in to the Super App again.")
                else -> SsoOutcome.Failed("${res.error}: ${res.errorDescription}")
            }
        }
    } catch (e: SsoUnavailable) {
        SsoOutcome.Failed(explain(e.code))
    } catch (e: Exception) {
        SsoOutcome.Failed(e.message ?: e.javaClass.simpleName)
    }

    // ---- Bonus: re-consent through eSignet's own consent screen (authorization code flow) ----

    private fun ownDPoPKey() = KeystoreKey.ec(context, OWN_DPOP_ALIAS)
    private val ownProofs = ProofProvider { htm, htu, at, nonce -> DPoP(ownDPoPKey()).proof(htm, htu, at, nonce) }

    /**
     * Starts a browser authorization request for [scopes] with prompt=consent, so eSignet shows the
     * consent screen and records the user's decision server-side. Uses the Child App's own DPoP key.
     */
    fun startConsentFlow(scopes: List<String>): String {
        val pkce = Pkce.create()
        val state = Jose.randomB64(16)
        val nonce = Jose.randomB64(16)
        pending.write(JSONObject().put("verifier", pkce.verifier).put("challenge", pkce.challenge)
            .put("state", state).put("nonce", nonce))
        return client.pushAuthorizationRequest(Scopes.forExchange(scopes).joinToString(" "),
            BuildConfig.CHILD_REDIRECT_URI, pkce, state, nonce, DPoP(ownDPoPKey()).jkt, ownProofs, prompt = "consent")
    }

    fun completeConsentFlow(redirect: Uri) {
        val p = pending.read() ?: throw OAuthException("no consent flow in progress")
        // A forged deep link without this flow's state is ignored and leaves the flow intact.
        if (redirect.getQueryParameter("state") != p.getString("state")) throw OAuthException("state mismatch")
        pending.clear()
        redirect.getQueryParameter("error")?.let { throw OAuthException("consent not given: $it") }
        val code = redirect.getQueryParameter("code") ?: throw OAuthException("no authorization code")
        val res = client.exchangeCode(code, BuildConfig.CHILD_REDIRECT_URI,
            Pkce(p.getString("verifier"), p.getString("challenge")), ownProofs)
        if (!res.ok) throw OAuthException("token request failed: ${res.error} ${res.errorDescription}")
        persist(res, nonce = p.getString("nonce"), proofSource = PROOF_OWN)
    }

    // ---- session ----

    fun activeSession(): JSONObject? {
        val s = store.read() ?: return null
        return if (s.optLong("access_token_exp") > System.currentTimeMillis() / 1000) s else null
    }

    suspend fun userinfo(): Pair<Int, String> {
        val s = activeSession() ?: throw OAuthException("not signed in")
        val at = s.getString("access_token")
        return if (s.optString("proof_source") == PROOF_OWN) client.userinfo(at, ownProofs)
        else sso.use { service -> client.userinfo(at, sso.remoteProofs(service)) }
    }

    fun logout() {
        store.clear()
        pending.clear()
        if (KeystoreKey.exists(OWN_DPOP_ALIAS)) ownDPoPKey().delete()
    }

    private fun persist(res: TokenResult, nonce: String?, proofSource: String) {
        val now = System.currentTimeMillis() / 1000
        val claims = IdTokenValidator.validate(res.idToken, OAuthClient.fetchJwks(BuildConfig.ISSUER),
            BuildConfig.ISSUER, BuildConfig.CHILD_CLIENT_ID, nonce, now)
        store.write(JSONObject()
            .put("access_token", res.accessToken).put("id_token", res.idToken).put("scope", res.scope)
            .put("token_type", res.tokenType).put("access_token_exp", now + res.expiresIn)
            .put("sub", claims.optString("sub")).put("sid", claims.optString("sid"))
            .put("acr", claims.optString("acr")).put("proof_source", proofSource))
    }

    private fun explain(code: String) = when (code) {
        SsoContract.ERROR_NOT_SIGNED_IN -> "Sign in to the eSignet Super App first."
        SsoContract.ERROR_CALLER_NOT_TRUSTED -> "The Super App does not trust this app."
        "super_app_missing_or_untrusted" -> "The eSignet Super App is not installed (or is not from the same vendor)."
        "bind_denied" -> "This app is not permitted to use the Super App's sign-in."
        else -> "Native SSO unavailable ($code)."
    }

    companion object {
        const val CLIENT_KEY_ALIAS = "nsso-child-client"
        const val OWN_DPOP_ALIAS = "nsso-child-dpop"
        const val PROOF_SUPER = "super"
        const val PROOF_OWN = "own"

        @Volatile private var instance: ChildSession? = null
        fun get(context: Context): ChildSession =
            instance ?: synchronized(this) { instance ?: ChildSession(context.applicationContext).also { instance = it } }
    }
}
