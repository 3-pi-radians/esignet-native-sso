package io.mosip.nativesso.superapp

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
import io.mosip.nativesso.core.SecureStore
import io.mosip.nativesso.core.fetchJwks
import org.json.JSONObject

/**
 * The Super App's eSignet session. Holds the client key (private_key_jwt), DPoP key A and the
 * encrypted token store. Key A is created per login and deleted on logout, which also ends every
 * sibling app's ability to use the device secret (it is bound to key A via cnf.jkt).
 */
class SuperAppSession private constructor(private val context: Context) {
    private val clientKey = KeystoreKey.rsa(context, CLIENT_KEY_ALIAS)
    private val store = SecureStore(context, "super-session")
    private val pending = SecureStore(context, "super-pending")
    val client = OAuthClient(BuildConfig.ISSUER, BuildConfig.SUPER_CLIENT_ID, clientKey)

    val clientPublicJwk: JSONObject get() = clientKey.publicJwk().put("use", "sig").put("alg", "RS256")

    private fun dpopKey() = KeystoreKey.ec(context, DPOP_KEY_ALIAS)

    /** DPoP proofs signed with key A. */
    val proofs = ProofProvider { htm, htu, at, nonce -> DPoP(dpopKey()).proof(htm, htu, at, nonce) }

    /** Starts PAR + PKCE + DPoP with device_sso; returns the URL to open in the browser. */
    fun startLogin(scope: String): String {
        val pkce = Pkce.create()
        val state = Jose.randomB64(16)
        val nonce = Jose.randomB64(16)
        pending.write(JSONObject().put("verifier", pkce.verifier).put("challenge", pkce.challenge)
            .put("state", state).put("nonce", nonce))
        return client.pushAuthorizationRequest(scope, BuildConfig.SUPER_REDIRECT_URI, pkce, state, nonce,
            DPoP(dpopKey()).jkt, proofs)
    }

    /** Handles the redirect: exchanges the code, validates the response and stores the session. */
    fun completeLogin(redirect: Uri) {
        val p = pending.read() ?: throw OAuthException("no login in progress")
        pending.clear()
        redirect.getQueryParameter("error")?.let {
            throw OAuthException("authorization failed: $it ${redirect.getQueryParameter("error_description").orEmpty()}")
        }
        if (redirect.getQueryParameter("state") != p.getString("state")) throw OAuthException("state mismatch")
        val code = redirect.getQueryParameter("code") ?: throw OAuthException("no authorization code")
        val res = client.exchangeCode(code, BuildConfig.SUPER_REDIRECT_URI,
            Pkce(p.getString("verifier"), p.getString("challenge")), proofs)
        if (!res.ok) throw OAuthException("token request failed: ${res.error} ${res.errorDescription}")

        val now = System.currentTimeMillis() / 1000
        val claims = IdTokenValidator.validate(res.idToken, OAuthClient.fetchJwks(BuildConfig.ISSUER),
            BuildConfig.ISSUER, BuildConfig.SUPER_CLIENT_ID, p.getString("nonce"), now)
        if (res.deviceSecret.isNotEmpty() && claims.optString("ds_hash") != Jose.b64Sha256(res.deviceSecret)) {
            throw OAuthException("ds_hash does not match the device_secret")
        }
        store.write(JSONObject()
            .put("access_token", res.accessToken).put("id_token", res.idToken)
            .put("device_secret", res.deviceSecret).put("scope", res.scope).put("token_type", res.tokenType)
            .put("access_token_exp", now + res.expiresIn).put("id_token_exp", claims.optLong("exp"))
            .put("sub", claims.optString("sub")).put("sid", claims.optString("sid"))
            .put("acr", claims.optString("acr")))
    }

    /** The stored session while its ID token is still valid (the Native SSO window), else null. */
    fun activeSession(): JSONObject? {
        val s = store.read() ?: return null
        return if (s.optLong("id_token_exp") > System.currentTimeMillis() / 1000) s else null
    }

    fun hasExpiredSession(): Boolean = store.read() != null && activeSession() == null

    fun logout() {
        store.clear()
        pending.clear()
        if (KeystoreKey.exists(DPOP_KEY_ALIAS)) dpopKey().delete()
    }

    companion object {
        const val CLIENT_KEY_ALIAS = "nsso-super-client"
        const val DPOP_KEY_ALIAS = "nsso-super-dpop-a"
        const val LOGIN_SCOPE = "openid profile email device_sso"

        @Volatile private var instance: SuperAppSession? = null
        fun get(context: Context): SuperAppSession =
            instance ?: synchronized(this) { instance ?: SuperAppSession(context.applicationContext).also { instance = it } }
    }
}
