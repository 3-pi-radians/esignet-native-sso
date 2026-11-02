package io.mosip.nativesso.core

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Produces a DPoP proof for (htm, htu, accessToken?, nonce?). Local key or the Super App's signer. */
fun interface ProofProvider {
    fun proof(htm: String, htu: String, accessToken: String?, nonce: String?): String
}

data class Discovery(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val parEndpoint: String,
    val userinfoEndpoint: String,
)

/** Outcome of a token endpoint call. Tokens are kept out of toString() so they never reach logs. */
class TokenResult(val status: Int, val body: JSONObject) {
    val ok get() = status == 200 && body.has("access_token")
    val error: String? get() = body.optString("error").ifEmpty { null }
    val errorDescription: String get() = body.optString("error_description")
    val accessToken: String get() = body.optString("access_token")
    val idToken: String get() = body.optString("id_token")
    val deviceSecret: String get() = body.optString("device_secret")
    val scope: String get() = body.optString("scope")
    val tokenType: String get() = body.optString("token_type")
    val expiresIn: Long get() = body.optLong("expires_in")
    override fun toString() = "TokenResult(status=$status, error=$error)"
}

class OAuthException(message: String) : IOException(message)

/**
 * Minimal OAuth 2.0 / OIDC client for eSignet: PAR (RFC 9126), PKCE, private_key_jwt, DPoP
 * (RFC 9449) and the Native SSO token exchange. Blocking: call from a background dispatcher.
 */
class OAuthClient(
    private val issuer: String,
    private val clientId: String,
    private val clientKey: KeystoreKey,
) {
    @Volatile private var dpopNonce: String? = null
    private var cachedDiscovery: Discovery? = null

    fun discovery(): Discovery {
        cachedDiscovery?.let { return it }
        val (status, body) = http("GET", "$issuer/.well-known/openid-configuration", emptyMap(), null)
        if (status != 200) throw OAuthException("discovery failed: HTTP $status")
        val d = Discovery(
            issuer = body.getString("issuer"),
            authorizationEndpoint = body.getString("authorization_endpoint"),
            tokenEndpoint = body.getString("token_endpoint"),
            parEndpoint = body.getString("pushed_authorization_request_endpoint"),
            userinfoEndpoint = body.getString("userinfo_endpoint"),
        )
        if (d.issuer != issuer) throw OAuthException("issuer mismatch in discovery")
        cachedDiscovery = d
        return d
    }

    /** RFC 7523 private_key_jwt assertion; eSignet validates aud against the issuer. */
    fun clientAssertion(): String {
        val now = System.currentTimeMillis() / 1000
        val claims = JSONObject().put("iss", clientId).put("sub", clientId).put("aud", issuer)
            .put("iat", now).put("exp", now + 300).put("jti", Jose.randomB64(16))
        return clientKey.signJws(JSONObject().put("typ", "JWT"), claims)
    }

    /** Pushes the authorization request bound to [dpopJkt] and returns the browser URL to open. */
    fun pushAuthorizationRequest(
        scope: String, redirectUri: String, pkce: Pkce, state: String, nonce: String,
        dpopJkt: String, proofs: ProofProvider, prompt: String? = null,
    ): String {
        val d = discovery()
        val form = mutableMapOf(
            "response_type" to "code", "client_id" to clientId, "scope" to scope,
            "redirect_uri" to redirectUri, "state" to state, "nonce" to nonce,
            "code_challenge" to pkce.challenge, "code_challenge_method" to "S256",
            "acr_values" to "mosip:idp:acr:generated-code", "dpop_jkt" to dpopJkt,
            "client_assertion_type" to CLIENT_ASSERTION_TYPE, "client_assertion" to clientAssertion(),
        )
        if (prompt != null) form["prompt"] = prompt
        val res = postWithDPoP(d.parEndpoint, form, proofs, null)
        val requestUri = res.body.optString("request_uri")
        if (requestUri.isEmpty()) {
            throw OAuthException("PAR failed: ${res.body.optString("error")} ${res.body.optString("error_description")}")
        }
        return d.authorizationEndpoint + "?client_id=" + enc(clientId) + "&request_uri=" + enc(requestUri)
    }

    fun exchangeCode(code: String, redirectUri: String, pkce: Pkce, proofs: ProofProvider): TokenResult =
        postWithDPoP(discovery().tokenEndpoint, mapOf(
            "grant_type" to "authorization_code", "code" to code, "redirect_uri" to redirectUri,
            "client_id" to clientId, "code_verifier" to pkce.verifier,
            "client_assertion_type" to CLIENT_ASSERTION_TYPE, "client_assertion" to clientAssertion(),
        ), proofs, null)

    /**
     * OpenID Connect Native SSO token exchange (section 4.1): subject_token is the Super App's
     * id_token, actor_token its device_secret, audience the issuer. device_sso is never requested.
     * [firstProof] is the proof the Super App signed with the handoff; [proofs] signs retries.
     */
    fun nativeSsoExchange(
        idToken: String, deviceSecret: String, scopes: List<String>, firstProof: String, proofs: ProofProvider,
    ): TokenResult {
        val form = mapOf(
            "grant_type" to SsoContract.GRANT_TOKEN_EXCHANGE, "client_id" to clientId,
            "subject_token" to idToken, "subject_token_type" to SsoContract.TOKEN_TYPE_ID_TOKEN,
            "actor_token" to deviceSecret, "actor_token_type" to SsoContract.TOKEN_TYPE_DEVICE_SECRET,
            "audience" to issuer, "scope" to Scopes.forExchange(scopes).joinToString(" "),
            "client_assertion_type" to CLIENT_ASSERTION_TYPE, "client_assertion" to clientAssertion(),
        )
        var first = true
        return postWithDPoP(discovery().tokenEndpoint, form, { htm, htu, at, nonce ->
            if (first && nonce == null) firstProof.also { first = false } else proofs.proof(htm, htu, at, nonce)
        }, null)
    }

    /** GET userinfo with a DPoP-bound access token. Returns the raw body (JSON or JWS). */
    fun userinfo(accessToken: String, proofs: ProofProvider): Pair<Int, String> {
        val url = discovery().userinfoEndpoint
        repeat(2) {
            val proof = proofs.proof("GET", url, accessToken, dpopNonce)
            val conn = open("GET", url, mapOf("Authorization" to "DPoP $accessToken", "DPoP" to proof))
            val status = conn.responseCode
            conn.getHeaderField("DPoP-Nonce")?.let { n ->
                if (status == 401 && n != dpopNonce) { dpopNonce = n; return@repeat }
            }
            val text = (if (status < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
            return status to text
        }
        throw OAuthException("userinfo failed after DPoP nonce retry")
    }

    private fun postWithDPoP(url: String, form: Map<String, String>, proofs: ProofProvider, accessToken: String?): TokenResult {
        repeat(2) { attempt ->
            val body = form.toMutableMap()
            if (attempt > 0 && body.containsKey("client_assertion")) body["client_assertion"] = clientAssertion()
            val proof = proofs.proof("POST", url, accessToken, dpopNonce)
            val conn = open("POST", url, mapOf("Content-Type" to "application/x-www-form-urlencoded", "DPoP" to proof))
            conn.doOutput = true
            conn.outputStream.use { it.write(body.entries.joinToString("&") { (k, v) -> enc(k) + "=" + enc(v) }.toByteArray()) }
            val status = conn.responseCode
            val text = (if (status < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
            val json = runCatching { JSONObject(text) }.getOrDefault(JSONObject())
            val nonce = conn.getHeaderField("DPoP-Nonce")
            if (attempt == 0 && json.optString("error") == "use_dpop_nonce" && nonce != null) {
                dpopNonce = nonce
                return@repeat
            }
            return TokenResult(status, json)
        }
        throw OAuthException("token request failed after DPoP nonce retry")
    }

    private fun http(method: String, url: String, headers: Map<String, String>, body: String?): Pair<Int, JSONObject> {
        val conn = open(method, url, headers)
        if (body != null) {
            conn.doOutput = true
            conn.outputStream.use { it.write(body.toByteArray()) }
        }
        val status = conn.responseCode
        val text = (if (status < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
        return status to runCatching { JSONObject(text) }.getOrDefault(JSONObject())
    }

    private fun open(method: String, url: String, headers: Map<String, String>): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 30_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
            headers.forEach { (k, v) -> setRequestProperty(k, v) }
        }

    private fun enc(v: String) = URLEncoder.encode(v, "UTF-8")

    companion object {
        const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}

/** Fetches the issuer JWKS (used to validate ID tokens). */
fun OAuthClient.Companion.fetchJwks(issuer: String): JSONObject {
    val disc = (URL("$issuer/.well-known/openid-configuration").openConnection() as HttpURLConnection)
        .run { JSONObject(inputStream.bufferedReader().readText()) }
    return (URL(disc.getString("jwks_uri")).openConnection() as HttpURLConnection)
        .run { JSONObject(inputStream.bufferedReader().readText()) }
}
