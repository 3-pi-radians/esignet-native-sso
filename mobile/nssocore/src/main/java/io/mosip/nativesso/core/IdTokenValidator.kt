package io.mosip.nativesso.core

import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec

/** OIDC Core 3.1.3.7 ID token validation against the issuer's JWKS (ES256, RS256, PS256). */
object IdTokenValidator {
    class Invalid(message: String) : Exception(message)

    fun validate(idToken: String, jwks: JSONObject, issuer: String, clientId: String, nonce: String?, nowSecs: Long,
                 leewaySecs: Long = 60): JSONObject {
        val parts = idToken.split(".")
        if (parts.size != 3) throw Invalid("id_token is not a compact JWS")
        val header = JSONObject(String(Jose.unb64(parts[0])))
        val alg = header.optString("alg")
        val kid = header.optString("kid")
        val keys = jwks.getJSONArray("keys")
        val candidates = (0 until keys.length()).map { keys.getJSONObject(it) }
            .filter { it.optString("use", "sig") == "sig" && (kid.isEmpty() || it.optString("kid") == kid) }
        val input = (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)
        val sig = Jose.unb64(parts[2])
        val verified = candidates.any { jwk -> runCatching { verify(alg, jwk, input, sig) }.getOrDefault(false) }
        if (!verified) throw Invalid("id_token signature is not valid")

        val claims = JSONObject(String(Jose.unb64(parts[1])))
        if (claims.optString("iss") != issuer) throw Invalid("unexpected issuer")
        val aud = claims.opt("aud")
        val audOk = when (aud) {
            is String -> aud == clientId
            is org.json.JSONArray -> (0 until aud.length()).any { aud.optString(it) == clientId }
            else -> false
        }
        if (!audOk) throw Invalid("id_token is not addressed to this client")
        if (claims.optLong("exp") + leewaySecs < nowSecs) throw Invalid("id_token has expired")
        if (nonce != null && claims.optString("nonce") != nonce) throw Invalid("nonce mismatch")
        return claims
    }

    private fun verify(alg: String, jwk: JSONObject, input: ByteArray, sig: ByteArray): Boolean = when (alg) {
        "ES256" -> Signature.getInstance("SHA256withECDSA").run {
            initVerify(ecKey(jwk)); update(input); verify(joseToDer(sig))
        }
        "RS256" -> Signature.getInstance("SHA256withRSA").run { initVerify(rsaKey(jwk)); update(input); verify(sig) }
        "PS256" -> Signature.getInstance("SHA256withRSA/PSS").run {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            initVerify(rsaKey(jwk)); update(input); verify(sig)
        }
        else -> false
    }

    private fun rsaKey(jwk: JSONObject): PublicKey = KeyFactory.getInstance("RSA").generatePublic(
        RSAPublicKeySpec(BigInteger(1, Jose.unb64(jwk.getString("n"))), BigInteger(1, Jose.unb64(jwk.getString("e")))),
    )

    private fun ecKey(jwk: JSONObject): PublicKey {
        require(jwk.getString("crv") == "P-256")
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(BigInteger(1, Jose.unb64(jwk.getString("x"))), BigInteger(1, Jose.unb64(jwk.getString("y"))))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
    }

    /** R||S (64 bytes) to DER, for java.security ECDSA verification. */
    internal fun joseToDer(sig: ByteArray): ByteArray {
        require(sig.size == 64) { "ES256 signature must be 64 bytes" }
        fun der(int: ByteArray): ByteArray {
            var v = int.dropWhile { it == 0.toByte() }.toByteArray()
            if (v.isEmpty()) v = byteArrayOf(0)
            if (v[0] < 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = der(sig.copyOfRange(0, 32)) + der(sig.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
