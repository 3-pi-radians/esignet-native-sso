package io.mosip.nativesso.core

import org.json.JSONObject
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Pure JOSE helpers (no Android APIs) so they can be unit tested on the JVM. */
object Jose {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val random = SecureRandom()

    fun b64(bytes: ByteArray): String = encoder.encodeToString(bytes)
    fun b64(text: String): String = b64(text.toByteArray(Charsets.UTF_8))
    fun unb64(text: String): ByteArray = decoder.decode(text)

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun b64Sha256(text: String): String = b64(sha256(text.toByteArray(Charsets.US_ASCII)))

    fun randomB64(bytes: Int): String = ByteArray(bytes).also { random.nextBytes(it) }.let(::b64)

    /** Unsigned big-endian magnitude, left-padded to [size] bytes (JWK coordinates, raw signatures). */
    fun fixedLength(value: BigInteger, size: Int): ByteArray {
        val raw = value.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        require(raw.size <= size) { "value does not fit in $size bytes" }
        return ByteArray(size - raw.size) + raw
    }

    fun unsignedB64(value: BigInteger): String =
        b64(value.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it })

    /** RFC 7638 thumbprint of an EC P-256 public JWK: required members, lexicographic, no whitespace. */
    fun ecThumbprint(x: String, y: String): String =
        b64(sha256("""{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}""".toByteArray(Charsets.UTF_8)))

    /** RFC 7638 thumbprint of an RSA public JWK. */
    fun rsaThumbprint(n: String, e: String): String =
        b64(sha256("""{"e":"$e","kty":"RSA","n":"$n"}""".toByteArray(Charsets.UTF_8)))

    /**
     * Converts a DER-encoded ECDSA signature (what java.security / Android Keystore produce) to the
     * fixed-length R||S form JWS ES256 requires (RFC 7518 section 3.4).
     */
    fun derToJose(der: ByteArray, partLength: Int = 32): ByteArray {
        var i = 0
        require(der[i++] == 0x30.toByte()) { "not a DER sequence" }
        var seqLen = der[i++].toInt() and 0xff
        if (seqLen and 0x80 != 0) {
            val n = seqLen and 0x7f
            seqLen = 0
            repeat(n) { seqLen = (seqLen shl 8) or (der[i++].toInt() and 0xff) }
        }
        fun readInt(): BigInteger {
            require(der[i++] == 0x02.toByte()) { "not a DER integer" }
            val len = der[i++].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(i, i + len))
            i += len
            return v
        }
        val r = readInt()
        val s = readInt()
        return fixedLength(r, partLength) + fixedLength(s, partLength)
    }

    /** Decodes a JWT payload without verifying it (display / routing only, never for trust decisions). */
    fun claims(jwt: String): JSONObject {
        val parts = jwt.split(".")
        require(parts.size == 3) { "not a compact JWS" }
        return JSONObject(String(unb64(parts[1]), Charsets.UTF_8))
    }

    fun signingInput(header: JSONObject, claims: JSONObject): String =
        b64(header.toString()) + "." + b64(claims.toString())
}

/** PKCE (RFC 7636) S256 pair. */
data class Pkce(val verifier: String, val challenge: String) {
    companion object {
        fun create(): Pkce {
            val verifier = Jose.randomB64(32)
            return Pkce(verifier, Jose.b64Sha256(verifier))
        }
    }
}

/** Scope arithmetic for the Native SSO subset rule and the re-consent decision. */
object Scopes {
    const val OPENID = "openid"
    const val DEVICE_SSO = "device_sso"

    fun parse(scope: String?): List<String> = scope.orEmpty().split(' ').filter { it.isNotBlank() }.distinct()

    /** Scopes a sibling app may request through token exchange: never device_sso, always openid. */
    fun forExchange(requested: List<String>): List<String> =
        (listOf(OPENID) + requested).filter { it != DEVICE_SSO }.distinct()

    /** Requested scopes that were not part of the original grant (need user consent). */
    fun notGranted(requested: List<String>, granted: List<String>): List<String> =
        requested.filter { it !in granted }
}
