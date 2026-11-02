package io.mosip.nativesso.core

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class JoseTest {

    @Test fun base64UrlHasNoPaddingAndRoundTrips() {
        val encoded = Jose.b64(byteArrayOf(-1, -2, -3, 0))
        assertFalse(encoded.contains('='))
        assertFalse(encoded.contains('+') || encoded.contains('/'))
        assertArrayEquals(byteArrayOf(-1, -2, -3, 0), Jose.unb64(encoded))
    }

    @Test fun dsHashMatchesServerDefinition() {
        // ds_hash = BASE64URL(SHA-256(device_secret)); same vector as the server-side Go test.
        assertEquals("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", Jose.b64Sha256("abc"))
    }

    @Test fun rfc7638RsaThumbprintVector() {
        // RFC 7638 section 3.1 example.
        val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP" +
            "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic" +
            "AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksI" +
            "NHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Jose.rsaThumbprint(n, "AQAB"))
    }

    @Test fun fixedLengthPadsAndStripsSignByte() {
        assertEquals(32, Jose.fixedLength(BigInteger.ONE, 32).size)
        val big = BigInteger(1, ByteArray(32) { -1 })
        assertEquals(32, Jose.fixedLength(big, 32).size)
        try { Jose.fixedLength(BigInteger(1, ByteArray(33) { -1 }), 32); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun derToJoseAndBackVerifiesWithJca() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        repeat(20) {
            val data = Jose.randomB64(32).toByteArray()
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(data); sign() }
            val jose = Jose.derToJose(der)
            assertEquals(64, jose.size)
            val ok = Signature.getInstance("SHA256withECDSA").run {
                initVerify(kp.public); update(data); verify(IdTokenValidator.joseToDer(jose))
            }
            assertTrue(ok)
        }
    }

    @Test fun idTokenValidatorAcceptsValidEs256AndRejectsTampering() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val w = (kp.public as ECPublicKey).w
        val jwks = JSONObject().put("keys", org.json.JSONArray().put(JSONObject().put("kty", "EC").put("crv", "P-256")
            .put("kid", "k1").put("use", "sig")
            .put("x", Jose.b64(Jose.fixedLength(w.affineX, 32))).put("y", Jose.b64(Jose.fixedLength(w.affineY, 32)))))
        val now = 1_800_000_000L
        fun token(claims: JSONObject): String {
            val input = Jose.signingInput(JSONObject().put("alg", "ES256").put("kid", "k1"), claims)
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(input.toByteArray()); sign() }
            return input + "." + Jose.b64(Jose.derToJose(der))
        }
        val good = JSONObject().put("iss", "https://op").put("aud", "child").put("exp", now + 60).put("nonce", "n1").put("sid", "s")
        assertEquals("s", IdTokenValidator.validate(token(good), jwks, "https://op", "child", "n1", now).getString("sid"))

        fun rejects(t: String, iss: String = "https://op", aud: String = "child", nonce: String? = "n1") {
            try { IdTokenValidator.validate(t, jwks, iss, aud, nonce, now); fail("accepted an invalid token") }
            catch (_: IdTokenValidator.Invalid) {}
        }
        rejects(token(good), iss = "https://evil")
        rejects(token(good), aud = "other")
        rejects(token(good), nonce = "n2")
        rejects(token(JSONObject(good.toString()).put("exp", now - 600)))
        val parts = token(good).split(".")
        rejects(parts[0] + "." + Jose.b64(JSONObject(good.toString()).put("sub", "x").toString()) + "." + parts[2])
    }
}
