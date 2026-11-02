package io.mosip.nativesso.core

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

/**
 * Non-exportable signing keys held in the Android Keystore (StrongBox when the device has one).
 * Private keys never leave secure hardware; this class only ever returns signatures and public JWKs.
 */
class KeystoreKey private constructor(private val alias: String, private val ec: Boolean) {

    private val keyStore: KeyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val privateKey: PrivateKey
        get() = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("Keystore key '$alias' is missing")

    /** Public key as a JWK (EC: kty/crv/x/y, RSA: kty/n/e). */
    fun publicJwk(): JSONObject {
        val pub = keyStore.getCertificate(alias).publicKey
        return if (ec) {
            val w = (pub as ECPublicKey).w
            JSONObject().put("kty", "EC").put("crv", "P-256")
                .put("x", Jose.b64(Jose.fixedLength(w.affineX, 32)))
                .put("y", Jose.b64(Jose.fixedLength(w.affineY, 32)))
        } else {
            val rsa = pub as RSAPublicKey
            JSONObject().put("kty", "RSA").put("n", Jose.unsignedB64(rsa.modulus))
                .put("e", Jose.unsignedB64(rsa.publicExponent))
        }
    }

    /** RFC 7638 thumbprint of the public key; for a DPoP key this is the cnf.jkt value. */
    fun thumbprint(): String {
        val jwk = publicJwk()
        return if (ec) Jose.ecThumbprint(jwk.getString("x"), jwk.getString("y"))
        else Jose.rsaThumbprint(jwk.getString("n"), jwk.getString("e"))
    }

    /** Signs a JWS over [header] and [claims]; alg is ES256 (EC) or RS256 (RSA). */
    fun signJws(header: JSONObject, claims: JSONObject): String {
        header.put("alg", if (ec) "ES256" else "RS256")
        val input = Jose.signingInput(header, claims)
        val sig = Signature.getInstance(if (ec) "SHA256withECDSA" else "SHA256withRSA").run {
            initSign(privateKey)
            update(input.toByteArray(Charsets.US_ASCII))
            sign()
        }
        return input + "." + Jose.b64(if (ec) Jose.derToJose(sig) else sig)
    }

    fun delete() = keyStore.deleteEntry(alias)

    /**
     * Public JWK for registering this key as a private_key_jwt client key (kid = RFC 7638 thumbprint,
     * the same kid the client assertion header carries). Also written to files/client-jwk.json so the
     * demo registration script can read it with `adb shell run-as` (public material only).
     */
    fun clientRegistrationJwk(context: Context): JSONObject {
        val jwk = publicJwk().put("kid", thumbprint()).put("use", "sig").put("alg", if (ec) "ES256" else "RS256")
        java.io.File(context.filesDir, "client-jwk.json").writeText(jwk.toString())
        return jwk
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** EC P-256 key for DPoP (RFC 9449). */
        fun ec(context: Context, alias: String): KeystoreKey = getOrCreate(context, alias, ec = true)

        /** RSA-2048 key for private_key_jwt client authentication. */
        fun rsa(context: Context, alias: String): KeystoreKey = getOrCreate(context, alias, ec = false)

        fun exists(alias: String): Boolean =
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(alias)

        private fun getOrCreate(context: Context, alias: String, ec: Boolean): KeystoreKey {
            if (!exists(alias)) generate(context, alias, ec)
            return KeystoreKey(alias, ec)
        }

        private fun generate(context: Context, alias: String, ec: Boolean) {
            val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            try {
                generate(alias, ec, strongBox)
            } catch (e: StrongBoxUnavailableException) {
                generate(alias, ec, strongBox = false)
            }
        }

        private fun generate(alias: String, ec: Boolean, strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(strongBox)
                .apply {
                    if (ec) setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    else {
                        setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537)))
                        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    }
                }
                .build()
            KeyPairGenerator.getInstance(
                if (ec) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE,
            ).apply { initialize(spec) }.generateKeyPair()
        }
    }
}

/** Builds RFC 9449 DPoP proofs with a Keystore key. */
class DPoP(private val key: KeystoreKey) {
    val jkt: String get() = key.thumbprint()

    fun proof(htm: String, htu: String, accessToken: String? = null, nonce: String? = null): String {
        val header = JSONObject().put("typ", "dpop+jwt").put("jwk", key.publicJwk())
        val claims = JSONObject()
            .put("jti", Jose.randomB64(16))
            .put("htm", htm.uppercase())
            .put("htu", htu.substringBefore('?').substringBefore('#'))
            .put("iat", System.currentTimeMillis() / 1000)
        if (!accessToken.isNullOrEmpty()) claims.put("ath", Jose.b64Sha256(accessToken))
        if (!nonce.isNullOrEmpty()) claims.put("nonce", nonce)
        return key.signJws(header, claims)
    }
}
