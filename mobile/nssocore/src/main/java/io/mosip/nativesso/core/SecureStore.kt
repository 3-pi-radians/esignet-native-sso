package io.mosip.nativesso.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores a small JSON document encrypted with AES-256-GCM under a non-exportable Android Keystore
 * key, in the app's private files directory. Tokens and the device secret are never written in
 * plaintext (no SharedPreferences, no external storage).
 */
class SecureStore(context: Context, name: String) {
    private val file = File(context.filesDir, "$name.enc")
    private val alias = "nsso-store-$name"

    fun write(doc: JSONObject) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ct = cipher.doFinal(doc.toString().toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + ct)
        if (!tmp.renameTo(file)) throw IllegalStateException("could not persist secure store")
    }

    /** Returns the stored document, or null when absent or unreadable (e.g. key invalidated). */
    fun read(): JSONObject? {
        if (!file.exists()) return null
        return try {
            val bytes = file.readBytes()
            val ivLen = bytes[0].toInt()
            val iv = bytes.copyOfRange(1, 1 + ivLen)
            val cipher = Cipher.getInstance(TRANSFORMATION)
                .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
            JSONObject(String(cipher.doFinal(bytes.copyOfRange(1 + ivLen, bytes.size)), Charsets.UTF_8))
        } catch (e: Exception) {
            clear()
            null
        }
    }

    fun clear() {
        file.delete()
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
