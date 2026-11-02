package io.mosip.nativesso.core

import android.content.Context
import android.content.pm.PackageManager

/**
 * Verifies that another installed app is signed with the same certificate(s) as this app. This is
 * the "same vendor" check Native SSO relies on; the package name alone is never trusted.
 */
object AppIdentity {
    fun ownSigners(context: Context): List<ByteArray> {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return emptyList()
        val sigs = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
        return sigs.orEmpty().map { it.toByteArray() }
    }

    /** True when [packageName] is installed and holds every one of this app's current signing certificates. */
    fun sharesSigner(context: Context, packageName: String): Boolean {
        val own = ownSigners(context)
        if (own.isEmpty()) return false
        val pm = context.packageManager
        return try {
            own.all { pm.hasSigningCertificate(packageName, it, PackageManager.CERT_INPUT_RAW_X509) }
        } catch (e: Exception) {
            false
        }
    }

    /** SHA-256 fingerprint of this app's first signing certificate, for display and documentation. */
    fun signerFingerprint(context: Context): String =
        ownSigners(context).firstOrNull()?.let { Jose.sha256(it).joinToString(":") { b -> "%02X".format(b) } } ?: "unknown"
}
