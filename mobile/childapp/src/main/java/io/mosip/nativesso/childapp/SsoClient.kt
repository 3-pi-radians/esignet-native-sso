package io.mosip.nativesso.childapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import io.mosip.nativesso.core.AppIdentity
import io.mosip.nativesso.core.ISsoSigningService
import io.mosip.nativesso.core.ProofProvider
import io.mosip.nativesso.core.SsoContract
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class SsoUnavailable(val code: String) : Exception(code)

/**
 * Talks to the Super App's SSO signing service over an explicit, permission-protected binding.
 * The Super App is verified as well: it must be installed and signed with our own certificate.
 */
class SsoClient(private val context: Context) {

    suspend fun <T> use(block: (ISsoSigningService) -> T): T {
        if (!AppIdentity.sharesSigner(context, SsoContract.SUPER_APP_PACKAGE)) {
            throw SsoUnavailable("super_app_missing_or_untrusted")
        }
        var connection: ServiceConnection? = null
        try {
            val service = withTimeout(5_000) {
                suspendCancellableCoroutine<ISsoSigningService> { cont ->
                    val conn = object : ServiceConnection {
                        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                            if (cont.isActive) cont.resume(ISsoSigningService.Stub.asInterface(binder))
                        }
                        override fun onServiceDisconnected(name: ComponentName?) {}
                        override fun onNullBinding(name: ComponentName?) {
                            if (cont.isActive) cont.resumeWithException(SsoUnavailable("null_binding"))
                        }
                    }
                    connection = conn
                    val intent = Intent("io.mosip.nativesso.action.SSO")
                        .setComponent(ComponentName(SsoContract.SUPER_APP_PACKAGE, SsoContract.SERVICE_CLASS))
                    val bound = try {
                        context.bindService(intent, conn, Context.BIND_AUTO_CREATE)
                    } catch (e: SecurityException) {
                        false
                    }
                    if (!bound && cont.isActive) cont.resumeWithException(SsoUnavailable("bind_denied"))
                }
            }
            return block(service)
        } finally {
            connection?.let { runCatching { context.unbindService(it) } }
        }
    }

    /** DPoP proofs signed by the Super App's key A, for this issuer's token/userinfo endpoints. */
    fun remoteProofs(service: ISsoSigningService) = ProofProvider { htm, htu, at, nonce ->
        val b: Bundle = service.signDPoPProof(htm, htu, at, nonce)
        b.getString(SsoContract.KEY_ERROR)?.let { throw SsoUnavailable(it) }
        b.getString(SsoContract.KEY_DPOP_PROOF) ?: throw SsoUnavailable(SsoContract.ERROR_INTERNAL)
    }
}
