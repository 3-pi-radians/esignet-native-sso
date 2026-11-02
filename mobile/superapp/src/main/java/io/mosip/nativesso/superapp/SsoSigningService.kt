package io.mosip.nativesso.superapp

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import io.mosip.nativesso.core.AppIdentity
import io.mosip.nativesso.core.ISsoSigningService
import io.mosip.nativesso.core.SsoContract

/**
 * Native SSO handoff ("Super App signs for Child Apps"). The caller must hold the signature-level
 * permission (enforced by Android on bind) AND, on every call, be a known sibling package that is
 * signed with this app's certificate. The DPoP private key never leaves this process: callers get
 * proofs, and only for this issuer's token and userinfo endpoints.
 */
class SsoSigningService : Service() {

    private val binder = object : ISsoSigningService.Stub() {
        override fun getSsoArtifacts(): Bundle = guarded { caller ->
            val session = SuperAppSession.get(this@SsoSigningService)
            val active = session.activeSession() ?: return@guarded failure(
                if (session.hasExpiredSession()) SsoContract.ERROR_SESSION_EXPIRED else SsoContract.ERROR_NOT_SIGNED_IN)
            val deviceSecret = active.optString("device_secret")
            if (deviceSecret.isEmpty()) return@guarded failure(SsoContract.ERROR_NOT_SIGNED_IN)
            val tokenEndpoint = session.client.discovery().tokenEndpoint
            Log.i(TAG, "Native SSO artifacts served to $caller")
            Bundle().apply {
                putString(SsoContract.KEY_ID_TOKEN, active.getString("id_token"))
                putString(SsoContract.KEY_DEVICE_SECRET, deviceSecret)
                putString(SsoContract.KEY_DPOP_PROOF, session.proofs.proof("POST", tokenEndpoint, null, null))
                putString(SsoContract.KEY_GRANTED_SCOPE, active.optString("scope"))
            }
        }

        override fun signDPoPProof(htm: String?, htu: String?, accessToken: String?, nonce: String?): Bundle =
            guarded { _ ->
                val session = SuperAppSession.get(this@SsoSigningService)
                if (session.activeSession() == null) return@guarded failure(SsoContract.ERROR_NOT_SIGNED_IN)
                val d = session.client.discovery()
                val allowed = (htm == "POST" && htu == d.tokenEndpoint) || (htm == "GET" && htu == d.userinfoEndpoint)
                if (!allowed) return@guarded failure(SsoContract.ERROR_TARGET_NOT_ALLOWED)
                Bundle().apply { putString(SsoContract.KEY_DPOP_PROOF, session.proofs.proof(htm!!, htu!!, accessToken, nonce)) }
            }
    }

    /** Re-verifies the binder caller on every call; never trusts the package name alone. */
    private inline fun guarded(block: (caller: String) -> Bundle): Bundle {
        val uid = Binder.getCallingUid()
        val caller = packageManager.getPackagesForUid(uid).orEmpty()
            .firstOrNull { it in SsoContract.TRUSTED_CHILD_PACKAGES && AppIdentity.sharesSigner(this, it) }
        if (caller == null) {
            Log.w(TAG, "rejected Native SSO call from uid $uid")
            return failure(SsoContract.ERROR_CALLER_NOT_TRUSTED)
        }
        return try {
            block(caller)
        } catch (e: Exception) {
            Log.w(TAG, "Native SSO call failed: ${e.javaClass.simpleName}")
            failure(SsoContract.ERROR_INTERNAL)
        }
    }

    private fun failure(code: String) = Bundle().apply { putString(SsoContract.KEY_ERROR, code) }

    override fun onBind(intent: Intent?): IBinder = binder

    private companion object { const val TAG = "SsoSigningService" }
}
