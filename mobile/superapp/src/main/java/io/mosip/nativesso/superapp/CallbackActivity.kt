package io.mosip.nativesso.superapp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Receives the OAuth redirect, completes the code exchange off the main thread, returns home. */
class CallbackActivity : Activity() {
    private val scope: CoroutineScope = MainScope()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent?.data
        if (uri == null) { finish(); return }
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { SuperAppSession.get(this@CallbackActivity).completeLogin(uri) }
            }
            result.exceptionOrNull()?.let {
                // Message only: never log tokens or codes.
                Log.w(TAG, "login failed: ${it.message}")
                Toast.makeText(this@CallbackActivity, "Sign-in failed: ${it.message}", Toast.LENGTH_LONG).show()
            }
            startActivity(Intent(this@CallbackActivity, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            finish()
        }
    }

    override fun onDestroy() {
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
        super.onDestroy()
    }

    private companion object { const val TAG = "SuperAppCallback" }
}
