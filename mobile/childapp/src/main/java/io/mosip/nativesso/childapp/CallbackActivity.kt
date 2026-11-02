package io.mosip.nativesso.childapp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Redirect target of the re-consent authorization flow (bonus task). */
class CallbackActivity : Activity() {
    private val scope = MainScope()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent?.data
        if (uri == null) { finish(); return }
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { ChildSession.get(this@CallbackActivity).completeConsentFlow(uri) }
            }
            result.exceptionOrNull()?.let {
                Log.w("ChildCallback", "consent flow failed: ${it.message}")
                Toast.makeText(this@CallbackActivity, "Consent flow failed: ${it.message}", Toast.LENGTH_LONG).show()
            }
            startActivity(Intent(this@CallbackActivity, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            finish()
        }
    }

    override fun onDestroy() {
        scope.coroutineContext[Job]?.cancel()
        super.onDestroy()
    }
}
