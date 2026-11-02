package io.mosip.nativesso.core

import org.junit.Assert.assertEquals
import org.junit.Test

class ScopesTest {
    @Test fun exchangeNeverRequestsDeviceSsoAndAlwaysOpenid() {
        assertEquals(listOf("openid", "email"), Scopes.forExchange(listOf("email", "device_sso")))
        assertEquals(listOf("openid", "email"), Scopes.forExchange(listOf("openid", "email", "openid")))
    }

    @Test fun notGrantedDrivesReconsent() {
        val granted = Scopes.parse("openid profile email device_sso")
        assertEquals(emptyList<String>(), Scopes.notGranted(listOf("openid", "email"), granted))
        assertEquals(listOf("phone"), Scopes.notGranted(listOf("openid", "email", "phone"), granted))
    }

    @Test fun parseIgnoresBlanksAndDuplicates() {
        assertEquals(listOf("openid", "email"), Scopes.parse("  openid  email openid "))
        assertEquals(emptyList<String>(), Scopes.parse(null))
    }

    @Test fun pkceChallengeIsS256OfVerifier() {
        val p = Pkce.create()
        assertEquals(Jose.b64Sha256(p.verifier), p.challenge)
        assertEquals(43, p.verifier.length)
    }
}
