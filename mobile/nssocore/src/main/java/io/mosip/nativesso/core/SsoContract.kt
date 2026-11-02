package io.mosip.nativesso.core

/** Shared constants of the Super App <-> Child App handoff. */
object SsoContract {
    /** Signature-level permission guarding the Super App's SSO signing service. */
    const val PERMISSION = "io.mosip.nativesso.permission.SSO"
    const val SUPER_APP_PACKAGE = "io.mosip.nativesso.superapp"
    const val SERVICE_CLASS = "io.mosip.nativesso.superapp.SsoSigningService"

    /** Sibling packages the Super App will serve (in addition to the same-signer check). */
    val TRUSTED_CHILD_PACKAGES = setOf("io.mosip.nativesso.childapp")

    const val KEY_ID_TOKEN = "id_token"
    const val KEY_DEVICE_SECRET = "device_secret"
    const val KEY_DPOP_PROOF = "dpop_proof"
    const val KEY_DPOP_JKT = "dpop_jkt"
    const val KEY_GRANTED_SCOPE = "granted_scope"
    const val KEY_ERROR = "error"

    const val ERROR_NOT_SIGNED_IN = "not_signed_in"
    const val ERROR_CALLER_NOT_TRUSTED = "caller_not_trusted"
    const val ERROR_TARGET_NOT_ALLOWED = "target_not_allowed"
    const val ERROR_INTERNAL = "internal_error"

    const val TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    const val TOKEN_TYPE_DEVICE_SECRET = "urn:openid:params:token-type:device-secret"
    const val GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
}
