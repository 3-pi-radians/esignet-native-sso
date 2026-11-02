package io.mosip.nativesso.core;

import android.os.Bundle;

/**
 * Native SSO handoff exposed by the Super App to sibling apps signed with the same certificate.
 * The binding is protected by a signature-level permission and every call re-verifies the caller.
 * The DPoP private key never leaves the Super App: callers receive signed proofs, not keys.
 */
interface ISsoSigningService {
    /**
     * Returns id_token, device_secret and a DPoP proof (htm=POST, htu=token endpoint) signed with
     * the Super App's key, or an "error" entry. Keys: see SsoContract.
     */
    Bundle getSsoArtifacts();

    /**
     * Signs a DPoP proof with the Super App's key for a request to this issuer's token or userinfo
     * endpoint only. accessToken (nullable) adds the ath claim; nonce (nullable) echoes a
     * server-issued DPoP-Nonce.
     */
    Bundle signDPoPProof(String htm, String htu, String accessToken, String nonce);
}
