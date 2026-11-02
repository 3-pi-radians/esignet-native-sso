// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"slices"
	"sort"
	"time"

	"github.com/thunder-id/thunderid/internal/attributecache"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	oauth2utils "github.com/thunder-id/thunderid/internal/oauth/oauth2/utils"
	"github.com/thunder-id/thunderid/internal/system/log"
	sysutils "github.com/thunder-id/thunderid/internal/system/utils"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// computeDeviceSecretHash returns the ds_hash of a device secret.
//
// OpenID Connect Native SSO 1.0 leaves the ds_hash/device_secret binding to the deployment. This
// implementation uses BASE64URL(SHA-256(device_secret)) over the ASCII octets of the device secret,
// unpadded, as defined by the MOSIP eSignet Native SSO design.
func computeDeviceSecretHash(deviceSecret string) string {
	sum := sha256.Sum256([]byte(deviceSecret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// constantTimeEquals compares two strings without leaking their common prefix length through timing.
func constantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// withoutScope returns scopes with every occurrence of scope removed.
func withoutScope(scopes []string, scope string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != scope {
			out = append(out, s)
		}
	}
	return out
}

// consentedClaimNames returns the user claims a login released: the claims mapped to its granted
// scopes, the claims named in its claims request, and the names of the released user attributes. An
// opaque identity-system JWT (providers.RawJWTAttributeKey) is not a claim name and is skipped.
func consentedClaimNames(scopes []string, claimsRequest *model.ClaimsRequest, scopeClaims map[string][]string,
	attrs map[string]interface{}) []string {
	set := map[string]struct{}{}
	for _, scope := range scopes {
		for _, claim := range oauth2utils.ResolveScopeClaims(scope, scopeClaims) {
			set[claim] = struct{}{}
		}
	}
	if claimsRequest != nil {
		for claim := range claimsRequest.IDToken {
			set[claim] = struct{}{}
		}
		for claim := range claimsRequest.UserInfo {
			set[claim] = struct{}{}
		}
	}
	for name := range attrs {
		if name != providers.RawJWTAttributeKey {
			set[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// deviceSSOIneligibility explains why a device secret cannot be issued on an authorization_code grant
// whose code carries the device_sso scope, or returns "" when it can: the server must have a device
// secret provider, the client must still be registered for device_sso, openid must have been granted,
// and the token request must carry a verified DPoP proof (the device secret is bound to that key via
// cnf.jkt).
//
// By this point the one-time authorization code is already consumed, so an ineligible request is
// not failed (that would force the user through the whole login again). The grant proceeds as an
// ordinary login: no device secret is issued and device_sso is left out of the granted scope, which
// is how RFC 6749 section 3.3 tells the client a requested scope was not granted.
func deviceSSOIneligibility(ctx context.Context, deviceSecretProvider providers.DeviceSecretProvider,
	oauthApp *providers.OAuthClient, grantedScopes []string) string {
	switch {
	case deviceSecretProvider == nil:
		return "no device secret provider is configured"
	case oauthApp == nil || !slices.Contains(oauthApp.Scopes, constants.ScopeDeviceSSO):
		return "the client is not registered for device_sso"
	case !slices.Contains(grantedScopes, constants.ScopeOpenID):
		return "openid was not granted"
	case dpop.GetJkt(ctx) == "":
		return "the token request carried no DPoP proof"
	}
	return ""
}

// issueDeviceSecret mints a device secret for the authorization_code grant and returns it together
// with the session id (sid) and ds_hash to embed in the ID token. When the login cached user
// attributes, the cache entry is kept alive for the device secret's lifetime so that tokens issued
// later through Native SSO can release the same consented claims.
func issueDeviceSecret(
	ctx context.Context,
	deviceSecretProvider providers.DeviceSecretProvider,
	attributeCache attributecache.AttributeCacheServiceInterface,
	req *providers.DeviceSecretRequest,
	logger *log.Logger,
) (deviceSecret, sid, dsHash string, errResp *model.ErrorResponse) {
	req.AuthID = sysutils.GenerateUUID()

	secret, err := deviceSecretProvider.GenerateDeviceSecret(ctx, req)
	if err != nil || secret == nil || secret.Value == "" {
		logger.Error(ctx, "Failed to generate device secret", log.Error(err))
		return "", "", "", &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate device secret",
		}
	}

	if req.AttributeCacheID != "" && attributeCache != nil {
		ttl := secret.ExpiresAt - time.Now().Unix() + constants.AttributeCacheTTLBufferSeconds
		if ttl > 0 {
			if svcErr := attributeCache.ExtendAttributeCacheTTL(ctx, req.AttributeCacheID, int(ttl)); svcErr != nil {
				logger.Error(ctx, "Failed to extend attribute cache TTL for device secret",
					log.String("error", svcErr.Code))
				return "", "", "", &model.ErrorResponse{
					Error:            constants.ErrorServerError,
					ErrorDescription: "Failed to generate device secret",
				}
			}
		}
	}

	return secret.Value, req.AuthID, computeDeviceSecretHash(secret.Value), nil
}
