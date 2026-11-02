// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	oauth2utils "github.com/thunder-id/thunderid/internal/oauth/oauth2/utils"
	"github.com/thunder-id/thunderid/internal/system/jose/jwt"
	"github.com/thunder-id/thunderid/internal/system/log"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// validateNativeSSORequest checks the request shape of an OpenID Connect Native SSO token exchange
// (OpenID Connect Native SSO for Mobile Apps 1.0, section 4.1): the subject_token is an ID token, the
// requested token (if named) is an access token, and resources are not supported.
func validateNativeSSORequest(tokenRequest *model.TokenRequest) *model.ErrorResponse {
	if constants.TokenTypeIdentifier(tokenRequest.SubjectTokenType) != constants.TokenTypeIdentifierIDToken {
		return &model.ErrorResponse{
			Error: constants.ErrorInvalidRequest,
			ErrorDescription: "A device-secret actor_token requires subject_token_type " +
				string(constants.TokenTypeIdentifierIDToken),
		}
	}
	if tokenRequest.RequestedTokenType != "" &&
		constants.TokenTypeIdentifier(tokenRequest.RequestedTokenType) != constants.TokenTypeIdentifierAccessToken {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Native SSO only issues access tokens",
		}
	}
	if len(tokenRequest.Resources) > 0 {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidTarget,
			ErrorDescription: "The resource parameter is not supported for Native SSO",
		}
	}
	return nil
}

// handleNativeSSOGrant signs a second application in silently using the first application's ID token
// (subject_token) and device secret (actor_token). The request must carry a DPoP proof made with the
// key the device secret is bound to.
func (h *tokenExchangeGrantHandler) handleNativeSSOGrant(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient) (*model.TokenResponseDTO, *model.ErrorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NativeSSOGrantHandler"))

	if h.deviceSecretProvider == nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Native SSO is not supported by this server",
		}
	}

	// The spec requires the audience to be the issuer of the ID token, i.e. this server.
	if len(tokenRequest.Audiences) != 1 || tokenRequest.Audiences[0] != h.cfg.JWT.Issuer {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidTarget,
			ErrorDescription: "The audience parameter must be the issuer of the ID token",
		}
	}

	// The device secret is bound to a DPoP key; without a verified proof there is nothing to match.
	jkt := dpop.GetJkt(ctx)
	if jkt == "" {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidDPoPProof,
			ErrorDescription: "A DPoP proof is required for Native SSO",
		}
	}

	dsClaims, errResp := h.validateDeviceSecret(ctx, tokenRequest.ClientID, tokenRequest.ActorToken, logger)
	if errResp != nil {
		return nil, errResp
	}

	// The proof key must be the very key the device secret was bound to at issuance.
	if !constantTimeEquals(jkt, dsClaims.CnfJkt) {
		return nil, invalidGrant("The DPoP proof key does not match the device_secret binding")
	}

	idClaims, errResp := h.validateNativeSSOIDToken(ctx, tokenRequest.SubjectToken, dsClaims.ClientID, logger)
	if errResp != nil {
		return nil, errResp
	}

	// ds_hash binds the ID token to this exact device secret.
	dsHash, _ := idClaims[constants.ClaimDeviceSecretHash].(string)
	if dsHash == "" || !constantTimeEquals(dsHash, computeDeviceSecretHash(tokenRequest.ActorToken)) {
		return nil, invalidGrant("The subject_token is not bound to the device_secret")
	}

	// sid ties the ID token to the authentication session recorded in the device secret; the
	// provider has already confirmed that session is still active.
	sid, _ := idClaims[constants.ClaimSessionID].(string)
	if sid == "" || !constantTimeEquals(sid, dsClaims.AuthID) {
		return nil, invalidGrant("The subject_token session does not match the device_secret")
	}
	if sub, _ := idClaims["sub"].(string); sub == "" || sub != dsClaims.Subject {
		return nil, invalidGrant("The subject_token subject does not match the device_secret")
	}

	// The client that minted the device secret must still be registered for device_sso.
	if errResp := h.checkOriginalClientDeviceSSO(ctx, dsClaims.ClientID, logger); errResp != nil {
		return nil, errResp
	}

	finalScopes, errResp := resolveNativeSSOScopes(tokenRequest.Scope, dsClaims.Scopes, oauthApp)
	if errResp != nil {
		return nil, errResp
	}

	resp, errResp := h.issueNativeSSOTokens(ctx, tokenRequest, oauthApp, dsClaims, finalScopes, jkt, logger)
	if errResp != nil {
		return nil, errResp
	}

	// Record the redemption only once tokens exist, so a failure while building them never consumes
	// the device secret. A provider whose policy forbids this redemption still blocks the response.
	if err := h.deviceSecretProvider.MarkDeviceSecretUsed(ctx, dsClaims, tokenRequest.ClientID); err != nil {
		if errors.Is(err, providers.ErrDeviceSecretReplayed) {
			return nil, invalidGrant("The device_secret was already redeemed by this client")
		}
		logger.Error(ctx, "Failed to record device secret redemption", log.Error(err))
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to process token request",
		}
	}
	return resp, nil
}

// validateDeviceSecret invokes the provider and maps its errors: credential problems become
// invalid_grant, anything else server_error.
func (h *tokenExchangeGrantHandler) validateDeviceSecret(ctx context.Context, clientID, deviceSecret string,
	logger *log.Logger) (*providers.DeviceSecretClaims, *model.ErrorResponse) {
	claims, err := h.deviceSecretProvider.ValidateDeviceSecret(ctx, clientID, deviceSecret)
	if err != nil {
		switch {
		case errors.Is(err, providers.ErrDeviceSecretExpired):
			return nil, invalidGrant("The device_secret has expired")
		case errors.Is(err, providers.ErrDeviceSecretRevoked):
			return nil, invalidGrant("The device_secret session is no longer active")
		case errors.Is(err, providers.ErrDeviceSecretClientNotPermitted):
			return nil, invalidGrant("The client is not permitted to use this device_secret")
		case errors.Is(err, providers.ErrDeviceSecretInvalid):
			return nil, invalidGrant("Invalid device_secret")
		default:
			logger.Error(ctx, "Device secret validation failed unexpectedly", log.Error(err))
			return nil, &model.ErrorResponse{
				Error:            constants.ErrorServerError,
				ErrorDescription: "Failed to process token request",
			}
		}
	}
	if claims == nil || claims.Subject == "" || claims.ClientID == "" || claims.AuthID == "" ||
		claims.CnfJkt == "" {
		return nil, invalidGrant("Invalid device_secret")
	}
	return claims, nil
}

// validateNativeSSOIDToken validates the subject_token as an ID token this server issued to the
// original client: compact JWS (not JWE), typ JWT, not a refresh token, valid signature, issuer and
// audience, and not issued in the future.
//
// Its exp is deliberately not enforced. The ID token is used like an id_token_hint (OpenID Connect
// Native SSO 1.0, section 4.1): it identifies the session, while the lifetime of that session is
// carried by the device secret it is bound to through ds_hash and sid. ID tokens are short-lived
// (eSignet: minutes), whereas the device secret defines the Native SSO window.
func (h *tokenExchangeGrantHandler) validateNativeSSOIDToken(ctx context.Context, idToken, originalClientID string,
	logger *log.Logger) (map[string]interface{}, *model.ErrorResponse) {
	if strings.Count(idToken, ".") != 2 {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "The subject_token must be a signed ID token",
		}
	}
	header, err := jwt.DecodeJWTHeader(idToken)
	if err != nil {
		return nil, &model.ErrorResponse{Error: constants.ErrorInvalidRequest, ErrorDescription: "Invalid subject_token"}
	}
	if typ, _ := header["typ"].(string); typ != jwt.TokenTypeJWT {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "The subject_token is not an ID token",
		}
	}
	claims, err := jwt.DecodeJWTPayload(idToken)
	if err != nil {
		return nil, &model.ErrorResponse{Error: constants.ErrorInvalidRequest, ErrorDescription: "Invalid subject_token"}
	}
	if _, isRefreshToken := claims["access_token_sub"]; isRefreshToken {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "The subject_token is not an ID token",
		}
	}
	if svcErr := h.jwtService.VerifyJWTSignature(ctx, idToken); svcErr != nil {
		logger.Debug(ctx, "Native SSO subject_token signature verification failed", log.String("error", svcErr.Code))
		return nil, invalidGrant("Invalid subject_token")
	}
	if iss, _ := claims["iss"].(string); iss != h.cfg.JWT.Issuer {
		return nil, invalidGrant("Invalid subject_token")
	}
	if !audienceContains(claims["aud"], originalClientID) {
		return nil, invalidGrant("Invalid subject_token")
	}
	if iat, ok := claims["iat"].(float64); !ok || int64(iat) > time.Now().Unix()+h.cfg.JWT.Leeway {
		return nil, invalidGrant("Invalid subject_token")
	}
	return claims, nil
}

// checkOriginalClientDeviceSSO confirms the client the device secret was minted for still exists and
// still has device_sso among its registered scopes.
func (h *tokenExchangeGrantHandler) checkOriginalClientDeviceSSO(ctx context.Context, clientID string,
	logger *log.Logger) *model.ErrorResponse {
	originalClient, svcErr := h.actorProvider.GetOAuthClientByClientID(ctx, clientID)
	if svcErr != nil && svcErr.Type == tidcommon.ServerErrorType {
		logger.Error(ctx, "Failed to load the device_secret's original client", log.String("error", svcErr.Code))
		return &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to process token request",
		}
	}
	if svcErr != nil || originalClient == nil ||
		!slices.Contains(originalClient.Scopes, constants.ScopeDeviceSSO) {
		return invalidGrant("The device_secret's client is no longer authorized for device_sso")
	}
	return nil
}

// resolveNativeSSOScopes decides the scopes the second application receives. With no scope parameter
// it inherits the original grant. A requested scope must be an OpenID scope, allowed for the
// requesting client, and part of the original grant: anything beyond the original grant needs the
// user's consent, so the request fails with interaction_required and the client restarts the
// browser-based authorization flow.
func resolveNativeSSOScopes(requestedScope string, grantedScopes []string,
	oauthApp *providers.OAuthClient) ([]string, *model.ErrorResponse) {
	granted := withoutScope(grantedScopes, constants.ScopeDeviceSSO)
	requested := tokenservice.ParseScopes(requestedScope)
	if len(requested) == 0 {
		requested = granted
	}

	if !slices.Contains(requested, constants.ScopeOpenID) {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "The scope parameter must include openid",
		}
	}

	_, permissionScopes := oauth2utils.SeparateOIDCAndNonOIDCScopes(strings.Join(requested, " "),
		oauthApp.ScopeClaims)
	if len(permissionScopes) > 0 {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "Only OpenID Connect scopes can be obtained through Native SSO",
		}
	}

	if len(oauthApp.Scopes) > 0 {
		for _, s := range requested {
			if s != constants.ScopeOpenID && !slices.Contains(oauthApp.Scopes, s) {
				return nil, &model.ErrorResponse{
					Error:            constants.ErrorInvalidScope,
					ErrorDescription: "The client is not authorized for the requested scope",
				}
			}
		}
	}

	var notGranted []string
	for _, s := range requested {
		if !slices.Contains(granted, s) {
			notGranted = append(notGranted, s)
		}
	}
	if len(notGranted) > 0 {
		return nil, &model.ErrorResponse{
			Error: constants.ErrorInteractionRequired,
			ErrorDescription: "User consent is required for scopes not granted to the original application: " +
				strings.Join(notGranted, " "),
		}
	}
	return requested, nil
}

// issueNativeSSOTokens issues the second application's DPoP-bound access token and ID token. The ID
// token carries the same sid, since both applications share one authentication session.
func (h *tokenExchangeGrantHandler) issueNativeSSOTokens(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient, dsClaims *providers.DeviceSecretClaims, scopes []string, jkt string,
	logger *log.Logger) (*model.TokenResponseDTO, *model.ErrorResponse) {
	attrs, attributeCacheID := h.reusableAttributes(ctx, tokenRequest.ClientID, dsClaims, scopes, logger)

	userSubConfig := oauthApp.UserAccessTokenConfig()
	accessToken, err := h.tokenBuilder.BuildAccessToken(ctx, &tokenservice.AccessTokenBuildContext{
		Subject:           dsClaims.Subject,
		Audiences:         []string{oauthApp.ResolveDefaultAudience(tokenRequest.ClientID)},
		ClientID:          tokenRequest.ClientID,
		Scopes:            scopes,
		SubjectAttributes: tokenservice.FilterAttributesByAllowList(attrs, userSubConfig),
		AttributeCacheID:  attributeCacheID,
		GrantType:         string(providers.GrantTypeTokenExchange),
		OAuthApp:          oauthApp,
		ValidityPeriod:    userSubConfig.ValidityPeriodOrZero(),
		DPoPJkt:           jkt,
	})
	if err != nil {
		logger.Error(ctx, "Failed to generate Native SSO access token", log.Error(err))
		return nil, &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to generate token"}
	}

	idToken, err := h.tokenBuilder.BuildIDToken(ctx, &tokenservice.IDTokenBuildContext{
		Subject:        dsClaims.Subject,
		Audience:       tokenRequest.ClientID,
		Scopes:         scopes,
		UserAttributes: attrs,
		AuthTime:       dsClaims.AuthTime,
		OAuthApp:       oauthApp,
		CompletedACR:   dsClaims.ACR,
		SessionID:      dsClaims.AuthID,
	})
	if err != nil {
		logger.Error(ctx, "Failed to generate Native SSO ID token", log.Error(err))
		return nil, &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to generate token"}
	}

	return &model.TokenResponseDTO{AccessToken: *accessToken, IDToken: *idToken}, nil
}

// reusableAttributes returns the original login's cached user attributes when the requesting client
// may receive them. Attributes held as individual claims are filtered per scope and per client
// downstream, so they are always reusable. An opaque identity-system JWT
// (providers.RawJWTAttributeKey) cannot be filtered and is addressed to the original client: it is
// reused only by that same client with exactly the original scopes, and never handed to a sibling.
func (h *tokenExchangeGrantHandler) reusableAttributes(ctx context.Context, clientID string,
	dsClaims *providers.DeviceSecretClaims, scopes []string, logger *log.Logger) (map[string]interface{}, string) {
	if dsClaims.AttributeCacheID == "" || h.attributeCache == nil {
		return map[string]interface{}{}, ""
	}
	cached, svcErr := h.attributeCache.GetAttributeCache(ctx, dsClaims.AttributeCacheID)
	if svcErr != nil || cached == nil || cached.Attributes == nil {
		logger.Debug(ctx, "User attributes of the original login are no longer cached")
		return map[string]interface{}{}, ""
	}
	if _, opaque := cached.Attributes[providers.RawJWTAttributeKey]; opaque &&
		(clientID != dsClaims.ClientID ||
			!sameScopeSet(scopes, withoutScope(dsClaims.Scopes, constants.ScopeDeviceSSO))) {
		return map[string]interface{}{}, ""
	}
	return cached.Attributes, dsClaims.AttributeCacheID
}

// sameScopeSet reports whether a and b contain the same scopes, ignoring order and duplicates.
func sameScopeSet(a, b []string) bool {
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	for _, s := range b {
		if !slices.Contains(a, s) {
			return false
		}
	}
	return true
}

// audienceContains reports whether a JWT aud claim (string or array) names clientID.
func audienceContains(aud interface{}, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []interface{}:
		for _, a := range v {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

func invalidGrant(description string) *model.ErrorResponse {
	return &model.ErrorResponse{Error: constants.ErrorInvalidGrant, ErrorDescription: description}
}
