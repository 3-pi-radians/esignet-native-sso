// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/attributecache"
	oauthconfig "github.com/thunder-id/thunderid/internal/oauth/config"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/authz"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	"github.com/thunder-id/thunderid/internal/system/config"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	engineconfig "github.com/thunder-id/thunderid/pkg/thunderidengine/config"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
	"github.com/thunder-id/thunderid/tests/mocks/actorprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/attributecachemock"
	"github.com/thunder-id/thunderid/tests/mocks/devicesecretprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/jose/jwtmock"
	"github.com/thunder-id/thunderid/tests/mocks/oauth/oauth2/authzmock"
	"github.com/thunder-id/thunderid/tests/mocks/oauth/oauth2/tokenservicemock"
	"github.com/thunder-id/thunderid/tests/mocks/resourcemock"
)

const (
	nssoIssuer        = "https://esignet.example.com"
	nssoSuperClientID = "super-app"
	nssoChildClientID = "child-app"
	nssoJKT           = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	nssoOtherJKT      = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	nssoAuthID        = "3f5b8a52-3b9c-4bd1-9f3e-6c1b2b4c0a11"
	nssoDeviceSecret  = "eyJhbGciOiJSU0EtT0FFUC0yNTYifQ.k.iv.ct.tag"
	nssoCacheID       = "attr-cache-1"
)

// NativeSSOTestSuite covers OpenID Connect Native SSO: device secret issuance on the
// authorization_code grant and the device-secret token exchange.
type NativeSSOTestSuite struct {
	suite.Suite
	mockTokenBuilder   *tokenservicemock.TokenBuilderInterfaceMock
	mockAuthzService   *authzmock.AuthorizeServiceInterfaceMock
	mockAttrCache      *attributecachemock.AttributeCacheServiceInterfaceMock
	mockResource       *resourcemock.ResourceServiceInterfaceMock
	mockDeviceSecret   *devicesecretprovidermock.DeviceSecretProviderMock
	mockJWTService     *jwtmock.JWTServiceInterfaceMock
	mockActorProvider  *actorprovidermock.ActorProviderMock
	superApp           *providers.OAuthClient
	childApp           *providers.OAuthClient
	authCodeHandler    *authorizationCodeGrantHandler
	tokenExchangeHandl *tokenExchangeGrantHandler
	dsClaims           *providers.DeviceSecretClaims
}

func TestNativeSSOTestSuite(t *testing.T) {
	suite.Run(t, new(NativeSSOTestSuite))
}

func (s *NativeSSOTestSuite) SetupTest() {
	_ = config.InitializeServerRuntime("test", &config.Config{
		JWT: engineconfig.JWTConfig{ValidityPeriod: 3600},
	})

	s.mockTokenBuilder = tokenservicemock.NewTokenBuilderInterfaceMock(s.T())
	s.mockAuthzService = authzmock.NewAuthorizeServiceInterfaceMock(s.T())
	s.mockAttrCache = attributecachemock.NewAttributeCacheServiceInterfaceMock(s.T())
	s.mockResource = resourcemock.NewResourceServiceInterfaceMock(s.T())
	s.mockDeviceSecret = devicesecretprovidermock.NewDeviceSecretProviderMock(s.T())
	s.mockJWTService = jwtmock.NewJWTServiceInterfaceMock(s.T())
	s.mockActorProvider = actorprovidermock.NewActorProviderMock(s.T())

	scopeClaims := map[string][]string{
		"profile": {"name"},
		"email":   {"email"},
	}
	s.superApp = &providers.OAuthClient{
		ClientID:    nssoSuperClientID,
		GrantTypes:  []providers.GrantType{providers.GrantTypeAuthorizationCode},
		Scopes:      []string{"email", "profile", constants.ScopeDeviceSSO},
		ScopeClaims: scopeClaims,
	}
	s.childApp = &providers.OAuthClient{
		ClientID:    nssoChildClientID,
		GrantTypes:  []providers.GrantType{providers.GrantTypeTokenExchange},
		Scopes:      []string{"email", "profile"},
		ScopeClaims: scopeClaims,
	}

	s.authCodeHandler = &authorizationCodeGrantHandler{
		authzService:         s.mockAuthzService,
		tokenBuilder:         s.mockTokenBuilder,
		attributeCache:       s.mockAttrCache,
		resourceService:      s.mockResource,
		deviceSecretProvider: s.mockDeviceSecret,
	}
	s.tokenExchangeHandl = &tokenExchangeGrantHandler{
		tokenBuilder:         s.mockTokenBuilder,
		resourceService:      s.mockResource,
		actorProvider:        s.mockActorProvider,
		jwtService:           s.mockJWTService,
		attributeCache:       s.mockAttrCache,
		deviceSecretProvider: s.mockDeviceSecret,
		cfg:                  oauthconfig.Config{JWT: engineconfig.JWTConfig{Issuer: nssoIssuer, Leeway: 0}},
	}
	s.dsClaims = &providers.DeviceSecretClaims{
		JTI:              "ds-jti",
		Issuer:           nssoIssuer,
		Subject:          testUserID,
		AuthID:           nssoAuthID,
		ClientID:         nssoSuperClientID,
		Scopes:           []string{"openid", "email"},
		ACR:              "mosip:idp:acr:generated-code",
		Claims:           []string{"email"},
		AuthTime:         time.Now().Add(-time.Minute).Unix(),
		CnfJkt:           nssoJKT,
		AttributeCacheID: nssoCacheID,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
	}
}

// ---------------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------------

func dpopCtx(jkt string) context.Context {
	return dpop.WithJkt(context.Background(), jkt)
}

// fakeIDToken builds a compact JWS with the given claims. Signature verification is the JWT
// service's responsibility and is mocked here; the handler only parses header and payload itself.
func fakeIDToken(typ string, claims map[string]interface{}) string {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ})
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func (s *NativeSSOTestSuite) superIDTokenClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss":                           nssoIssuer,
		"sub":                           testUserID,
		"aud":                           nssoSuperClientID,
		"exp":                           float64(time.Now().Add(time.Hour).Unix()),
		"iat":                           float64(time.Now().Unix()),
		constants.ClaimSessionID:        nssoAuthID,
		constants.ClaimDeviceSecretHash: computeDeviceSecretHash(nssoDeviceSecret),
	}
}

func (s *NativeSSOTestSuite) exchangeRequest(idToken, scope string) *model.TokenRequest {
	return &model.TokenRequest{
		GrantType:        string(providers.GrantTypeTokenExchange),
		ClientID:         nssoChildClientID,
		SubjectToken:     idToken,
		SubjectTokenType: string(constants.TokenTypeIdentifierIDToken),
		ActorToken:       nssoDeviceSecret,
		ActorTokenType:   string(constants.TokenTypeIdentifierDeviceSecret),
		Audiences:        []string{nssoIssuer},
		Scope:            scope,
	}
}

func (s *NativeSSOTestSuite) expectValidDeviceSecret() {
	s.mockDeviceSecret.On("ValidateDeviceSecret", mock.Anything, nssoChildClientID, nssoDeviceSecret).
		Return(s.dsClaims, nil).Once()
}

func (s *NativeSSOTestSuite) expectValidIDTokenSignature(idToken string) {
	s.mockJWTService.On("VerifyJWT", mock.Anything, idToken, nssoSuperClientID, nssoIssuer).
		Return((*tidcommon.ServiceError)(nil)).Once()
}

func (s *NativeSSOTestSuite) expectOriginalClientDeviceSSO() {
	s.mockActorProvider.On("GetOAuthClientByClientID", mock.Anything, nssoSuperClientID).
		Return(s.superApp, (*tidcommon.ServiceError)(nil)).Once()
}

func (s *NativeSSOTestSuite) expectIssuance() (*providers.DeviceSecretClaims, *[]string) {
	s.mockDeviceSecret.On("MarkDeviceSecretUsed", mock.Anything, s.dsClaims, nssoChildClientID).
		Return(nil).Once()
	s.mockAttrCache.On("GetAttributeCache", mock.Anything, nssoCacheID).
		Return(&attributecache.AttributeCache{ID: nssoCacheID,
			Attributes: map[string]interface{}{"email": "user@example.com"}}, (*tidcommon.ServiceError)(nil)).Once()
	var accessScopes []string
	s.mockTokenBuilder.On("BuildAccessToken", mock.Anything, mock.MatchedBy(
		func(c *tokenservice.AccessTokenBuildContext) bool {
			accessScopes = c.Scopes
			return c.Subject == testUserID && c.ClientID == nssoChildClientID && c.DPoPJkt == nssoJKT &&
				c.AttributeCacheID == nssoCacheID &&
				c.GrantType == string(providers.GrantTypeTokenExchange)
		})).Return(&model.TokenDTO{Token: "child-at", Scopes: []string{"openid", "email"}}, nil).Once()
	s.mockTokenBuilder.On("BuildIDToken", mock.Anything, mock.MatchedBy(
		func(c *tokenservice.IDTokenBuildContext) bool {
			return c.Audience == nssoChildClientID && c.SessionID == nssoAuthID && c.DeviceSecretHash == "" &&
				c.CompletedACR == s.dsClaims.ACR && c.Subject == testUserID
		})).Return(&model.TokenDTO{Token: "child-idt"}, nil).Once()
	return s.dsClaims, &accessScopes
}

func (s *NativeSSOTestSuite) assertError(errResp *model.ErrorResponse, code string) {
	s.Require().NotNil(errResp)
	s.Equal(code, errResp.Error)
}

// ---------------------------------------------------------------------------------------------------
// ds_hash and scope helpers
// ---------------------------------------------------------------------------------------------------

func (s *NativeSSOTestSuite) TestComputeDeviceSecretHash() {
	// SHA-256("abc") = ba7816bf..., base64url without padding.
	s.Equal("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", computeDeviceSecretHash("abc"))
	s.NotEqual(computeDeviceSecretHash("abc"), computeDeviceSecretHash("abd"))
}

func (s *NativeSSOTestSuite) TestResolveNativeSSOScopes() {
	granted := []string{"openid", "email", "profile", constants.ScopeDeviceSSO}

	got, errResp := resolveNativeSSOScopes("", granted, s.childApp)
	s.Nil(errResp)
	s.Equal([]string{"openid", "email", "profile"}, got, "no scope inherits the grant without device_sso")

	got, errResp = resolveNativeSSOScopes("openid email", granted, s.childApp)
	s.Nil(errResp)
	s.Equal([]string{"openid", "email"}, got, "a narrower scope is allowed")

	_, errResp = resolveNativeSSOScopes("openid email profile",
		[]string{"openid", "email"}, s.childApp)
	s.assertError(errResp, constants.ErrorInteractionRequired)
	s.Contains(errResp.ErrorDescription, "profile")

	_, errResp = resolveNativeSSOScopes("email", granted, s.childApp)
	s.assertError(errResp, constants.ErrorInvalidScope)

	_, errResp = resolveNativeSSOScopes("openid payments:write", granted, s.childApp)
	s.assertError(errResp, constants.ErrorInvalidScope)

	restricted := *s.childApp
	restricted.Scopes = []string{"email"}
	_, errResp = resolveNativeSSOScopes("openid profile", granted, &restricted)
	s.assertError(errResp, constants.ErrorInvalidScope)
}

// ---------------------------------------------------------------------------------------------------
// authorization_code grant: device secret issuance
// ---------------------------------------------------------------------------------------------------

func (s *NativeSSOTestSuite) authCode(scopes string) *authz.AuthorizationCode {
	return &authz.AuthorizationCode{
		Code:             "code-1",
		ClientID:         nssoSuperClientID,
		AuthorizedUserID: testUserID,
		AttributeCacheID: nssoCacheID,
		TimeCreated:      time.Now().Add(-time.Minute),
		ExpiryTime:       time.Now().Add(time.Minute),
		Scopes:           scopes,
		CompletedACR:     "mosip:idp:acr:generated-code",
		DPoPJkt:          nssoJKT,
	}
}

func (s *NativeSSOTestSuite) codeRequest() *model.TokenRequest {
	return &model.TokenRequest{
		GrantType: string(providers.GrantTypeAuthorizationCode),
		ClientID:  nssoSuperClientID,
		Code:      "code-1",
	}
}

func (s *NativeSSOTestSuite) TestAuthorizationCode_DeviceSSO_IssuesDeviceSecret() {
	s.mockAuthzService.On("GetAuthorizationCodeDetails", mock.Anything, nssoSuperClientID, "code-1").
		Return(s.authCode("openid email device_sso"), nil).Once()
	s.mockAttrCache.On("GetAttributeCache", mock.Anything, nssoCacheID).
		Return(&attributecache.AttributeCache{ID: nssoCacheID,
			Attributes: map[string]interface{}{"email": "user@example.com"}}, (*tidcommon.ServiceError)(nil)).Once()
	s.mockTokenBuilder.On("BuildAccessToken", mock.Anything, mock.Anything).
		Return(&model.TokenDTO{Token: "at"}, nil).Once()

	var dsReq *providers.DeviceSecretRequest
	s.mockDeviceSecret.On("GenerateDeviceSecret", mock.Anything, mock.MatchedBy(
		func(r *providers.DeviceSecretRequest) bool { dsReq = r; return true })).
		Return(&providers.DeviceSecret{Value: nssoDeviceSecret,
			ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil).Once()
	s.mockAttrCache.On("ExtendAttributeCacheTTL", mock.Anything, nssoCacheID,
		mock.MatchedBy(func(ttl int) bool { return ttl > 3600 && ttl <= 3600+constants.AttributeCacheTTLBufferSeconds })).
		Return((*tidcommon.ServiceError)(nil)).Once()

	var idCtx *tokenservice.IDTokenBuildContext
	s.mockTokenBuilder.On("BuildIDToken", mock.Anything, mock.MatchedBy(
		func(c *tokenservice.IDTokenBuildContext) bool { idCtx = c; return true })).
		Return(&model.TokenDTO{Token: "idt"}, nil).Once()

	resp, errResp := s.authCodeHandler.HandleGrant(dpopCtx(nssoJKT), s.codeRequest(), s.superApp)

	s.Require().Nil(errResp)
	s.Equal(nssoDeviceSecret, resp.DeviceSecret)
	s.Require().NotNil(dsReq)
	s.Equal(testUserID, dsReq.Subject)
	s.Equal(nssoSuperClientID, dsReq.ClientID)
	s.Equal([]string{"openid", "email"}, dsReq.Scopes, "device_sso is not carried into the device secret")
	s.Equal(nssoJKT, dsReq.CnfJkt)
	s.Equal("mosip:idp:acr:generated-code", dsReq.ACR)
	s.Equal([]string{"email", "sub"}, dsReq.Claims)
	s.Equal(nssoCacheID, dsReq.AttributeCacheID)
	s.NotEmpty(dsReq.AuthID)
	s.Require().NotNil(idCtx)
	s.Equal(dsReq.AuthID, idCtx.SessionID, "sid equals the device secret's auth_id")
	s.Equal(computeDeviceSecretHash(nssoDeviceSecret), idCtx.DeviceSecretHash)
}

func (s *NativeSSOTestSuite) TestAuthorizationCode_WithoutDeviceSSO_IsUnchanged() {
	code := s.authCode("openid email")
	code.AttributeCacheID = ""
	s.mockAuthzService.On("GetAuthorizationCodeDetails", mock.Anything, nssoSuperClientID, "code-1").
		Return(code, nil).Once()
	s.mockTokenBuilder.On("BuildAccessToken", mock.Anything, mock.Anything).
		Return(&model.TokenDTO{Token: "at"}, nil).Once()
	s.mockTokenBuilder.On("BuildIDToken", mock.Anything, mock.MatchedBy(
		func(c *tokenservice.IDTokenBuildContext) bool { return c.SessionID == "" && c.DeviceSecretHash == "" })).
		Return(&model.TokenDTO{Token: "idt"}, nil).Once()

	resp, errResp := s.authCodeHandler.HandleGrant(dpopCtx(nssoJKT), s.codeRequest(), s.superApp)

	s.Require().Nil(errResp)
	s.Empty(resp.DeviceSecret)
	s.mockDeviceSecret.AssertNotCalled(s.T(), "GenerateDeviceSecret", mock.Anything, mock.Anything)
}

func (s *NativeSSOTestSuite) TestAuthorizationCode_DeviceSSO_Rejections() {
	cases := []struct {
		name     string
		scopes   string
		app      func() *providers.OAuthClient
		provider bool
		ctx      context.Context
		wantErr  string
	}{
		{"client not registered for device_sso", "openid email device_sso", func() *providers.OAuthClient {
			app := *s.superApp
			app.Scopes = []string{"email"}
			return &app
		}, true, dpopCtx(nssoJKT), constants.ErrorInvalidScope},
		{"server without provider", "openid email device_sso", func() *providers.OAuthClient { return s.superApp },
			false, dpopCtx(nssoJKT), constants.ErrorInvalidScope},
		{"device_sso without openid", "email device_sso", func() *providers.OAuthClient { return s.superApp },
			true, dpopCtx(nssoJKT), constants.ErrorInvalidScope},
		{"no DPoP proof", "openid email device_sso", func() *providers.OAuthClient { return s.superApp },
			true, context.Background(), constants.ErrorInvalidDPoPProof},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			code := s.authCode(tc.scopes)
			if tc.ctx == context.Background() {
				code.DPoPJkt = ""
			}
			authzSvc := authzmock.NewAuthorizeServiceInterfaceMock(s.T())
			authzSvc.On("GetAuthorizationCodeDetails", mock.Anything, nssoSuperClientID, "code-1").
				Return(code, nil).Once()
			builder := tokenservicemock.NewTokenBuilderInterfaceMock(s.T())
			h := &authorizationCodeGrantHandler{authzService: authzSvc, tokenBuilder: builder,
				attributeCache: s.mockAttrCache, resourceService: s.mockResource}
			if tc.provider {
				h.deviceSecretProvider = s.mockDeviceSecret
			}

			resp, errResp := h.HandleGrant(tc.ctx, s.codeRequest(), tc.app())

			s.Nil(resp)
			s.assertError(errResp, tc.wantErr)
			builder.AssertNotCalled(s.T(), "BuildAccessToken", mock.Anything, mock.Anything)
		})
	}
}

func (s *NativeSSOTestSuite) TestAuthorizationCode_DeviceSSO_ProviderFailure() {
	s.mockAuthzService.On("GetAuthorizationCodeDetails", mock.Anything, nssoSuperClientID, "code-1").
		Return(s.authCode("openid email device_sso"), nil).Once()
	s.mockAttrCache.On("GetAttributeCache", mock.Anything, nssoCacheID).
		Return(&attributecache.AttributeCache{ID: nssoCacheID, Attributes: map[string]interface{}{}},
			(*tidcommon.ServiceError)(nil)).Once()
	s.mockTokenBuilder.On("BuildAccessToken", mock.Anything, mock.Anything).
		Return(&model.TokenDTO{Token: "at"}, nil).Once()
	s.mockDeviceSecret.On("GenerateDeviceSecret", mock.Anything, mock.Anything).
		Return(nil, errors.New("keystore unavailable")).Once()

	resp, errResp := s.authCodeHandler.HandleGrant(dpopCtx(nssoJKT), s.codeRequest(), s.superApp)

	s.Nil(resp)
	s.assertError(errResp, constants.ErrorServerError)
	s.mockTokenBuilder.AssertNotCalled(s.T(), "BuildIDToken", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------------------------------
// token exchange: request validation
// ---------------------------------------------------------------------------------------------------

func (s *NativeSSOTestSuite) TestValidateGrant_NativeSSO() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())

	s.Nil(s.tokenExchangeHandl.ValidateGrant(context.Background(), s.exchangeRequest(idToken, "openid email"),
		s.childApp))

	req := s.exchangeRequest(idToken, "openid email device_sso")
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidScope)

	req = s.exchangeRequest(idToken, "openid")
	req.SubjectTokenType = string(constants.TokenTypeIdentifierAccessToken)
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidRequest)

	req = s.exchangeRequest(idToken, "openid")
	req.SubjectTokenType = string(constants.TokenTypeIdentifierDeviceSecret)
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidRequest)

	req = s.exchangeRequest(idToken, "openid")
	req.RequestedTokenType = string(constants.TokenTypeIdentifierJWT)
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidRequest)

	req = s.exchangeRequest(idToken, "openid")
	req.ActorToken = ""
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidRequest)

	req = s.exchangeRequest("", "openid")
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidRequest)

	req = s.exchangeRequest(idToken, "openid")
	req.Resources = []string{"https://api.example.com"}
	s.assertError(s.tokenExchangeHandl.ValidateGrant(context.Background(), req, s.childApp),
		constants.ErrorInvalidTarget)
}

// ---------------------------------------------------------------------------------------------------
// token exchange: success paths
// ---------------------------------------------------------------------------------------------------

func (s *NativeSSOTestSuite) TestNativeSSO_Success() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.expectOriginalClientDeviceSSO()
	_, accessScopes := s.expectIssuance()

	resp, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
		s.exchangeRequest(idToken, "openid email"), s.childApp)

	s.Require().Nil(errResp)
	s.Equal("child-at", resp.AccessToken.Token)
	s.Equal("child-idt", resp.IDToken.Token)
	s.Empty(resp.DeviceSecret, "the device secret is not re-issued")
	s.Equal([]string{"openid", "email"}, *accessScopes)
}

func (s *NativeSSOTestSuite) TestNativeSSO_ScopeOmittedInheritsGrant() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.expectOriginalClientDeviceSSO()
	_, accessScopes := s.expectIssuance()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, ""), s.childApp)

	s.Require().Nil(errResp)
	s.Equal([]string{"openid", "email"}, *accessScopes)
}

func (s *NativeSSOTestSuite) TestNativeSSO_NarrowerScope() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.expectOriginalClientDeviceSSO()
	_, accessScopes := s.expectIssuance()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, "openid"),
		s.childApp)

	s.Require().Nil(errResp)
	s.Equal([]string{"openid"}, *accessScopes)
}

// ---------------------------------------------------------------------------------------------------
// token exchange: rejections
// ---------------------------------------------------------------------------------------------------

func (s *NativeSSOTestSuite) TestNativeSSO_ScopeBeyondGrantNeedsConsent() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.expectOriginalClientDeviceSSO()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
		s.exchangeRequest(idToken, "openid email profile"), s.childApp)

	s.assertError(errResp, constants.ErrorInteractionRequired)
	s.mockDeviceSecret.AssertNotCalled(s.T(), "MarkDeviceSecretUsed", mock.Anything, mock.Anything, mock.Anything)
	s.mockTokenBuilder.AssertNotCalled(s.T(), "BuildAccessToken", mock.Anything, mock.Anything)
}

func (s *NativeSSOTestSuite) TestNativeSSO_MissingDPoPProof() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())

	_, errResp := s.tokenExchangeHandl.HandleGrant(context.Background(),
		s.exchangeRequest(idToken, "openid"), s.childApp)

	s.assertError(errResp, constants.ErrorInvalidDPoPProof)
	s.mockDeviceSecret.AssertNotCalled(s.T(), "ValidateDeviceSecret", mock.Anything, mock.Anything, mock.Anything)
}

func (s *NativeSSOTestSuite) TestNativeSSO_DPoPKeyMismatch() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoOtherJKT),
		s.exchangeRequest(idToken, "openid"), s.childApp)

	s.assertError(errResp, constants.ErrorInvalidGrant)
	s.Contains(errResp.ErrorDescription, "DPoP")
}

func (s *NativeSSOTestSuite) TestNativeSSO_AudienceMustBeIssuer() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	for _, aud := range [][]string{nil, {"https://other.example.com"}, {nssoIssuer, "x"}} {
		req := s.exchangeRequest(idToken, "openid")
		req.Audiences = aud
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), req, s.childApp)
		s.assertError(errResp, constants.ErrorInvalidTarget)
	}
}

func (s *NativeSSOTestSuite) TestNativeSSO_DeviceSecretProviderErrors() {
	cases := []struct {
		err     error
		wantErr string
	}{
		{providers.ErrDeviceSecretExpired, constants.ErrorInvalidGrant},
		{providers.ErrDeviceSecretInvalid, constants.ErrorInvalidGrant},
		{providers.ErrDeviceSecretRevoked, constants.ErrorInvalidGrant},
		{providers.ErrDeviceSecretClientNotPermitted, constants.ErrorInvalidGrant},
		{errors.New("wrapped: " + providers.ErrDeviceSecretInvalid.Error()), constants.ErrorServerError},
		{errors.Join(errors.New("decrypt"), providers.ErrDeviceSecretInvalid), constants.ErrorInvalidGrant},
	}
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	for _, tc := range cases {
		s.Run(tc.err.Error(), func() {
			s.mockDeviceSecret.On("ValidateDeviceSecret", mock.Anything, nssoChildClientID, nssoDeviceSecret).
				Return(nil, tc.err).Once()
			_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
				s.exchangeRequest(idToken, "openid"), s.childApp)
			s.assertError(errResp, tc.wantErr)
		})
	}
}

func (s *NativeSSOTestSuite) TestNativeSSO_IncompleteDeviceSecretClaims() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	incomplete := *s.dsClaims
	incomplete.CnfJkt = ""
	s.mockDeviceSecret.On("ValidateDeviceSecret", mock.Anything, nssoChildClientID, nssoDeviceSecret).
		Return(&incomplete, nil).Once()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, "openid"),
		s.childApp)

	s.assertError(errResp, constants.ErrorInvalidGrant)
}

func (s *NativeSSOTestSuite) TestNativeSSO_IDTokenBindingFailures() {
	cases := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"wrong ds_hash", func(c map[string]interface{}) {
			c[constants.ClaimDeviceSecretHash] = computeDeviceSecretHash("another-secret")
		}},
		{"missing ds_hash", func(c map[string]interface{}) { delete(c, constants.ClaimDeviceSecretHash) }},
		{"wrong sid", func(c map[string]interface{}) { c[constants.ClaimSessionID] = "other-session" }},
		{"missing sid", func(c map[string]interface{}) { delete(c, constants.ClaimSessionID) }},
		{"wrong sub", func(c map[string]interface{}) { c["sub"] = "someone-else" }},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			claims := s.superIDTokenClaims()
			tc.mutate(claims)
			idToken := fakeIDToken("JWT", claims)
			s.expectValidDeviceSecret()
			s.expectValidIDTokenSignature(idToken)

			_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
				s.exchangeRequest(idToken, "openid"), s.childApp)

			s.assertError(errResp, constants.ErrorInvalidGrant)
		})
	}
}

func (s *NativeSSOTestSuite) TestNativeSSO_IDTokenValidationFailures() {
	s.Run("invalid signature or issuer", func() {
		idToken := fakeIDToken("JWT", s.superIDTokenClaims())
		s.expectValidDeviceSecret()
		s.mockJWTService.On("VerifyJWT", mock.Anything, idToken, nssoSuperClientID, nssoIssuer).
			Return(&tidcommon.ServiceError{Code: "JWT-1001"}).Once()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest(idToken, "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidGrant)
	})
	s.Run("expired", func() {
		claims := s.superIDTokenClaims()
		claims["exp"] = float64(time.Now().Add(-time.Minute).Unix())
		s.expectValidDeviceSecret()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest(fakeIDToken("JWT", claims), "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidGrant)
		s.Contains(errResp.ErrorDescription, "expired")
	})
	s.Run("encrypted (JWE) ID token", func() {
		s.expectValidDeviceSecret()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest("a.b.c.d.e", "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidRequest)
	})
	s.Run("access token presented as ID token", func() {
		s.expectValidDeviceSecret()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest(fakeIDToken("at+jwt", s.superIDTokenClaims()), "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidRequest)
	})
	s.Run("refresh token presented as ID token", func() {
		claims := s.superIDTokenClaims()
		claims["access_token_sub"] = testUserID
		s.expectValidDeviceSecret()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest(fakeIDToken("JWT", claims), "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidRequest)
	})
	s.Run("malformed", func() {
		s.expectValidDeviceSecret()
		_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
			s.exchangeRequest("!!.@@.##", "openid"), s.childApp)
		s.assertError(errResp, constants.ErrorInvalidRequest)
	})
}

func (s *NativeSSOTestSuite) TestNativeSSO_OriginalClientLostDeviceSSO() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	revoked := *s.superApp
	revoked.Scopes = []string{"email"}
	s.mockActorProvider.On("GetOAuthClientByClientID", mock.Anything, nssoSuperClientID).
		Return(&revoked, (*tidcommon.ServiceError)(nil)).Once()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, "openid"),
		s.childApp)

	s.assertError(errResp, constants.ErrorInvalidGrant)
}

func (s *NativeSSOTestSuite) TestNativeSSO_OriginalClientLookupServerError() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.mockActorProvider.On("GetOAuthClientByClientID", mock.Anything, nssoSuperClientID).
		Return(nil, &tidcommon.ServiceError{Type: tidcommon.ServerErrorType, Code: "X"}).Once()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, "openid"),
		s.childApp)

	s.assertError(errResp, constants.ErrorServerError)
}

func (s *NativeSSOTestSuite) TestNativeSSO_Replay() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()
	s.expectValidIDTokenSignature(idToken)
	s.expectOriginalClientDeviceSSO()
	s.mockDeviceSecret.On("MarkDeviceSecretUsed", mock.Anything, s.dsClaims, nssoChildClientID).
		Return(providers.ErrDeviceSecretReplayed).Once()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT), s.exchangeRequest(idToken, "openid"),
		s.childApp)

	s.assertError(errResp, constants.ErrorInvalidGrant)
	s.mockTokenBuilder.AssertNotCalled(s.T(), "BuildAccessToken", mock.Anything, mock.Anything)
}

func (s *NativeSSOTestSuite) TestNativeSSO_NotSupportedWithoutProvider() {
	h := *s.tokenExchangeHandl
	h.deviceSecretProvider = nil
	_, errResp := h.HandleGrant(dpopCtx(nssoJKT),
		s.exchangeRequest(fakeIDToken("JWT", s.superIDTokenClaims()), "openid"), s.childApp)
	s.assertError(errResp, constants.ErrorInvalidRequest)
}

func (s *NativeSSOTestSuite) TestNativeSSO_ErrorDescriptionsDoNotLeakSecrets() {
	idToken := fakeIDToken("JWT", s.superIDTokenClaims())
	s.expectValidDeviceSecret()

	_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoOtherJKT),
		s.exchangeRequest(idToken, "openid"), s.childApp)

	s.Require().NotNil(errResp)
	s.False(strings.Contains(errResp.ErrorDescription, nssoDeviceSecret))
	s.False(strings.Contains(errResp.ErrorDescription, nssoJKT))
	s.False(strings.Contains(errResp.ErrorDescription, idToken))
}

func (s *NativeSSOTestSuite) TestConsentedClaimNames() {
	claimsReq := &model.ClaimsRequest{
		UserInfo: map[string]*model.IndividualClaimRequest{"phone_number": nil},
		IDToken:  map[string]*model.IndividualClaimRequest{"birthdate": nil},
	}
	got := consentedClaimNames([]string{"openid", "email", constants.ScopeDeviceSSO}, claimsReq,
		map[string][]string{"email": {"email"}},
		map[string]interface{}{"email": "a@b.c", "gender": "x", providers.RawJWTAttributeKey: "jwt"})
	s.Equal([]string{"birthdate", "email", "gender", "phone_number", "sub"}, got)
}

// An opaque identity-system JWT cannot be filtered per scope, so a narrower second application must
// not inherit it; an identical scope set may.
func (s *NativeSSOTestSuite) TestNativeSSO_OpaqueAttributesOnlyForIdenticalScopes() {
	for _, tc := range []struct {
		scope   string
		wantACI string
	}{
		{"openid", ""},
		{"openid email", nssoCacheID},
	} {
		s.Run(tc.scope, func() {
			s.SetupTest()
			idToken := fakeIDToken("JWT", s.superIDTokenClaims())
			s.expectValidDeviceSecret()
			s.expectValidIDTokenSignature(idToken)
			s.expectOriginalClientDeviceSSO()
			s.mockDeviceSecret.On("MarkDeviceSecretUsed", mock.Anything, s.dsClaims, nssoChildClientID).
				Return(nil).Once()
			s.mockAttrCache.On("GetAttributeCache", mock.Anything, nssoCacheID).
				Return(&attributecache.AttributeCache{ID: nssoCacheID, Attributes: map[string]interface{}{
					providers.RawJWTAttributeKey: "kyc.jwt.sig"}}, (*tidcommon.ServiceError)(nil)).Once()
			var gotACI = "unset"
			s.mockTokenBuilder.On("BuildAccessToken", mock.Anything, mock.MatchedBy(
				func(c *tokenservice.AccessTokenBuildContext) bool { gotACI = c.AttributeCacheID; return true })).
				Return(&model.TokenDTO{Token: "at"}, nil).Once()
			s.mockTokenBuilder.On("BuildIDToken", mock.Anything, mock.Anything).
				Return(&model.TokenDTO{Token: "idt"}, nil).Once()

			_, errResp := s.tokenExchangeHandl.HandleGrant(dpopCtx(nssoJKT),
				s.exchangeRequest(idToken, tc.scope), s.childApp)

			s.Require().Nil(errResp)
			s.Equal(tc.wantACI, gotACI)
		})
	}
}
