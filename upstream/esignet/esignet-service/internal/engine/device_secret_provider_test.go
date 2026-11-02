/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/engine/runtimestores/inmemory"
	"github.com/mosip/esignet/internal/keymanager/cryptomanager"
	"github.com/mosip/esignet/internal/keymanager/signature"
)

const (
	dsTestIssuer  = "https://esignet.example.com"
	dsTestSuper   = "super-app"
	dsTestChild   = "child-app"
	dsTestJKT     = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	dsTestSubject = "8212412839"
	dsTestAuthID  = "auth-session-1"
)

// fakeDeviceSecretSigner signs and verifies with a real P-256 key (ES256), standing in for
// signature.Service so the provider's sign/verify contract is exercised with real cryptography.
type fakeDeviceSecretSigner struct {
	key       *ecdsa.PrivateKey
	verifyKey *ecdsa.PublicKey
	verifyErr error
}

func newFakeSigner() *fakeDeviceSecretSigner {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &fakeDeviceSecretSigner{key: k, verifyKey: &k.PublicKey}
}

func (f *fakeDeviceSecretSigner) JWSSign(_ context.Context, req signature.JWSSignRequest) (signature.JWSSignResponse, error) {
	if req.ApplicationID != config.OIDCServiceAppID || req.ReferenceID != DeviceSecretSignReferenceID {
		return signature.JWSSignResponse{}, errors.New("unexpected sign key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(req.DataToSign)
	if err != nil {
		return signature.JWSSignResponse{}, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key}, nil)
	if err != nil {
		return signature.JWSSignResponse{}, err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return signature.JWSSignResponse{}, err
	}
	compact, err := obj.CompactSerialize()
	return signature.JWSSignResponse{JWTSignedData: compact}, err
}

func (f *fakeDeviceSecretSigner) JWSVerify(_ context.Context, req signature.JWSVerifyRequest) (signature.JWSVerifyResponse, error) {
	if f.verifyErr != nil {
		return signature.JWSVerifyResponse{}, f.verifyErr
	}
	obj, err := jose.ParseSigned(req.JWTSignatureData, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return signature.JWSVerifyResponse{}, fmt.Errorf("%w: %w", signature.ErrMalformedJWS, err)
	}
	if _, err := obj.Verify(f.verifyKey); err != nil {
		return signature.JWSVerifyResponse{SignatureValid: false, Message: err.Error()}, nil
	}
	return signature.JWSVerifyResponse{SignatureValid: true}, nil
}

// fakeDeviceSecretEncrypter performs real RSA-OAEP-256 / A256GCM JWE like cryptomanager.Service and
// reports failures with cryptomanager's sentinel errors.
type fakeDeviceSecretEncrypter struct {
	key        *rsa.PrivateKey
	decryptErr error
}

func newFakeEncrypter() *fakeDeviceSecretEncrypter {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &fakeDeviceSecretEncrypter{key: k}
}

func (f *fakeDeviceSecretEncrypter) JWTEncrypt(_ context.Context, req cryptomanager.JWTEncryptRequest) (cryptomanager.JWTCipherResponse, error) {
	if req.ReferenceID != DeviceSecretEncryptReferenceID {
		return cryptomanager.JWTCipherResponse{}, errors.New("unexpected encryption key")
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &f.key.PublicKey},
		(&jose.EncrypterOptions{}).WithContentType("JWT"))
	if err != nil {
		return cryptomanager.JWTCipherResponse{}, err
	}
	obj, err := enc.Encrypt([]byte(req.Data))
	if err != nil {
		return cryptomanager.JWTCipherResponse{}, err
	}
	compact, err := obj.CompactSerialize()
	return cryptomanager.JWTCipherResponse{Data: compact}, err
}

func (f *fakeDeviceSecretEncrypter) JWTDecrypt(_ context.Context, req cryptomanager.JWTDecryptRequest) (cryptomanager.JWTCipherResponse, error) {
	if f.decryptErr != nil {
		return cryptomanager.JWTCipherResponse{}, f.decryptErr
	}
	obj, err := jose.ParseEncryptedCompact(req.EncData, []jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return cryptomanager.JWTCipherResponse{}, fmt.Errorf("%w: %w", cryptomanager.ErrJWEInvalidCompactSerialization, err)
	}
	plain, err := obj.Decrypt(f.key)
	if err != nil {
		return cryptomanager.JWTCipherResponse{}, fmt.Errorf("%w: %w", cryptomanager.ErrJWEDecryptFailed, err)
	}
	return cryptomanager.JWTCipherResponse{Data: base64.RawURLEncoding.EncodeToString(plain)}, nil
}

type fakeDeviceSecretClients map[string]clientmgmt.ClientResponse

func (f fakeDeviceSecretClients) GetActiveClient(_ context.Context, clientID string) (clientmgmt.ClientResponse, error) {
	c, ok := f[clientID]
	if !ok {
		return clientmgmt.ClientResponse{}, clientmgmt.ErrClientNotFound
	}
	return c, nil
}

type DeviceSecretProviderTestSuite struct {
	suite.Suite
	signer    *fakeDeviceSecretSigner
	encrypter *fakeDeviceSecretEncrypter
	clients   fakeDeviceSecretClients
	store     providers.RuntimeStoreProvider
	provider  *deviceSecretProvider
	now       time.Time
}

func TestDeviceSecretProviderTestSuite(t *testing.T) {
	suite.Run(t, new(DeviceSecretProviderTestSuite))
}

func (ts *DeviceSecretProviderTestSuite) SetupTest() {
	ts.signer = newFakeSigner()
	ts.encrypter = newFakeEncrypter()
	ts.clients = fakeDeviceSecretClients{
		dsTestSuper: {ClientID: dsTestSuper, RpID: "vendor-rp", AdditionalConfig: map[string]any{
			DeviceSSOAllowedClientsKey: []any{dsTestChild, "foreign-app"},
		}},
		dsTestChild:   {ClientID: dsTestChild, RpID: "vendor-rp"},
		"other-app":   {ClientID: "other-app", RpID: "vendor-rp"},
		"foreign-app": {ClientID: "foreign-app", RpID: "another-rp"},
	}
	ts.store = inmemory.Initialize("test")
	ts.now = time.Now()
	ts.provider = ts.newProvider(dsTestIssuer)
}

func (ts *DeviceSecretProviderTestSuite) newProvider(issuer string) *deviceSecretProvider {
	p := newDeviceSecretProvider(&config.AppConfig{Issuer: issuer, DeviceSecretExpirySecs: 3600},
		ts.signer, ts.encrypter, ts.clients, ts.store)
	p.now = func() time.Time { return ts.now }
	return p
}

func (ts *DeviceSecretProviderTestSuite) request() *providers.DeviceSecretRequest {
	return &providers.DeviceSecretRequest{
		Subject:          dsTestSubject,
		AuthID:           dsTestAuthID,
		ClientID:         dsTestSuper,
		Scopes:           []string{"openid", "email"},
		ACR:              "mosip:idp:acr:generated-code",
		Claims:           []string{"email", "name"},
		AuthTime:         ts.now.Unix(),
		CnfJkt:           dsTestJKT,
		AttributeCacheID: "acid-1",
	}
}

func (ts *DeviceSecretProviderTestSuite) generate() string {
	ds, err := ts.provider.GenerateDeviceSecret(context.Background(), ts.request())
	ts.Require().NoError(err)
	return ds.Value
}

// decryptPayload opens a device secret the way only esignet can, for asserting its claims.
func (ts *DeviceSecretProviderTestSuite) decryptPayload(value string) map[string]any {
	resp, err := ts.encrypter.JWTDecrypt(context.Background(), cryptomanager.JWTDecryptRequest{EncData: value})
	ts.Require().NoError(err)
	jws, _ := base64.RawURLEncoding.DecodeString(resp.Data)
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(string(jws), ".")[1])
	var claims map[string]any
	ts.Require().NoError(json.Unmarshal(payload, &claims))
	return claims
}

// craft signs and encrypts an arbitrary payload with the provider's keys.
func (ts *DeviceSecretProviderTestSuite) craft(payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	signed, err := ts.signer.JWSSign(context.Background(), signature.JWSSignRequest{
		ApplicationID: config.OIDCServiceAppID, ReferenceID: DeviceSecretSignReferenceID,
		DataToSign: base64.RawURLEncoding.EncodeToString(raw),
	})
	ts.Require().NoError(err)
	enc, err := ts.encrypter.JWTEncrypt(context.Background(), cryptomanager.JWTEncryptRequest{
		ReferenceID: DeviceSecretEncryptReferenceID, Data: signed.JWTSignedData,
	})
	ts.Require().NoError(err)
	return enc.Data
}

func (ts *DeviceSecretProviderTestSuite) TestGenerate_IsSignedThenEncryptedWithRequiredClaims() {
	ds, err := ts.provider.GenerateDeviceSecret(context.Background(), ts.request())
	ts.Require().NoError(err)

	ts.Equal(4, strings.Count(ds.Value, "."), "a compact JWE has five segments")
	ts.NotContains(ds.Value, dsTestSubject)
	ts.Equal(ts.now.Add(time.Hour).Unix(), ds.ExpiresAt)

	claims := ts.decryptPayload(ds.Value)
	ts.Equal(dsTestIssuer, claims["iss"])
	ts.Equal(dsTestIssuer, claims["aud"])
	ts.Equal(dsTestSubject, claims["sub"])
	ts.Equal(dsTestAuthID, claims["auth_id"])
	ts.Equal(dsTestSuper, claims["client_id"])
	ts.Equal("openid email", claims["scope"])
	ts.Equal("mosip:idp:acr:generated-code", claims["acr"])
	ts.Equal([]any{"email", "name"}, claims["claims"])
	ts.Equal(map[string]any{"jkt": dsTestJKT}, claims["cnf"])
	ts.Equal(float64(ds.ExpiresAt), claims["exp"])
	ts.NotEmpty(claims["jti"])
	ts.NotEmpty(claims["iat"])
}

func (ts *DeviceSecretProviderTestSuite) TestGenerate_RejectsIncompleteRequest() {
	for _, mutate := range []func(*providers.DeviceSecretRequest){
		func(r *providers.DeviceSecretRequest) { r.Subject = "" },
		func(r *providers.DeviceSecretRequest) { r.AuthID = "" },
		func(r *providers.DeviceSecretRequest) { r.ClientID = "" },
		func(r *providers.DeviceSecretRequest) { r.CnfJkt = "" },
	} {
		req := ts.request()
		mutate(req)
		_, err := ts.provider.GenerateDeviceSecret(context.Background(), req)
		ts.Error(err)
	}
	_, err := ts.provider.GenerateDeviceSecret(context.Background(), nil)
	ts.Error(err)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_RoundTripForPermittedChild() {
	value := ts.generate()

	claims, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)

	ts.Require().NoError(err)
	ts.Equal(dsTestSubject, claims.Subject)
	ts.Equal(dsTestAuthID, claims.AuthID)
	ts.Equal(dsTestSuper, claims.ClientID)
	ts.Equal([]string{"openid", "email"}, claims.Scopes)
	ts.Equal(dsTestJKT, claims.CnfJkt)
	ts.Equal("acid-1", claims.AttributeCacheID)
	ts.Equal(dsTestIssuer, claims.Issuer)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_OriginalClientMayRedeem() {
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestSuper, ts.generate())
	ts.NoError(err)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_UnlistedClientIsNotPermitted() {
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), "other-app", ts.generate())
	ts.ErrorIs(err, providers.ErrDeviceSecretClientNotPermitted)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_OriginalClientGone() {
	value := ts.generate()
	delete(ts.clients, dsTestSuper)
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.ErrorIs(err, providers.ErrDeviceSecretClientNotPermitted)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_Expired() {
	value := ts.generate()
	ts.now = ts.now.Add(time.Hour + time.Second)
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.ErrorIs(err, providers.ErrDeviceSecretExpired)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_RevokedSession() {
	value := ts.generate()
	ts.Require().NoError(ts.store.Delete(context.Background(), nativeSSOSessionNamespace, dsTestAuthID))
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.ErrorIs(err, providers.ErrDeviceSecretRevoked)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_SessionReboundToNewerSecret() {
	first := ts.generate()
	_ = ts.generate() // same auth_id re-issued: the session now belongs to the newer jti
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, first)
	ts.ErrorIs(err, providers.ErrDeviceSecretRevoked)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_MalformedInputs() {
	for _, value := range []string{"", "not-a-jwe", "a.b.c", "a.b.c.d.e", strings.Repeat("a.", 4) + strings.Repeat("x", 20000)} {
		_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
		ts.ErrorIs(err, providers.ErrDeviceSecretInvalid, "input %q", value[:min(len(value), 20)])
	}
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_TamperedCiphertext() {
	value := ts.generate()
	parts := strings.Split(value, ".")
	ct := []byte(parts[3])
	ct[0] ^= 0x01
	if ct[0] == '.' {
		ct[0] = 'A'
	}
	parts[3] = string(ct)
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, strings.Join(parts, "."))
	ts.ErrorIs(err, providers.ErrDeviceSecretInvalid)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_WrongSigningKey() {
	value := ts.generate()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts.signer.verifyKey = &other.PublicKey
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.ErrorIs(err, providers.ErrDeviceSecretInvalid)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_WrongIssuer() {
	value := ts.newProvider("https://attacker.example.com").mustGenerate(ts)
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.ErrorIs(err, providers.ErrDeviceSecretInvalid)
}

func (p *deviceSecretProvider) mustGenerate(ts *DeviceSecretProviderTestSuite) string {
	ds, err := p.GenerateDeviceSecret(context.Background(), ts.request())
	ts.Require().NoError(err)
	return ds.Value
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_MissingRequiredClaims() {
	base := func() map[string]any {
		return map[string]any{
			"iss": dsTestIssuer, "aud": dsTestIssuer, "sub": dsTestSubject, "jti": "j1",
			"iat": ts.now.Unix(), "nbf": ts.now.Unix(), "exp": ts.now.Add(time.Hour).Unix(),
			"auth_id": dsTestAuthID, "client_id": dsTestSuper, "scope": "openid email",
			"claims": []string{"email"}, "cnf": map[string]string{"jkt": dsTestJKT},
		}
	}
	for _, missing := range []string{"sub", "jti", "auth_id", "client_id", "cnf", "exp", "iat", "claims", "scope"} {
		payload := base()
		delete(payload, missing)
		_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, ts.craft(payload))
		ts.ErrorIs(err, providers.ErrDeviceSecretInvalid, "missing %s", missing)
	}

	payload := base()
	payload["iat"] = ts.now.Add(time.Hour).Unix()
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, ts.craft(payload))
	ts.ErrorIs(err, providers.ErrDeviceSecretInvalid, "issued in the future")
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_RejectsUnexpectedAlgorithm() {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + dsTestIssuer + `"}`))
	enc, err := ts.encrypter.JWTEncrypt(context.Background(), cryptomanager.JWTEncryptRequest{
		ReferenceID: DeviceSecretEncryptReferenceID, Data: header + "." + payload + ".",
	})
	ts.Require().NoError(err)
	_, err = ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, enc.Data)
	ts.ErrorIs(err, providers.ErrDeviceSecretInvalid)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_InfrastructureFailureIsNotInvalid() {
	value := ts.generate()
	ts.encrypter.decryptErr = errors.New("keystore unavailable")
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.Error(err)
	ts.False(errors.Is(err, providers.ErrDeviceSecretInvalid))

	ts.encrypter.decryptErr = nil
	ts.signer.verifyErr = errors.New("db down")
	_, err = ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, value)
	ts.Error(err)
	ts.False(errors.Is(err, providers.ErrDeviceSecretInvalid))
}

func (ts *DeviceSecretProviderTestSuite) TestMarkUsed_RecordsAndAllowsRepeatSignIn() {
	claims, err := ts.provider.ValidateDeviceSecret(context.Background(), dsTestChild, ts.generate())
	ts.Require().NoError(err)

	ts.NoError(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, dsTestChild))
	ts.NoError(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, dsTestChild),
		"a sibling app may sign in again while the device secret is valid")
	raw, err := ts.store.Get(context.Background(), nativeSSORedemptionNamespace, claims.JTI+"|"+dsTestChild)
	ts.Require().NoError(err)
	ts.Contains(string(raw), dsTestChild)
}

func (ts *DeviceSecretProviderTestSuite) TestValidate_ListedClientOfAnotherRelyingPartyIsNotPermitted() {
	ts.clients["foreign-app"] = clientmgmt.ClientResponse{ClientID: "foreign-app", RpID: "another-rp"}
	_, err := ts.provider.ValidateDeviceSecret(context.Background(), "foreign-app", ts.generate())
	ts.ErrorIs(err, providers.ErrDeviceSecretClientNotPermitted)
}

func (ts *DeviceSecretProviderTestSuite) TestMarkUsed_ExpiredOrIncomplete() {
	claims := &providers.DeviceSecretClaims{JTI: "j", ExpiresAt: ts.now.Add(-time.Second).Unix()}
	ts.ErrorIs(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, dsTestChild),
		providers.ErrDeviceSecretExpired)
	ts.Error(ts.provider.MarkDeviceSecretUsed(context.Background(), nil, dsTestChild))
	ts.Error(ts.provider.MarkDeviceSecretUsed(context.Background(), &providers.DeviceSecretClaims{JTI: "j"}, ""))
}

func (ts *DeviceSecretProviderTestSuite) TestDeviceSSOAllowedClients() {
	ts.Equal([]string{"a", "b"}, DeviceSSOAllowedClients(map[string]any{DeviceSSOAllowedClientsKey: []any{"a", 1, "b"}}))
	ts.Nil(DeviceSSOAllowedClients(map[string]any{}))
	ts.Nil(DeviceSSOAllowedClients(map[string]any{DeviceSSOAllowedClientsKey: "a"}))
}
