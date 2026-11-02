/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/keymanager"
	"github.com/mosip/esignet/internal/keymanager/cryptomanager"
	"github.com/mosip/esignet/internal/keymanager/signature"
	applog "github.com/mosip/esignet/internal/log"
)

const (
	// DeviceSecretSignReferenceID is the keymanager reference id whose EC P-256 key signs device
	// secrets (ES256). It is esignet's own sign key, provisioned at startup.
	DeviceSecretSignReferenceID = keymanager.RefIDECSECP256R1Sign

	// DeviceSecretEncryptReferenceID is the keymanager reference id of the RSA component encryption
	// key device secrets are encrypted to (RSA-OAEP-256 / A256GCM). The key is provisioned on first use
	// and never leaves the keymanager.
	DeviceSecretEncryptReferenceID = "DEVICE_SECRET_ENC"

	// DeviceSSOAllowedClientsKey is the client additional_config key on the client that obtains the
	// device secret (the Super App) listing the client ids allowed to redeem it (the Child Apps).
	DeviceSSOAllowedClientsKey = "device_sso_allowed_clients"

	deviceSecretSignAlgorithm = "ES256"
	// deviceSecretMaxLength rejects absurd inputs before any cryptographic work.
	deviceSecretMaxLength = 16 * 1024
	// deviceSecretClockSkewSecs tolerates small clock drift on iat/nbf.
	deviceSecretClockSkewSecs = 30

	nativeSSOSessionNamespace    providers.RuntimeStoreNamespace = "nativesso:session"
	nativeSSORedemptionNamespace providers.RuntimeStoreNamespace = "nativesso:redemption"
)

// deviceSecretSigner is the subset of signature.Service the provider uses.
type deviceSecretSigner interface {
	JWSSign(ctx context.Context, req signature.JWSSignRequest) (signature.JWSSignResponse, error)
	JWSVerify(ctx context.Context, req signature.JWSVerifyRequest) (signature.JWSVerifyResponse, error)
}

// deviceSecretEncrypter is the subset of cryptomanager.Service the provider uses.
type deviceSecretEncrypter interface {
	JWTEncrypt(ctx context.Context, req cryptomanager.JWTEncryptRequest) (cryptomanager.JWTCipherResponse, error)
	JWTDecrypt(ctx context.Context, req cryptomanager.JWTDecryptRequest) (cryptomanager.JWTCipherResponse, error)
}

// deviceSecretClientLookup is the subset of clientmgmt.Service the provider uses.
type deviceSecretClientLookup interface {
	GetActiveClient(ctx context.Context, clientID string) (clientmgmt.ClientResponse, error)
}

// deviceSecretPayload is the JWT claim set of a device secret. It is signed (ES256) and then
// encrypted (RSA-OAEP-256 + A256GCM), so its content, including cnf.jkt and the attribute cache
// reference, stays opaque to clients.
type deviceSecretPayload struct {
	Issuer           string            `json:"iss"`
	Audience         string            `json:"aud"`
	Subject          string            `json:"sub"`
	JTI              string            `json:"jti"`
	IssuedAt         int64             `json:"iat"`
	NotBefore        int64             `json:"nbf"`
	ExpiresAt        int64             `json:"exp"`
	AuthID           string            `json:"auth_id"`
	ClientID         string            `json:"client_id"`
	Scope            string            `json:"scope"`
	ACR              string            `json:"acr,omitempty"`
	Claims           []string          `json:"claims"`
	AuthTime         int64             `json:"auth_time,omitempty"`
	Confirmation     *deviceSecretConf `json:"cnf"`
	AttributeCacheID string            `json:"acid,omitempty"`
}

type deviceSecretConf struct {
	JKT string `json:"jkt"`
}

// nativeSSOSession is the server-side record of an authentication session that minted a device
// secret, keyed by auth_id (the ID token's sid). Validation requires it, so deleting the record from
// the runtime store revokes the session's device secret. No logout hook deletes it in this version;
// it otherwise expires with the device secret.
type nativeSSOSession struct {
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	JTI      string `json:"jti"`
}

type deviceSecretProvider struct {
	issuer    string
	expiry    time.Duration
	signer    deviceSecretSigner
	encrypter deviceSecretEncrypter
	clients   deviceSecretClientLookup
	store     providers.RuntimeStoreProvider
	now       func() time.Time
}

// NewDeviceSecretProvider returns esignet's OpenID Connect Native SSO device secret provider. Device
// secrets are signed with esignet's EC sign key and encrypted to a dedicated keymanager encryption
// key, so only esignet can read or mint them. Session and redemption state live in the runtime store.
func NewDeviceSecretProvider(cfg *config.AppConfig, sigSvc *signature.Service, cryptoSvc *cryptomanager.Service,
	clientSvc *clientmgmt.Service, store providers.RuntimeStoreProvider) providers.DeviceSecretProvider {
	return newDeviceSecretProvider(cfg, sigSvc, cryptoSvc, clientSvc, store)
}

func newDeviceSecretProvider(cfg *config.AppConfig, signer deviceSecretSigner, encrypter deviceSecretEncrypter,
	clients deviceSecretClientLookup, store providers.RuntimeStoreProvider) *deviceSecretProvider {
	return &deviceSecretProvider{
		issuer:    cfg.Issuer,
		expiry:    time.Duration(cfg.DeviceSecretExpirySecs) * time.Second,
		signer:    signer,
		encrypter: encrypter,
		clients:   clients,
		store:     store,
		now:       time.Now,
	}
}

// GenerateDeviceSecret signs then encrypts a device secret for req and records its session.
func (p *deviceSecretProvider) GenerateDeviceSecret(ctx context.Context, req *providers.DeviceSecretRequest) (
	*providers.DeviceSecret, error) {
	if req == nil || req.Subject == "" || req.AuthID == "" || req.ClientID == "" || req.CnfJkt == "" {
		return nil, errors.New("device secret request is missing required fields")
	}
	if p.expiry <= 0 {
		return nil, errors.New("device secret expiry is not configured")
	}

	now := p.now().UTC()
	exp := now.Add(p.expiry)
	claims := req.Claims
	if claims == nil {
		claims = []string{}
	}
	payload := deviceSecretPayload{
		Issuer:           p.issuer,
		Audience:         p.issuer,
		Subject:          req.Subject,
		JTI:              uuid.NewString(),
		IssuedAt:         now.Unix(),
		NotBefore:        now.Unix(),
		ExpiresAt:        exp.Unix(),
		AuthID:           req.AuthID,
		ClientID:         req.ClientID,
		Scope:            strings.Join(req.Scopes, " "),
		ACR:              req.ACR,
		Claims:           claims,
		AuthTime:         req.AuthTime,
		Confirmation:     &deviceSecretConf{JKT: req.CnfJkt},
		AttributeCacheID: req.AttributeCacheID,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal device secret: %w", err)
	}

	includeCert := false
	signed, err := p.signer.JWSSign(ctx, signature.JWSSignRequest{
		ApplicationID:      config.OIDCServiceAppID,
		ReferenceID:        DeviceSecretSignReferenceID,
		DataToSign:         base64.RawURLEncoding.EncodeToString(raw),
		IncludeCertificate: &includeCert,
		IncludeKeyID:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("sign device secret: %w", err)
	}

	noCompression := false
	encrypted, err := p.encrypter.JWTEncrypt(ctx, cryptomanager.JWTEncryptRequest{
		ApplicationID:            config.OIDCServiceAppID,
		ReferenceID:              DeviceSecretEncryptReferenceID,
		Data:                     signed.JWTSignedData,
		EnableDeflateCompression: &noCompression,
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt device secret: %w", err)
	}

	session, err := json.Marshal(nativeSSOSession{Subject: req.Subject, ClientID: req.ClientID, JTI: payload.JTI})
	if err != nil {
		return nil, fmt.Errorf("marshal native sso session: %w", err)
	}
	if err := p.store.Put(ctx, nativeSSOSessionNamespace, req.AuthID, session, int64(p.expiry.Seconds())); err != nil {
		return nil, fmt.Errorf("record native sso session: %w", err)
	}

	applog.GetLogger().Debug(ctx, "Device secret issued",
		applog.String("clientId", req.ClientID), applog.String("jti", payload.JTI))
	return &providers.DeviceSecret{Value: encrypted.Data, ExpiresAt: exp.Unix()}, nil
}

// ValidateDeviceSecret decrypts and verifies deviceSecret, checks its claims, its session and that
// requestingClientID may redeem it.
func (p *deviceSecretProvider) ValidateDeviceSecret(ctx context.Context, requestingClientID, deviceSecret string) (
	*providers.DeviceSecretClaims, error) {
	if deviceSecret == "" || len(deviceSecret) > deviceSecretMaxLength || strings.Count(deviceSecret, ".") != 4 {
		return nil, providers.ErrDeviceSecretInvalid
	}

	decrypted, err := p.encrypter.JWTDecrypt(ctx, cryptomanager.JWTDecryptRequest{
		ApplicationID: config.OIDCServiceAppID,
		ReferenceID:   DeviceSecretEncryptReferenceID,
		EncData:       deviceSecret,
	})
	if err != nil {
		if isInvalidCiphertext(err) {
			return nil, fmt.Errorf("%w: decrypt", providers.ErrDeviceSecretInvalid)
		}
		return nil, fmt.Errorf("decrypt device secret: %w", err)
	}
	jwsBytes, err := base64.RawURLEncoding.DecodeString(decrypted.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", providers.ErrDeviceSecretInvalid)
	}
	jws := string(jwsBytes)

	payload, err := p.verifySignedPayload(ctx, jws)
	if err != nil {
		return nil, err
	}
	if err := p.checkClaims(payload); err != nil {
		return nil, err
	}
	if err := p.checkSession(ctx, payload); err != nil {
		return nil, err
	}
	if err := p.checkClientPermitted(ctx, payload.ClientID, requestingClientID); err != nil {
		return nil, err
	}

	return &providers.DeviceSecretClaims{
		JTI:              payload.JTI,
		Issuer:           payload.Issuer,
		Subject:          payload.Subject,
		AuthID:           payload.AuthID,
		ClientID:         payload.ClientID,
		Scopes:           strings.Fields(payload.Scope),
		ACR:              payload.ACR,
		Claims:           payload.Claims,
		AuthTime:         payload.AuthTime,
		CnfJkt:           payload.Confirmation.JKT,
		AttributeCacheID: payload.AttributeCacheID,
		IssuedAt:         payload.IssuedAt,
		ExpiresAt:        payload.ExpiresAt,
	}, nil
}

// MarkDeviceSecretUsed records that requestingClientID redeemed the device secret (last use, for
// audit and operations). It never refuses a redemption: a sibling app may sign in again for as long
// as the device secret and its session are valid, e.g. after signing out or when its own tokens
// expire. Replaying a captured exchange request is already prevented by the single-use jti of the
// DPoP proof and of the private_key_jwt client assertion, and by the proof's key binding.
func (p *deviceSecretProvider) MarkDeviceSecretUsed(ctx context.Context, claims *providers.DeviceSecretClaims,
	requestingClientID string) error {
	if claims == nil || claims.JTI == "" || requestingClientID == "" {
		return errors.New("device secret redemption is missing required fields")
	}
	ttl := claims.ExpiresAt - p.now().Unix()
	if ttl <= 0 {
		return providers.ErrDeviceSecretExpired
	}
	record, err := json.Marshal(map[string]any{"client_id": requestingClientID, "last_used": p.now().Unix()})
	if err != nil {
		return fmt.Errorf("marshal device secret redemption: %w", err)
	}
	if err := p.store.Put(ctx, nativeSSORedemptionNamespace, claims.JTI+"|"+requestingClientID, record, ttl); err != nil {
		return fmt.Errorf("record device secret redemption: %w", err)
	}
	return nil
}

// verifySignedPayload checks the inner JWS uses the expected explicit algorithm, verifies it against
// esignet's own sign key (never a certificate embedded in the token) and decodes its claims.
func (p *deviceSecretProvider) verifySignedPayload(ctx context.Context, jws string) (*deviceSecretPayload, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", providers.ErrDeviceSecretInvalid)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", providers.ErrDeviceSecretInvalid)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != deviceSecretSignAlgorithm {
		return nil, fmt.Errorf("%w: unexpected signing algorithm", providers.ErrDeviceSecretInvalid)
	}

	verified, err := p.signer.JWSVerify(ctx, signature.JWSVerifyRequest{
		JWTSignatureData: jws,
		ApplicationID:    config.OIDCServiceAppID,
		ReferenceID:      DeviceSecretSignReferenceID,
	})
	if err != nil {
		if errors.Is(err, signature.ErrMalformedJWS) || errors.Is(err, signature.ErrBlankSignatureData) {
			return nil, fmt.Errorf("%w: malformed signature", providers.ErrDeviceSecretInvalid)
		}
		return nil, fmt.Errorf("verify device secret: %w", err)
	}
	if !verified.SignatureValid {
		return nil, fmt.Errorf("%w: signature", providers.ErrDeviceSecretInvalid)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", providers.ErrDeviceSecretInvalid)
	}
	var payload deviceSecretPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("%w: payload", providers.ErrDeviceSecretInvalid)
	}
	return &payload, nil
}

func (p *deviceSecretProvider) checkClaims(payload *deviceSecretPayload) error {
	if payload.Issuer != p.issuer || payload.Audience != p.issuer {
		return fmt.Errorf("%w: issuer", providers.ErrDeviceSecretInvalid)
	}
	if payload.Subject == "" || payload.JTI == "" || payload.AuthID == "" || payload.ClientID == "" ||
		payload.Confirmation == nil || payload.Confirmation.JKT == "" || payload.ExpiresAt == 0 ||
		payload.IssuedAt == 0 || payload.Claims == nil || !slices.Contains(strings.Fields(payload.Scope), "openid") {
		return fmt.Errorf("%w: missing required claims", providers.ErrDeviceSecretInvalid)
	}
	now := p.now().Unix()
	if payload.IssuedAt > now+deviceSecretClockSkewSecs || payload.NotBefore > now+deviceSecretClockSkewSecs {
		return fmt.Errorf("%w: not yet valid", providers.ErrDeviceSecretInvalid)
	}
	if now >= payload.ExpiresAt {
		return providers.ErrDeviceSecretExpired
	}
	return nil
}

// checkSession confirms the authentication session (sid / auth_id) that minted the device secret is
// still active and still belongs to this device secret.
func (p *deviceSecretProvider) checkSession(ctx context.Context, payload *deviceSecretPayload) error {
	raw, err := p.store.Get(ctx, nativeSSOSessionNamespace, payload.AuthID)
	if err != nil {
		if errors.Is(err, providers.ErrRuntimeStoreKeyNotFound) {
			return providers.ErrDeviceSecretRevoked
		}
		return fmt.Errorf("load native sso session: %w", err)
	}
	if raw == nil {
		return providers.ErrDeviceSecretRevoked
	}
	var session nativeSSOSession
	if err := json.Unmarshal(raw, &session); err != nil {
		return fmt.Errorf("decode native sso session: %w", err)
	}
	if session.JTI != payload.JTI || session.Subject != payload.Subject || session.ClientID != payload.ClientID {
		return providers.ErrDeviceSecretRevoked
	}
	return nil
}

// checkClientPermitted allows the original client itself, or a client listed in the original
// client's device_sso_allowed_clients additional_config that belongs to the same relying party. The
// same-relying-party rule matters because subjects are pairwise per relying party: tokens issued
// through Native SSO carry the original login's subject, which must not cross relying parties.
func (p *deviceSecretProvider) checkClientPermitted(ctx context.Context, originalClientID, requestingClientID string) error {
	if requestingClientID == "" {
		return providers.ErrDeviceSecretClientNotPermitted
	}
	original, err := p.clients.GetActiveClient(ctx, originalClientID)
	if err != nil {
		if errors.Is(err, clientmgmt.ErrClientNotFound) {
			return providers.ErrDeviceSecretClientNotPermitted
		}
		return fmt.Errorf("load device secret client: %w", err)
	}
	if requestingClientID == originalClientID {
		return nil
	}
	if !slices.Contains(DeviceSSOAllowedClients(original.AdditionalConfig), requestingClientID) {
		return providers.ErrDeviceSecretClientNotPermitted
	}
	requesting, err := p.clients.GetActiveClient(ctx, requestingClientID)
	if err != nil {
		if errors.Is(err, clientmgmt.ErrClientNotFound) {
			return providers.ErrDeviceSecretClientNotPermitted
		}
		return fmt.Errorf("load requesting client: %w", err)
	}
	if requesting.RpID == "" || requesting.RpID != original.RpID {
		return providers.ErrDeviceSecretClientNotPermitted
	}
	return nil
}

// DeviceSSOAllowedClients extracts DeviceSSOAllowedClientsKey from a client's additional_config.
func DeviceSSOAllowedClients(additionalConfig map[string]any) []string {
	v, ok := additionalConfig[DeviceSSOAllowedClientsKey].([]any)
	if !ok {
		return nil
	}
	clients := make([]string, 0, len(v))
	for _, item := range v {
		if s, ok := item.(string); ok {
			clients = append(clients, s)
		}
	}
	return clients
}

// isInvalidCiphertext reports whether a JWTDecrypt error means the presented device secret is bad
// (not ours, tampered, malformed) rather than an infrastructure failure.
func isInvalidCiphertext(err error) bool {
	for _, target := range []error{
		cryptomanager.ErrJWEInvalidCompactSerialization,
		cryptomanager.ErrJWEDecryptFailed,
		cryptomanager.ErrKeyNotFoundForThumbprint,
		cryptomanager.ErrKeyIdentifierMismatch,
		cryptomanager.ErrDecryptionNotAllowed,
		cryptomanager.ErrForeignDomainKeyNotDecryptable,
		cryptomanager.ErrInvalidRequest,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
