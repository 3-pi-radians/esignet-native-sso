// Command identity-stub is a LOCAL TEST DOUBLE for MOSIP's mock-identity-system (the "Identity
// Backend (MOSIP IDA / mock)" in the Native SSO sequence diagrams).
//
// It exists only so the Native SSO end-to-end test can run on a machine without Docker, where the
// official mosipdev/mock-identity-system image cannot run. It implements exactly the four HTTP
// endpoints eSignet's `mock` authn provider calls (internal/engine/mock), with the same request and
// response envelopes:
//
//	POST /v1/mock-identity-system/send-otp/{rpId}/{clientId}
//	POST /v1/mock-identity-system/v2/kyc-auth/{rpId}/{clientId}
//	POST /v1/mock-identity-system/v3/kyc-exchange/{rpId}/{clientId}
//	GET  /v1/mock-identity-system/keys.json
//
// Nothing in eSignet or ThunderID is stubbed: authentication flows, consent, PAR, DPoP, token
// issuance, device secrets and token exchange all run for real against it. With Docker available,
// use the official image instead (see docker-compose in this directory).
//
// Test identity (synthetic, not real PII): individualId 8267411571, OTP 111111.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const basePath = "/v1/mock-identity-system"

type identity struct {
	OTP    string
	Claims map[string]any
}

var identities = map[string]identity{
	"8267411571": {OTP: "111111", Claims: map[string]any{
		"name":           "Asha Demo",
		"email":          "asha.demo@example.com",
		"phone_number":   "+910000000000",
		"gender":         "female",
		"birthdate":      "1990/01/01",
		"email_verified": true,
	}},
}

type authState struct {
	individualID string
	psut         string
}

type server struct {
	key   *rsa.PrivateKey
	cert  []byte
	kid   string
	mu    sync.Mutex
	kycTk map[string]authState
}

type envelope struct {
	ID           string `json:"id,omitempty"`
	Version      string `json:"version,omitempty"`
	ResponseTime string `json:"responseTime,omitempty"`
	Response     any    `json:"response,omitempty"`
	Errors       []any  `json:"errors"`
}

func main() {
	addr := os.Getenv("IDENTITY_STUB_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8082"
	}
	s, err := newServer()
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+basePath+"/send-otp/{rp}/{client}", s.sendOTP)
	mux.HandleFunc("POST "+basePath+"/v2/kyc-auth/{rp}/{client}", s.kycAuth)
	mux.HandleFunc("POST "+basePath+"/v3/kyc-exchange/{rp}/{client}", s.kycExchange)
	mux.HandleFunc("GET "+basePath+"/keys.json", s.keys)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("identity-stub (test double for mock-identity-system) listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newServer() (*server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "identity-stub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &server{key: key, cert: der, kid: base64.RawURLEncoding.EncodeToString(sum[:]),
		kycTk: map[string]authState{}}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code, msg string) {
	writeJSON(w, envelope{Errors: []any{map[string]string{"errorCode": code, "message": msg}}})
}

func (s *server) sendOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID string `json:"transactionId"`
		IndividualID  string `json:"individualId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, "invalid_request", "bad json")
		return
	}
	if _, ok := identities[req.IndividualID]; !ok {
		fail(w, "invalid_individual_id", "unknown individual")
		return
	}
	writeJSON(w, envelope{Response: map[string]string{
		"transactionId": req.TransactionID, "maskedEmail": "as***@example.com", "maskedMobile": "******0000",
	}})
}

func (s *server) kycAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID string `json:"transactionId"`
		IndividualID  string `json:"individualId"`
		OTP           string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, "invalid_request", "bad json")
		return
	}
	id, ok := identities[req.IndividualID]
	if !ok || req.OTP == "" || req.OTP != id.OTP {
		writeJSON(w, envelope{Response: map[string]any{"authStatus": false},
			Errors: []any{map[string]string{"errorCode": "auth_failed", "message": "authentication failed"}}})
		return
	}
	kycToken := randomToken()
	// Partner-specific user token: stable per (individual, relying party), like IDA's PSUT.
	psutSum := sha256.Sum256([]byte(req.IndividualID + "|" + r.PathValue("rp")))
	psut := base64.RawURLEncoding.EncodeToString(psutSum[:])
	s.mu.Lock()
	s.kycTk[kycToken] = authState{individualID: req.IndividualID, psut: psut}
	s.mu.Unlock()
	writeJSON(w, envelope{Response: map[string]any{
		"authStatus": true, "kycToken": kycToken, "partnerSpecificUserToken": psut,
	}})
}

func (s *server) kycExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KycToken       string   `json:"kycToken"`
		IndividualID   string   `json:"individualId"`
		AcceptedClaims []string `json:"acceptedClaims"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, "invalid_request", "bad json")
		return
	}
	s.mu.Lock()
	st, ok := s.kycTk[req.KycToken]
	delete(s.kycTk, req.KycToken)
	s.mu.Unlock()
	if !ok || st.individualID != req.IndividualID {
		fail(w, "invalid_transaction", "unknown kyc token")
		return
	}
	claims := map[string]any{
		"sub": st.psut,
		"iss": "identity-stub",
		"aud": r.PathValue("client"),
		"iat": time.Now().Unix(),
	}
	for _, c := range req.AcceptedClaims {
		if v, ok := identities[st.individualID].Claims[c]; ok {
			claims[c] = v
		}
	}
	jwt, err := s.signRS256(claims)
	if err != nil {
		fail(w, "unknown_error", "sign failed")
		return
	}
	writeJSON(w, envelope{Response: map[string]string{"kyc": jwt}})
}

func (s *server) keys(w http.ResponseWriter, _ *http.Request) {
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert}))
	writeJSON(w, map[string]any{"response": map[string]any{"allCertificates": []map[string]string{
		{"keyId": s.kid, "certificateData": pemCert},
	}}})
}

func (s *server) signRS256(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}
