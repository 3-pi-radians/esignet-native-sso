// Command nativesso is a live end-to-end check of OpenID Connect Native SSO against a running eSignet.
//
// It registers throwaway clients, signs a user in to a "Super App" with PAR + PKCE + DPoP + OTP and
// the device_sso scope, then signs "Child Apps" in silently with the RFC 8693 token exchange
// (subject_token = id_token, actor_token = device_secret), and runs the negative cases the
// hackathon problem statement requires. Every request goes over HTTP to the real deployment.
//
// Environment:
//
//	ESIGNET_BASE_URL  eSignet base URL                 (default http://localhost:8088)
//	ADMIN_TOKEN       bearer for /client-mgmt/client   (default local-no-scope; scope enforcement off)
//	INDIVIDUAL_ID     test identity                    (default 8267411571)
//	OTP               OTP for that identity            (default 111111)
//	ESIGNET_LOG       optional eSignet log file to scan for leaked secrets
//	RESULTS_JSON      optional path to write the results as JSON
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mosip/esignet/api-test/internal/esignet"
)

const (
	redirectURI            = "https://native-sso.example.org/callback"
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeDeviceSecret  = "urn:openid:params:token-type:device-secret"
	clientAssertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	acrOTP                 = "mosip:idp:acr:generated-code"
)

type discovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	PAREndpoint   string `json:"pushed_authorization_request_endpoint"`
	UserInfo      string `json:"userinfo_endpoint"`
}

type harness struct {
	base, admin, individualID, otp, runID string
	d                                     discovery
	http                                  *http.Client
	results                               []result
}

type result struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type client struct {
	id  string
	key *rsa.PrivateKey
	kid string
}

type tokenResponse struct {
	Status          int    `json:"-"`
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	IDToken         string `json:"id_token"`
	DeviceSecret    string `json:"device_secret"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

func main() {
	h := &harness{
		base:         env("ESIGNET_BASE_URL", "http://localhost:8088"),
		admin:        env("ADMIN_TOKEN", "local-no-scope"),
		individualID: env("INDIVIDUAL_ID", "8267411571"),
		otp:          env("OTP", "111111"),
		runID:        fmt.Sprintf("%d", time.Now().Unix()),
		http:         &http.Client{Timeout: 30 * time.Second},
	}
	if err := h.run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		h.write()
		os.Exit(2)
	}
	if !h.write() {
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (h *harness) check(name string, ok bool, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	h.results = append(h.results, result{Name: name, Passed: ok, Detail: detail})
	mark := "PASS"
	if !ok {
		mark = "FAIL"
	}
	fmt.Printf("[%s] %s: %s\n", mark, name, detail)
}

func (h *harness) write() bool {
	passed := 0
	for _, r := range h.results {
		if r.Passed {
			passed++
		}
	}
	fmt.Printf("\n%d/%d checks passed\n", passed, len(h.results))
	if p := os.Getenv("RESULTS_JSON"); p != "" {
		b, _ := json.MarshalIndent(map[string]any{"run": h.runID, "base": h.base, "passed": passed,
			"total": len(h.results), "results": h.results}, "", "  ")
		_ = os.WriteFile(p, b, 0o600)
	}
	return passed == len(h.results)
}

func (h *harness) run(ctx context.Context) error {
	if err := h.getJSON(ctx, h.base+"/.well-known/openid-configuration", &h.d); err != nil {
		return fmt.Errorf("discovery: %w", err)
	}

	child := h.newClient("nsso-child")
	child2 := h.newClient("nsso-child2")
	rogue := h.newClient("nsso-rogue")
	super := h.newClient("nsso-super")
	plain := h.newClient("nsso-plain")
	foreign := h.newClient("nsso-foreign")
	nativeCfg := func(extra map[string]any) map[string]any {
		ac := map[string]any{
			"require_pushed_authorization_requests": true,
			"dpop_bound_access_tokens":              true,
			"require_pkce":                          true,
		}
		for k, v := range extra {
			ac[k] = v
		}
		return ac
	}
	for _, reg := range []struct {
		c      *client
		grants []string
		ac     map[string]any
	}{
		{super, []string{"authorization_code", grantTokenExchange}, nativeCfg(map[string]any{
			"allowed_authorization_scopes": []string{"device_sso"},
			"device_sso_allowed_clients":   []string{child.id, child2.id, foreign.id},
		})},
		{child, []string{"authorization_code", grantTokenExchange}, nativeCfg(nil)},
		{child2, []string{"authorization_code", grantTokenExchange}, nativeCfg(nil)},
		{rogue, []string{"authorization_code", grantTokenExchange}, nativeCfg(nil)},
		{plain, []string{"authorization_code"}, nativeCfg(nil)},
		{foreign, []string{"authorization_code", grantTokenExchange}, nativeCfg(nil)},
	} {
		rp := "native-sso-rp"
		if reg.c == foreign {
			rp = "another-vendor-rp"
		}
		if err := h.register(ctx, reg.c, reg.grants, reg.ac, rp); err != nil {
			return fmt.Errorf("register %s: %w", reg.c.id, err)
		}
	}
	h.check("client registration", true, "registered super, child, child2, rogue, plain, foreign (token-exchange grant and device_sso_allowed_clients accepted)")

	keyA := newDPoPKey()
	keyB := newDPoPKey()

	// Task 1: device_sso only for registered clients.
	parStatus, parBody := h.par(ctx, plain, "openid email device_sso", keyA)
	h.check("PAR: device_sso refused for a client not registered for it", parStatus == 400 && jsonErr(parBody) == "invalid_scope",
		"HTTP %d error=%s", parStatus, jsonErr(parBody))

	// Ordinary login is unchanged.
	ordinary := h.login(ctx, plain, "openid email", keyA)
	idc := claimsOf(ordinary.IDToken)
	h.check("ordinary authorization_code login unchanged", ordinary.Status == 200 && ordinary.AccessToken != "" &&
		ordinary.DeviceSecret == "" && idc["sid"] == nil && idc["ds_hash"] == nil,
		"HTTP %d device_secret=%t sid=%v ds_hash=%v", ordinary.Status, ordinary.DeviceSecret != "", idc["sid"] != nil, idc["ds_hash"] != nil)

	// Super App login with device_sso.
	sup := h.login(ctx, super, "openid email device_sso", keyA)
	if sup.Status != 200 {
		return fmt.Errorf("super app login failed: HTTP %d %s %s", sup.Status, sup.Error, sup.ErrorDesc)
	}
	sidc := claimsOf(sup.IDToken)
	atc := claimsOf(sup.AccessToken)
	h.check("super app: device_secret returned", strings.Count(sup.DeviceSecret, ".") == 4,
		"device_secret is a compact JWE (%d segments)", strings.Count(sup.DeviceSecret, ".")+1)
	h.check("super app: access_token, id_token, DPoP token type", sup.AccessToken != "" && sup.IDToken != "" &&
		strings.EqualFold(sup.TokenType, "DPoP"), "token_type=%s", sup.TokenType)
	h.check("super app: id_token carries sid", sidc["sid"] != nil && sidc["sid"] != "", "sid present=%t", sidc["sid"] != nil)
	h.check("super app: ds_hash = BASE64URL(SHA-256(device_secret))", sidc["ds_hash"] == b64sha256(sup.DeviceSecret),
		"match=%t", sidc["ds_hash"] == b64sha256(sup.DeviceSecret))
	h.check("super app: access_token bound to DPoP key A", cnfJKT(atc) == keyA.jkt, "cnf.jkt matches=%t", cnfJKT(atc) == keyA.jkt)
	st, _ := h.userinfo(ctx, sup.AccessToken, keyA)
	h.check("super app: userinfo with DPoP", st == 200, "HTTP %d", st)

	// Negative token exchanges (run before the child's first success so redemption is unaffected).
	ex := func(c *client, idToken, ds, scope string, key *dpopKey, mutate func(url.Values)) tokenResponse {
		return h.exchange(ctx, c, idToken, ds, scope, key, mutate)
	}
	r := ex(child, sup.IDToken, sup.DeviceSecret, "openid email device_sso", keyA, nil)
	h.check("exchange: device_sso in scope rejected", r.Error == "invalid_scope", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email phone", keyA, nil)
	h.check("exchange: scope beyond original grant needs consent", r.Error == "interaction_required", "HTTP %d %s: %s", r.Status, r.Error, r.ErrorDesc)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", keyB, nil)
	h.check("exchange: DPoP proof from an unrelated key rejected", r.Status == 400 && r.Error == "invalid_grant", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", nil, nil)
	h.check("exchange: missing DPoP proof rejected", r.Status == 400 && r.Error == "invalid_dpop_proof", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, tamper(sup.DeviceSecret), "openid email", keyA, nil)
	h.check("exchange: tampered device_secret rejected", r.Error == "invalid_grant", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, "not-a-device-secret", "openid email", keyA, nil)
	h.check("exchange: malformed device_secret rejected", r.Error == "invalid_grant", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, "x.y.z", sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: malformed id_token rejected", r.Status == 400 && (r.Error == "invalid_request" || r.Error == "invalid_grant"), "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.AccessToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: access token presented as id_token rejected", r.Status == 400, "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", keyA, func(f url.Values) { f.Set("audience", "https://elsewhere.example") })
	h.check("exchange: audience must be the issuer", r.Error == "invalid_target", "HTTP %d %s", r.Status, r.Error)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", keyA, func(f url.Values) { f.Del("actor_token_type") })
	h.check("exchange: missing actor_token_type rejected", r.Error == "invalid_request", "HTTP %d %s", r.Status, r.Error)

	r = ex(rogue, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: client outside the vendor family rejected", r.Error == "invalid_grant", "HTTP %d %s: %s", r.Status, r.Error, r.ErrorDesc)

	r = ex(foreign, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: listed client of another relying party rejected (pairwise sub)", r.Error == "invalid_grant", "HTTP %d %s: %s", r.Status, r.Error, r.ErrorDesc)

	r = ex(plain, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: client without token-exchange grant rejected", r.Error == "unauthorized_client", "HTTP %d %s", r.Status, r.Error)

	// A second Super App login yields a second device secret: the first id_token must not pair with it.
	sup2 := h.login(ctx, super, "openid email device_sso", keyA)
	r = ex(child, sup.IDToken, sup2.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: id_token not bound to device_secret (ds_hash/sid) rejected", r.Error == "invalid_grant", "HTTP %d %s: %s", r.Status, r.Error, r.ErrorDesc)

	// Silent SSO for the Child App.
	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	cidc := claimsOf(r.IDToken)
	catc := claimsOf(r.AccessToken)
	h.check("exchange: child app signed in silently", r.Status == 200 && r.AccessToken != "" && r.IDToken != "",
		"HTTP %d %s %s", r.Status, r.Error, r.ErrorDesc)
	h.check("exchange: issued_token_type is access_token, token_type DPoP", r.IssuedTokenType == tokenTypeAccessToken &&
		strings.EqualFold(r.TokenType, "DPoP"), "issued_token_type=%s token_type=%s", r.IssuedTokenType, r.TokenType)
	h.check("exchange: child id_token audience is the child, same sid", cidc["aud"] == child.id && cidc["sid"] == sidc["sid"] &&
		cidc["sub"] == sidc["sub"], "aud=%v same_sid=%t same_sub=%t", cidc["aud"], cidc["sid"] == sidc["sid"], cidc["sub"] == sidc["sub"])
	h.check("exchange: child access token bound to key A, scope subset", cnfJKT(catc) == keyA.jkt && r.Scope == "openid email",
		"cnf.jkt matches=%t scope=%q", cnfJKT(catc) == keyA.jkt, r.Scope)
	h.check("exchange: no device_secret re-issued", r.DeviceSecret == "", "device_secret present=%t", r.DeviceSecret != "")
	st, _ = h.userinfo(ctx, r.AccessToken, keyA)
	h.check("exchange: child userinfo with key A DPoP proof", st == 200, "HTTP %d", st)
	st, _ = h.userinfo(ctx, r.AccessToken, keyB)
	h.check("exchange: child userinfo with another key rejected", st == 401 || st == 400, "HTTP %d", st)

	r = ex(child, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: same app may sign in again (e.g. after sign-out)", r.Status == 200 && r.AccessToken != "",
		"HTTP %d %s %s", r.Status, r.Error, r.ErrorDesc)

	status1, status2, err2 := h.replayExchange(ctx, child, sup.IDToken, sup.DeviceSecret, keyA)
	// The replay is refused by whichever single-use check runs first (client assertion jti: 401
	// invalid_client, or DPoP proof jti: 400 invalid_dpop_proof).
	h.check("exchange: replaying an identical request (same proof and assertion) rejected",
		status1 == 200 && (status2 == 400 || status2 == 401),
		"first HTTP %d, replay HTTP %d %s", status1, status2, err2)

	self := ex(super, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
	h.check("exchange: super app renews its own access token with its device secret",
		self.Status == 200 && self.AccessToken != "" && cnfJKT(claimsOf(self.AccessToken)) == keyA.jkt,
		"HTTP %d %s", self.Status, self.Error)

	r = ex(child2, sup.IDToken, sup.DeviceSecret, "openid", keyA, nil)
	h.check("exchange: second sibling app with a narrower scope", r.Status == 200 && r.Scope == "openid", "HTTP %d scope=%q %s", r.Status, r.Scope, r.Error)

	// The ID token is short-lived (eSignet default 120s); the device secret carries the session.
	// Wait until the Super App's ID token has expired and sign a sibling in with it.
	if exp, ok := sidc["exp"].(float64); ok {
		wait := time.Until(time.Unix(int64(exp), 0)) + 15*time.Second
		if wait > 0 && wait <= 5*time.Minute && os.Getenv("SKIP_EXPIRY_WAIT") == "" {
			fmt.Printf("... waiting %s for the super app's id_token to expire\n", wait.Round(time.Second))
			time.Sleep(wait)
			r = ex(child2, sup.IDToken, sup.DeviceSecret, "openid email", keyA, nil)
			h.check("exchange: works after the id_token expired (device secret still valid)",
				r.Status == 200 && r.AccessToken != "", "HTTP %d %s %s", r.Status, r.Error, r.ErrorDesc)
		}
	}

	if logPath := os.Getenv("ESIGNET_LOG"); logPath != "" {
		logBytes, err := os.ReadFile(logPath)
		if err != nil {
			return fmt.Errorf("read log: %w", err)
		}
		leaked := []string{}
		for name, secret := range map[string]string{"device_secret": sup.DeviceSecret, "super id_token": sup.IDToken,
			"super access_token": sup.AccessToken, "child access_token": r.AccessToken, "otp": "\"" + h.otp + "\""} {
			if secret != "" && strings.Contains(string(logBytes), secret) {
				leaked = append(leaked, name)
			}
		}
		h.check("logs: no device secrets, tokens or OTPs logged", len(leaked) == 0, "leaked=%v (%d bytes scanned)", leaked, len(logBytes))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------
// protocol steps
// ---------------------------------------------------------------------------------------------------

func (h *harness) newClient(prefix string) *client {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &client{id: prefix + "-" + h.runID, key: k, kid: prefix + "-key"}
}

func (h *harness) register(ctx context.Context, c *client, grants []string, ac map[string]any, rpID string) error {
	body, _ := json.Marshal(map[string]any{
		"requestTime": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"request": map[string]any{
			"clientId": c.id, "clientName": c.id, "clientNameLangMap": map[string]string{"eng": c.id},
			"relyingPartyId": rpID, "logoUri": "https://native-sso.example.org/logo.png",
			"redirectUris": []string{redirectURI}, "publicKey": rsaJWK(c),
			"userClaims": []string{"name", "email", "phone_number"}, "authContextRefs": []string{acrOTP},
			"grantTypes": grants, "clientAuthMethods": []string{"private_key_jwt"}, "additionalConfig": ac,
		},
	})
	status, rb, _, err := h.do(ctx, http.MethodPost, h.base+"/client-mgmt/client",
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + h.admin}, string(body))
	if err != nil {
		return err
	}
	if status/100 != 2 || strings.Contains(string(rb), "errorCode") {
		return fmt.Errorf("HTTP %d: %s", status, trunc(rb))
	}
	return nil
}

func (h *harness) par(ctx context.Context, c *client, scope string, key *dpopKey) (int, []byte) {
	status, body, _ := h.parFull(ctx, c, scope, key)
	return status, body
}

type pkcePair struct{ verifier, challenge string }

func (h *harness) parFull(ctx context.Context, c *client, scope string, key *dpopKey) (int, []byte, pkcePair) {
	v := randB64(32)
	p := pkcePair{verifier: v, challenge: b64sha256(v)}
	f := url.Values{
		"response_type": {"code"}, "client_id": {c.id}, "scope": {scope}, "redirect_uri": {redirectURI},
		"state": {randB64(12)}, "nonce": {randB64(12)}, "code_challenge": {p.challenge},
		"code_challenge_method": {"S256"}, "acr_values": {acrOTP}, "dpop_jkt": {key.jkt},
		"client_assertion_type": {clientAssertionTypeJWT}, "client_assertion": {h.assertion(c)},
	}
	status, body := h.postDPoP(ctx, h.d.PAREndpoint, f, key, "")
	return status, body, p
}

func (h *harness) login(ctx context.Context, c *client, scope string, key *dpopKey) tokenResponse {
	status, body, p := h.parFull(ctx, c, scope, key)
	var parResp struct {
		RequestURI string `json:"request_uri"`
	}
	_ = json.Unmarshal(body, &parResp)
	if parResp.RequestURI == "" {
		return tokenResponse{Status: status, Error: "par_failed", ErrorDesc: trunc(body)}
	}
	authURL := h.d.AuthEndpoint + "?" + url.Values{"client_id": {c.id}, "request_uri": {parResp.RequestURI}}.Encode()
	answers := map[string]string{}
	for k, v := range map[string]string{"username": h.individualID, "individualId": h.individualID,
		"otp": h.otp, "captchaToken": "harness-captcha-bypass"} {
		answers[esignet.Normalize(k)] = v
	}
	driver := esignet.New(answers, esignet.AuthFactorTokens("otp"), true, 30*time.Second)
	driver.UseIDType(esignet.IDTypeTokens("uin"))
	fr := driver.Run(ctx, h.base, authURL)
	if !fr.OK() {
		return tokenResponse{Error: "login_failed", ErrorDesc: fr.Error}
	}
	ru, _ := url.Parse(fr.RedirectURI)
	code := ru.Query().Get("code")
	if code == "" {
		return tokenResponse{Error: "no_code", ErrorDesc: ru.Query().Get("error")}
	}
	f := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {c.id}, "code_verifier": {p.verifier},
		"client_assertion_type": {clientAssertionTypeJWT}, "client_assertion": {h.assertion(c)},
	}
	return h.token(ctx, f, key)
}

func (h *harness) exchange(ctx context.Context, c *client, idToken, deviceSecret, scope string, key *dpopKey,
	mutate func(url.Values)) tokenResponse {
	f := url.Values{
		"grant_type": {grantTokenExchange}, "client_id": {c.id},
		"subject_token": {idToken}, "subject_token_type": {tokenTypeIDToken},
		"actor_token": {deviceSecret}, "actor_token_type": {tokenTypeDeviceSecret},
		"audience": {h.d.Issuer}, "scope": {scope},
		"client_assertion_type": {clientAssertionTypeJWT}, "client_assertion": {h.assertion(c)},
	}
	if mutate != nil {
		mutate(f)
	}
	return h.token(ctx, f, key)
}

// replayExchange sends one exchange request, then the byte-identical request again (same DPoP proof,
// same client assertion), and returns both statuses and the replay's error code.
func (h *harness) replayExchange(ctx context.Context, c *client, idToken, deviceSecret string, key *dpopKey) (int, int, string) {
	f := url.Values{
		"grant_type": {grantTokenExchange}, "client_id": {c.id},
		"subject_token": {idToken}, "subject_token_type": {tokenTypeIDToken},
		"actor_token": {deviceSecret}, "actor_token_type": {tokenTypeDeviceSecret},
		"audience": {h.d.Issuer}, "scope": {"openid email"},
		"client_assertion_type": {clientAssertionTypeJWT}, "client_assertion": {h.assertion(c)},
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded",
		"DPoP": key.proof("POST", h.d.TokenEndpoint, "")}
	s1, _, _, _ := h.do(ctx, http.MethodPost, h.d.TokenEndpoint, headers, f.Encode())
	s2, b2, _, _ := h.do(ctx, http.MethodPost, h.d.TokenEndpoint, headers, f.Encode())
	return s1, s2, jsonErr(b2)
}

func (h *harness) token(ctx context.Context, f url.Values, key *dpopKey) tokenResponse {
	status, body := h.postDPoP(ctx, h.d.TokenEndpoint, f, key, "")
	var t tokenResponse
	_ = json.Unmarshal(body, &t)
	t.Status = status
	return t
}

func (h *harness) userinfo(ctx context.Context, accessToken string, key *dpopKey) (int, []byte) {
	for attempt := 0; attempt < 2; attempt++ {
		headers := map[string]string{"Authorization": "DPoP " + accessToken, "DPoP": key.proof("GET", h.d.UserInfo, accessToken)}
		status, body, respH, err := h.do(ctx, http.MethodGet, h.d.UserInfo, headers, "")
		if err != nil {
			return 0, nil
		}
		if n := respH.Get("DPoP-Nonce"); n != "" && n != key.nonce && attempt == 0 && status == 401 {
			key.nonce = n
			continue
		}
		return status, body
	}
	return 0, nil
}

func (h *harness) postDPoP(ctx context.Context, endpoint string, f url.Values, key *dpopKey, ath string) (int, []byte) {
	for attempt := 0; attempt < 2; attempt++ {
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		if key != nil {
			headers["DPoP"] = key.proof("POST", endpoint, ath)
		}
		// A fresh client assertion per attempt: assertions are single-use (jti).
		if f.Has("client_assertion") && attempt > 0 {
			f.Set("client_assertion", h.assertion(&client{id: f.Get("client_id")}))
		}
		status, body, respH, err := h.do(ctx, http.MethodPost, endpoint, headers, f.Encode())
		if err != nil {
			return 0, []byte(err.Error())
		}
		if key != nil && attempt == 0 && jsonErr(body) == "use_dpop_nonce" {
			if n := respH.Get("DPoP-Nonce"); n != "" {
				key.nonce = n
				continue
			}
		}
		return status, body
	}
	return 0, nil
}

func (h *harness) do(ctx context.Context, method, u string, headers map[string]string, body string) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, resp.Header, nil
}

func (h *harness) getJSON(ctx context.Context, u string, v any) error {
	status, b, _, err := h.do(ctx, http.MethodGet, u, nil, "")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------------------------------------------
// crypto helpers
// ---------------------------------------------------------------------------------------------------

var clientKeys = map[string]*client{}

func rsaJWK(c *client) map[string]any {
	clientKeys[c.id] = c
	return map[string]any{"kty": "RSA", "kid": c.kid, "use": "sig", "alg": "RS256",
		"n": b64(c.key.N.Bytes()), "e": b64(big.NewInt(int64(c.key.E)).Bytes())}
}

// assertion builds a private_key_jwt client assertion; aud is the issuer, as eSignet validates.
func (h *harness) assertion(c *client) string {
	if full, ok := clientKeys[c.id]; ok {
		c = full
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": c.kid})
	claims, _ := json.Marshal(map[string]any{"iss": c.id, "sub": c.id, "aud": h.d.Issuer,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": randB64(16)})
	input := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	return input + "." + b64(sig)
}

// dpopKey is an EC P-256 DPoP key (ES256), the key type Android Keystore / StrongBox provides.
type dpopKey struct {
	priv  *ecdsa.PrivateKey
	jwk   map[string]string
	jkt   string
	nonce string
}

func newDPoPKey() *dpopKey {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := b64(pad32(priv.PublicKey.X.Bytes()))
	y := b64(pad32(priv.PublicKey.Y.Bytes()))
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return &dpopKey{priv: priv, jwk: jwk, jkt: b64(sum[:])}
}

func (k *dpopKey) proof(htm, htu, accessToken string) string {
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.jwk})
	c := map[string]any{"jti": randB64(16), "htm": htm, "htu": htu, "iat": time.Now().Unix()}
	if accessToken != "" {
		c["ath"] = b64sha256(accessToken)
	}
	if k.nonce != "" {
		c["nonce"] = k.nonce
	}
	claims, _ := json.Marshal(c)
	input := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, k.priv, sum[:])
	return input + "." + b64(append(pad32(r.Bytes()), pad32(s.Bytes())...))
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64sha256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64(b)
}

func claimsOf(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	out := map[string]any{}
	if len(parts) != 3 {
		return out
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func cnfJKT(c map[string]any) string {
	cnf, _ := c["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func jsonErr(b []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Error
}

// tamper flips one character of the JWE ciphertext segment.
func tamper(jwe string) string {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || parts[3] == "" {
		return jwe + "x"
	}
	ct := []byte(parts[3])
	if ct[0] == 'A' {
		ct[0] = 'B'
	} else {
		ct[0] = 'A'
	}
	parts[3] = string(ct)
	return strings.Join(parts, ".")
}

func trunc(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
