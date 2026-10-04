// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type testEnv struct {
	t        *testing.T
	key      *rsa.PrivateKey
	casdoor  *httptest.Server
	kibana   *httptest.Server
	handler  *Handler
	token    func(code string) string
	upstream *http.Request
}

func newKey(t *testing.T) (*rsa.PrivateKey, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "casdoor-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (e *testEnv) signToken(key *rsa.PrivateKey, claims jwt.MapClaims) string {
	base := jwt.MapClaims{
		"owner":       "casbin",
		"name":        "alice",
		"id":          "a1b2c3",
		"displayName": "Alice",
		"email":       "alice@example.com",
		"aud":         []string{"test-client-id"},
		"exp":         time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		base[k] = v
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, base).SignedString(key)
	if err != nil {
		e.t.Fatal(err)
	}
	return token
}

func newTestEnv(t *testing.T) *testEnv {
	e := &testEnv{t: t}
	var certificate string
	e.key, certificate = newKey(t)
	e.token = func(code string) string { return e.signToken(e.key, nil) }

	e.casdoor = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login/oauth/access_token" || r.FormValue("client_secret") != "test-client-secret" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		code := r.FormValue("code")
		if code == "used-code" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "authorization code has been used"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": e.token(code), "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(e.casdoor.Close)

	e.kibana = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upstream = r
		_, _ = w.Write([]byte("kibana " + r.URL.RequestURI()))
	}))
	t.Cleanup(e.kibana.Close)

	config := &Config{
		PluginEndpoint:   "https://kibana.example.com",
		TargetEndpoint:   e.kibana.URL,
		CasdoorEndpoint:  e.casdoor.URL,
		ClientId:         "test-client-id",
		ClientSecret:     "test-client-secret",
		Certificate:      certificate,
		Organization:     "casbin",
		Application:      "app-elk",
		SessionSecret:    "test-session-secret",
		UpstreamUsername: "kibana_user",
		UpstreamPassword: "kibana_password",
	}
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	e.handler = handler
	return e
}

func (e *testEnv) do(r *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func browserGet(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	return r
}

func findCookie(w *httptest.ResponseRecorder, prefix string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if strings.HasPrefix(c.Name, prefix) && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// startLogin visits a page without a session and returns the state and its cookie.
func (e *testEnv) startLogin(target string) (string, *http.Cookie) {
	w := e.do(browserGet(target))
	if w.Code != http.StatusFound {
		e.t.Fatalf("expected a redirect to Casdoor, got %d", w.Code)
	}
	location, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(location.String(), e.casdoor.URL+"/login/oauth/authorize?") {
		e.t.Fatalf("unexpected redirect %s", location)
	}
	q := location.Query()
	if q.Get("client_id") != "test-client-id" || q.Get("redirect_uri") != "https://kibana.example.com"+CallbackPath || q.Get("response_type") != "code" {
		e.t.Fatalf("unexpected authorize parameters %v", q)
	}
	cookie := findCookie(w, stateCookieNamePrefix)
	if cookie == nil || cookie.Name != stateCookieNamePrefix+q.Get("state") || !cookie.HttpOnly || !cookie.Secure {
		e.t.Fatalf("unexpected state cookie %v", cookie)
	}
	return q.Get("state"), cookie
}

func (e *testEnv) callback(code string, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return e.do(browserGet(CallbackPath+"?code="+code+"&state="+state), cookies...)
}

func (e *testEnv) signIn(target string) *http.Cookie {
	state, stateCookie := e.startLogin(target)
	w := e.callback("the-code", state, stateCookie)
	if w.Code != http.StatusFound || w.Header().Get("Location") != target {
		e.t.Fatalf("expected a redirect to %s, got %d %s %s", target, w.Code, w.Header().Get("Location"), w.Body.String())
	}
	session := findCookie(w, sessionCookieName)
	if session == nil {
		e.t.Fatal("no session cookie")
	}
	return session
}

func TestSignInAndProxy(t *testing.T) {
	e := newTestEnv(t)
	session := e.signIn("/app/discover?x=1")

	r := browserGet("/app/discover?x=1")
	r.Header.Set("X-Forwarded-User", "admin")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "kibana-cookie"})
	w := e.do(r, session)
	if w.Code != http.StatusOK || w.Body.String() != "kibana /app/discover?x=1" {
		t.Fatalf("unexpected response %d %s", w.Code, w.Body.String())
	}
	if got := e.upstream.Header.Get("X-Forwarded-User"); got != "alice" {
		t.Errorf("X-Forwarded-User = %q", got)
	}
	if got := e.upstream.Header.Get("X-Forwarded-Email"); got != "alice@example.com" {
		t.Errorf("X-Forwarded-Email = %q", got)
	}
	if got := e.upstream.Header.Get("Cookie"); got != "sid=kibana-cookie" {
		t.Errorf("Cookie sent to Kibana = %q", got)
	}
	if username, password, ok := e.upstream.BasicAuth(); !ok || username != "kibana_user" || password != "kibana_password" {
		t.Errorf("unexpected basic auth %q %q", username, password)
	}
}

func TestApiRequestWithoutSession(t *testing.T) {
	e := newTestEnv(t)
	r := httptest.NewRequest(http.MethodPost, "/api/saved_objects", strings.NewReader("{}"))
	r.Header.Set("kbn-xsrf", "true")
	if w := e.do(r); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if e.upstream != nil {
		t.Fatal("the request reached Kibana")
	}
}

func TestCallbackRejectsWrongState(t *testing.T) {
	e := newTestEnv(t)
	_, stateCookie := e.startLogin("/")
	if w := e.callback("the-code", "forged", stateCookie); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackRejectsMissingStateCookie(t *testing.T) {
	e := newTestEnv(t)
	state, _ := e.startLogin("/")
	if w := e.callback("the-code", state); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackRejectsForgedStateCookie(t *testing.T) {
	e := newTestEnv(t)
	state, stateCookie := e.startLogin("/")
	stateCookie.Value = strings.Replace(stateCookie.Value, ".", "x.", 1)
	if w := e.callback("the-code", state, stateCookie); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackReportsTokenError(t *testing.T) {
	e := newTestEnv(t)
	state, stateCookie := e.startLogin("/")
	w := e.callback("used-code", state, stateCookie)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "authorization code has been used") {
		t.Fatalf("unexpected response %d %s", w.Code, w.Body.String())
	}
}

func TestCallbackRejectsBadSignature(t *testing.T) {
	e := newTestEnv(t)
	otherKey, _ := newKey(t)
	e.token = func(string) string { return e.signToken(otherKey, nil) }
	state, stateCookie := e.startLogin("/")
	if w := e.callback("the-code", state, stateCookie); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackRejectsOtherAudience(t *testing.T) {
	e := newTestEnv(t)
	e.token = func(string) string { return e.signToken(e.key, jwt.MapClaims{"aud": []string{"other-app"}}) }
	state, stateCookie := e.startLogin("/")
	if w := e.callback("the-code", state, stateCookie); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackRejectsOtherOrganization(t *testing.T) {
	e := newTestEnv(t)
	e.token = func(string) string { return e.signToken(e.key, jwt.MapClaims{"owner": "built-in"}) }
	state, stateCookie := e.startLogin("/")
	w := e.callback("the-code", state, stateCookie)
	if w.Code != http.StatusForbidden || findCookie(w, sessionCookieName) != nil {
		t.Fatalf("expected 403 without session, got %d", w.Code)
	}
}

func TestCallbackDoesNotRedirectToOtherHost(t *testing.T) {
	e := newTestEnv(t)
	state, stateCookie := e.startLogin("//evil.example.com/x")
	w := e.callback("the-code", state, stateCookie)
	if w.Header().Get("Location") != "/" {
		t.Fatalf("redirected to %q", w.Header().Get("Location"))
	}
}

func TestTamperedSessionIsRejected(t *testing.T) {
	e := newTestEnv(t)
	session := e.signIn("/")
	payload, signature, _ := strings.Cut(session.Value, ".")
	session.Value = payload + "A." + signature
	if w := e.do(browserGet("/"), session); w.Code != http.StatusFound {
		t.Fatalf("expected a redirect to Casdoor, got %d", w.Code)
	}
}

func TestStateCookieIsNotASession(t *testing.T) {
	e := newTestEnv(t)
	_, stateCookie := e.startLogin("/")
	if w := e.do(browserGet("/"), &http.Cookie{Name: sessionCookieName, Value: stateCookie.Value}); w.Code != http.StatusFound {
		t.Fatalf("expected a redirect to Casdoor, got %d", w.Code)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	e := newTestEnv(t)
	value, err := e.handler.signer.encode("session", Session{Name: "alice", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if w := e.do(browserGet("/"), &http.Cookie{Name: sessionCookieName, Value: value}); w.Code != http.StatusFound {
		t.Fatalf("expected a redirect to Casdoor, got %d", w.Code)
	}
}

func TestLogout(t *testing.T) {
	e := newTestEnv(t)
	session := e.signIn("/")
	w := e.do(browserGet(LogoutPath), session)
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if w.Code != http.StatusOK || !cleared {
		t.Fatalf("session cookie not cleared: %d %v", w.Code, w.Result().Cookies())
	}
}
