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
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
)

const (
	CallbackPath = "/casdoor-auth/callback"
	LogoutPath   = "/casdoor-auth/logout"

	sessionCookieName     = "casdoor_auth_session"
	stateCookieNamePrefix = "casdoor_auth_state_"
	stateLifetime         = 10 * time.Minute
)

// identityHeaders are set on every request sent to Kibana, and removed from the
// incoming request first so that clients cannot fake them.
var identityHeaders = []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Preferred-Username"}

type Handler struct {
	config *Config
	client *casdoorsdk.Client
	signer *signer
	proxy  *httputil.ReverseProxy
	secure bool
}

func NewHandler(config *Config) (*Handler, error) {
	target, err := url.Parse(config.TargetEndpoint)
	if err != nil {
		return nil, err
	}

	key := []byte(config.SessionSecret)
	if len(key) == 0 {
		log.Println("sessionSecret is not set, using a random one: everybody will be signed out when the proxy restarts")
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
	}

	h := &Handler{
		config: config,
		client: casdoorsdk.NewClient(config.CasdoorEndpoint, config.ClientId, config.ClientSecret, config.Certificate, config.Organization, config.Application),
		signer: &signer{key: key},
		secure: strings.HasPrefix(config.PluginEndpoint, "https://"),
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			h.rewriteUpstreamRequest(r.Out, r.In)
		},
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case CallbackPath:
		h.handleCallback(w, r)
		return
	case LogoutPath:
		h.handleLogout(w, r)
		return
	}

	if _, ok := h.getSession(r); ok {
		h.proxy.ServeHTTP(w, r)
		return
	}

	// Browsers navigating to a page are sent to Casdoor; Kibana's own API calls get a 401
	// so that it does not follow a redirect to a different origin.
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.startLogin(w, r)
		return
	}
	http.Error(w, "Unauthorized, please sign in again", http.StatusUnauthorized)
}

func (h *Handler) getSession(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	var session Session
	if err = h.signer.decode("session", cookie.Value, &session); err != nil || expired(session.ExpiresAt) {
		return nil, false
	}
	return &session, true
}

func (h *Handler) rewriteUpstreamRequest(out *http.Request, in *http.Request) {
	for _, name := range identityHeaders {
		out.Header.Del(name)
	}

	// Kibana does not need the proxy's cookies
	out.Header.Del("Cookie")
	for _, cookie := range in.Cookies() {
		if cookie.Name != sessionCookieName && !strings.HasPrefix(cookie.Name, stateCookieNamePrefix) {
			out.AddCookie(cookie)
		}
	}

	if session, ok := h.getSession(in); ok {
		out.Header.Set("X-Forwarded-User", session.Name)
		out.Header.Set("X-Forwarded-Preferred-Username", session.Name)
		if session.Email != "" {
			out.Header.Set("X-Forwarded-Email", session.Email)
		}
	}

	if h.config.UpstreamUsername != "" {
		out.SetBasicAuth(h.config.UpstreamUsername, h.config.UpstreamPassword)
	}
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *Handler) startLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// One cookie per login attempt, named after its state, so that signing in from several tabs at once works.
	value, err := h.signer.encode("state", loginState{
		ReturnTo:  r.URL.RequestURI(),
		ExpiresAt: time.Now().Add(stateLifetime).Unix(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieNamePrefix + state,
		Value:    value,
		Path:     CallbackPath,
		MaxAge:   int(stateLifetime.Seconds()),
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})

	params := url.Values{}
	params.Set("client_id", h.config.ClientId)
	params.Set("response_type", "code")
	params.Set("redirect_uri", h.config.PluginEndpoint+CallbackPath)
	params.Set("scope", "read")
	params.Set("state", state)
	http.Redirect(w, r, h.config.CasdoorEndpoint+"/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if e := query.Get("error"); e != "" {
		h.renderError(w, http.StatusBadRequest, fmt.Sprintf("Casdoor sign-in failed: %s %s", e, query.Get("error_description")))
		return
	}

	state := query.Get("state")
	cookie, err := r.Cookie(stateCookieNamePrefix + state)
	var login loginState
	if state == "" || err != nil || h.signer.decode("state", cookie.Value, &login) != nil || expired(login.ExpiresAt) {
		h.renderError(w, http.StatusBadRequest, "Invalid or expired state, please sign in again.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookie.Name, Path: CallbackPath, MaxAge: -1, HttpOnly: true, Secure: h.secure})

	token, err := h.client.GetOAuthToken(query.Get("code"), state)
	if err != nil {
		log.Printf("failed to get the OAuth token: %v", err)
		h.renderError(w, http.StatusBadRequest, "Casdoor sign-in failed: "+err.Error())
		return
	}

	claims, err := h.client.ParseJwtToken(token.AccessToken)
	if err != nil {
		log.Printf("invalid access token: %v", err)
		h.renderError(w, http.StatusBadRequest, "Invalid Casdoor access token.")
		return
	}
	if !slices.Contains(claims.Audience, h.config.ClientId) {
		h.renderError(w, http.StatusBadRequest, "The Casdoor access token was issued to another application.")
		return
	}
	if claims.Owner != h.config.Organization {
		h.renderError(w, http.StatusForbidden, fmt.Sprintf("The user %s/%s does not belong to the organization %s.", claims.Owner, claims.Name, h.config.Organization))
		return
	}
	if claims.ExpiresAt == nil {
		h.renderError(w, http.StatusBadRequest, "The Casdoor access token has no expiry.")
		return
	}

	session := Session{
		Id:          claims.Id,
		Name:        claims.Name,
		DisplayName: claims.DisplayName,
		Email:       claims.Email,
		ExpiresAt:   claims.ExpiresAt.Unix(),
	}
	value, err := h.signer.encode("session", session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  claims.ExpiresAt.Time,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	log.Printf("user %s/%s signed in", claims.Owner, claims.Name)

	returnTo := login.ReturnTo
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.HasPrefix(returnTo, "/\\") {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.secure})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Signed out</title><p>You have signed out. <a href="/">Sign in again</a></p>`)
}

func (h *Handler) renderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><title>Sign-in failed</title><p>%s</p><p><a href="/">Try again</a></p>`, html.EscapeString(message))
}
