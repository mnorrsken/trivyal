// Package auth adds optional OpenID Connect login in front of the UI and
// API. Sessions are stateless signed cookies, so the app stays a single
// replica without storage.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds the OIDC settings.
type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string // https://host/auth/callback
	Scopes        []string
	GroupsClaim   string
	AllowedGroups []string
	AllowedEmails []string
	// SessionKey signs cookies. Empty means a random key per process, so
	// sessions end when the pod restarts.
	SessionKey []byte
	SessionTTL time.Duration
}

// Auth is the login handler and middleware.
type Auth struct {
	cfg      Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	key      []byte
	secure   bool
}

// User is what the session cookie stores.
type User struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Expires int64    `json:"exp"`
}

const (
	sessionCookie = "trivyal_session"
	flowCookie    = "trivyal_flow"
)

// New discovers the provider and returns the handler.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc needs issuer URL, client ID and redirect URL")
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering oidc provider: %w", err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if !slices.Contains(cfg.Scopes, oidc.ScopeOpenID) {
		cfg.Scopes = append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	key := cfg.SessionKey
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
		slog.Warn("no session key set; sessions end when trivyal restarts")
	} else if len(key) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	u, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redirect URL: %w", err)
	}
	return &Auth{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		key:      key,
		secure:   u.Scheme == "https",
	}, nil
}

// Register adds /auth/login, /auth/callback, /auth/logout and /auth/me.
func (a *Auth) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /auth/logout", a.logout)
	mux.HandleFunc("GET /auth/me", a.me)
	mux.HandleFunc("GET /auth/signed-out", signedOut)
}

func signedOut(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>Signed out · trivyal</title><style>body{font:15px system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#f9f9f7;color:#0b0b0b}` +
		`@media(prefers-color-scheme:dark){body{background:#0d0d0d;color:#f0efec}a{color:#86b6ef}}</style>` +
		`<p>You are signed out. <a href="/auth/login">Sign in again</a></p>`))
}

// Middleware lets through health checks and the auth endpoints; anything
// else needs a session. API calls get 401, pages a redirect to login.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/healthz" || p == "/readyz" || strings.HasPrefix(p, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := a.session(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(p, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"login required"}` + "\n"))
			return
		}
		http.Redirect(w, r, "/auth/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// flow is the state kept across the redirect to the provider.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r"`
	Expires  int64  `json:"exp"`
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	f := flow{
		State:    randString(),
		Nonce:    randString(),
		Verifier: oauth2.GenerateVerifier(),
		Redirect: safeRedirect(r.URL.Query().Get("rd")),
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	a.setCookie(w, flowCookie, f, 10*time.Minute)
	u := a.oauth.AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier))
	http.Redirect(w, r, u, http.StatusFound)
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	var f flow
	if !a.readCookie(r, flowCookie, &f) || f.Expires < time.Now().Unix() {
		http.Error(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	a.clearCookie(w, flowCookie)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "login failed: "+e+" "+q.Get("error_description"), http.StatusUnauthorized)
		return
	}
	if q.Get("state") != f.State {
		http.Error(w, "login state mismatch", http.StatusBadRequest)
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		slog.Warn("oidc code exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "provider returned no id_token", http.StatusUnauthorized)
		return
	}
	idt, err := a.verifier.Verify(r.Context(), raw)
	if err != nil || idt.Nonce != f.Nonce {
		slog.Warn("oidc token verification failed", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "reading claims failed", http.StatusUnauthorized)
		return
	}
	u := User{
		Subject: idt.Subject,
		Email:   str(claims["email"]),
		Name:    str(claims["name"]),
		Groups:  strs(claims[a.cfg.GroupsClaim]),
		Expires: time.Now().Add(a.cfg.SessionTTL).Unix(),
	}
	if u.Name == "" {
		u.Name = str(claims["preferred_username"])
	}
	if !a.allowed(u) {
		slog.Info("login denied", "sub", u.Subject, "email", u.Email)
		http.Error(w, "you are not allowed to use this app", http.StatusForbidden)
		return
	}
	// Groups were only needed for the check; long group lists would not
	// fit in a cookie.
	u.Groups = nil
	a.setCookie(w, sessionCookie, u, a.cfg.SessionTTL)
	http.Redirect(w, r, f.Redirect, http.StatusFound)
}

func (a *Auth) allowed(u User) bool {
	if len(a.cfg.AllowedGroups) == 0 && len(a.cfg.AllowedEmails) == 0 {
		return true
	}
	for _, e := range a.cfg.AllowedEmails {
		if strings.EqualFold(e, u.Email) {
			return true
		}
	}
	for _, g := range u.Groups {
		if slices.Contains(a.cfg.AllowedGroups, g) {
			return true
		}
	}
	return false
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	a.clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/auth/signed-out", http.StatusFound)
}

func (a *Auth) me(w http.ResponseWriter, r *http.Request) {
	u, ok := a.session(r)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"login required"}` + "\n"))
		return
	}
	_ = json.NewEncoder(w).Encode(u)
}

func (a *Auth) session(r *http.Request) (User, bool) {
	var u User
	if !a.readCookie(r, sessionCookie, &u) || u.Expires < time.Now().Unix() {
		return User{}, false
	}
	return u, true
}

// Cookies hold base64(json) + "." + base64(hmac).

func (a *Auth) sign(v any) string {
	data, _ := json.Marshal(v)
	payload := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Auth) verify(s string, v any) bool {
	payload, sig, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(payload))
	if !hmac.Equal(mac.Sum(nil), want) {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

func (a *Auth) setCookie(w http.ResponseWriter, name string, v any, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: a.sign(v), Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func (a *Auth) readCookie(r *http.Request, name string, v any) bool {
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	return a.verify(c.Value, v)
}

func randString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeRedirect allows only local paths, so login cannot be abused as an
// open redirect.
func safeRedirect(rd string) string {
	if rd == "" || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return "/"
	}
	return rd
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}
