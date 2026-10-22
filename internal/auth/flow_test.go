package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeProvider is a minimal OIDC provider: discovery, JWKS, an authorize
// endpoint that approves at once, and a token endpoint.
type fakeProvider struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	email  string
	groups []string
	nonce  string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, email: "user@example.com"}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	iss := p.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge") == "" {
			http.Error(w, "missing pkce", http.StatusBadRequest)
			return
		}
		p.nonce = q.Get("nonce")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing verifier", http.StatusBadRequest)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		claims, _ := json.Marshal(map[string]any{
			"iss": iss, "sub": "u1", "aud": "trivyal", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": p.nonce, "email": p.email, "name": "User", "groups": p.groups,
		})
		jws, _ := signer.Sign(claims)
		tok, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": tok, "expires_in": 3600})
	})
	t.Cleanup(p.srv.Close)
	return p
}

func TestLoginFlow(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		allow  []string
		want   int
	}{
		{"no restriction", nil, nil, http.StatusTeapot},
		{"allowed group", []string{"ops"}, []string{"ops"}, http.StatusTeapot},
		{"denied group", []string{"dev"}, []string{"ops"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newFakeProvider(t)
			p.groups = tt.groups
			mux := http.NewServeMux()
			app := httptest.NewServer(nil)
			defer app.Close()
			a, err := New(context.Background(), Config{
				IssuerURL: p.srv.URL, ClientID: "trivyal", ClientSecret: "s",
				RedirectURL: app.URL + "/auth/callback", AllowedGroups: tt.allow,
			})
			if err != nil {
				t.Fatal(err)
			}
			a.Register(mux)
			mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
			app.Config.Handler = a.Middleware(mux)

			jar, _ := cookiejar.New(nil)
			c := &http.Client{Jar: jar}
			res, err := c.Get(app.URL + "/vulnerabilities?q=sev:high")
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != tt.want {
				t.Fatalf("final status %d, want %d", res.StatusCode, tt.want)
			}
			if tt.want == http.StatusTeapot {
				if got := res.Request.URL.RequestURI(); got != "/vulnerabilities?q=sev:high" {
					t.Errorf("landed on %q, want the original page", got)
				}
				me, _ := c.Get(app.URL + "/auth/me")
				var u User
				if err := json.NewDecoder(me.Body).Decode(&u); err != nil {
					t.Fatal(err)
				}
				me.Body.Close()
				if u.Email != p.email || u.Groups != nil {
					t.Errorf("/auth/me = %+v", u)
				}
				// Sign out clears the session.
				out, _ := c.Get(app.URL + "/auth/logout")
				out.Body.Close()
				api, _ := c.Get(app.URL + "/api/v1/summary")
				api.Body.Close()
				if api.StatusCode != http.StatusUnauthorized {
					t.Errorf("after logout: %d, want 401", api.StatusCode)
				}
			}
		})
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	p := newFakeProvider(t)
	a, err := New(context.Background(), Config{IssuerURL: p.srv.URL, ClientID: "trivyal", RedirectURL: "http://x/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/auth/callback?code=c&state=wrong", nil)
	r.AddCookie(&http.Cookie{Name: flowCookie, Value: a.sign(flow{State: "right", Expires: time.Now().Add(time.Minute).Unix()})})
	w := httptest.NewRecorder()
	a.callback(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "state") {
		t.Errorf("code %d body %q", w.Code, w.Body.String())
	}
}
