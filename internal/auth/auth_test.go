package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func testAuth(cfg Config) *Auth {
	return &Auth{cfg: cfg, key: []byte("0123456789abcdef0123456789abcdef")}
}

func TestSignVerify(t *testing.T) {
	a := testAuth(Config{})
	u := User{Subject: "s", Email: "e@example.com", Expires: 42}
	s := a.sign(u)
	var got User
	if !a.verify(s, &got) || !reflect.DeepEqual(got, u) {
		t.Fatalf("verify(sign(u)) = %+v", got)
	}
	if a.verify(s+"x", &got) {
		t.Error("tampered signature verified")
	}
	other := &Auth{key: []byte("another key that is long enough!!")}
	if other.verify(s, &got) {
		t.Error("signature from another key verified")
	}
}

func TestSafeRedirect(t *testing.T) {
	tests := map[string]string{
		"":                     "/",
		"/vulnerabilities?q=x": "/vulnerabilities?q=x",
		"//evil.example.com":   "/",
		"/\\evil.example.com":  "/",
		"https://evil.example": "/",
	}
	for in, want := range tests {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAllowed(t *testing.T) {
	tests := []struct {
		cfg  Config
		u    User
		want bool
	}{
		{Config{}, User{}, true},
		{Config{AllowedEmails: []string{"A@example.com"}}, User{Email: "a@example.com"}, true},
		{Config{AllowedEmails: []string{"a@example.com"}}, User{Email: "b@example.com"}, false},
		{Config{AllowedGroups: []string{"admins"}}, User{Groups: []string{"users", "admins"}}, true},
		{Config{AllowedGroups: []string{"admins"}}, User{Groups: []string{"users"}}, false},
	}
	for i, tt := range tests {
		if got := testAuth(tt.cfg).allowed(tt.u); got != tt.want {
			t.Errorf("case %d: allowed = %v, want %v", i, got, tt.want)
		}
	}
}

func TestMiddleware(t *testing.T) {
	a := testAuth(Config{})
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	valid := &http.Cookie{Name: sessionCookie, Value: a.sign(User{Subject: "s", Expires: time.Now().Add(time.Hour).Unix()})}
	expired := &http.Cookie{Name: sessionCookie, Value: a.sign(User{Subject: "s", Expires: time.Now().Add(-time.Hour).Unix()})}
	tests := []struct {
		path   string
		cookie *http.Cookie
		want   int
	}{
		{"/healthz", nil, http.StatusTeapot},
		{"/auth/login", nil, http.StatusTeapot},
		{"/api/v1/summary", nil, http.StatusUnauthorized},
		{"/vulnerabilities", nil, http.StatusFound},
		{"/vulnerabilities", expired, http.StatusFound},
		{"/api/v1/summary", valid, http.StatusTeapot},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", tt.path, nil)
		if tt.cookie != nil {
			r.AddCookie(tt.cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s (cookie %v): code %d, want %d", tt.path, tt.cookie != nil, w.Code, tt.want)
		}
	}
}
