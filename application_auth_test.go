package howdah

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func newTestAuth(t *testing.T, opts ...OIDCAuthOption) *OIDCAuth {
	t.Helper()

	provider := &oidc.Provider{}

	return NewOIDCAuth(
		provider,
		provider.Verifier(&oidc.Config{ClientID: "test"}),
		oauth2.Config{ClientID: "test"},
		opts...)
}

func TestRequireAuthLoginRedirectWithBasePath(t *testing.T) {
	auth := newTestAuth(t, WithBasePath(NewBasePath("/admin")))

	// The application sits behind StripPrefix, so the request path is
	// the stripped, application-relative path.
	r := httptest.NewRequest("GET", "/config/?x=1", nil)
	w := httptest.NewRecorder()

	_, err := auth.RequireAuth(context.Background(), w, r)
	if err == nil {
		t.Fatal("expected RequireAuth to fail without a session cookie")
	}

	if w.Code != http.StatusFound {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusFound)
	}

	loc := w.Header().Get("Location")
	want := "/admin/auth/login?redirect=%2Fconfig%2F%3Fx%3D1"

	if loc != want {
		t.Errorf("redirect location = %q, want %q", loc, want)
	}
}

func TestAuthRedirectCallbackCookiePaths(t *testing.T) {
	auth := newTestAuth(t, WithBasePath(NewBasePath("/admin")))

	r := httptest.NewRequest("POST", "/auth/login?redirect=/config/", nil)
	w := httptest.NewRecorder()

	_, err := auth.authRedirect(context.Background(), w, r)
	if err != ErrSkipRender {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	cookies := w.Result().Cookies()

	byName := map[string]*http.Cookie{}
	for _, c := range cookies {
		byName[c.Name] = c
	}

	// The browser-visible callback URL is /admin/auth/callback, so the
	// cookies must be scoped to a path that matches it.
	for _, name := range []string{"state", "nonce", "auth_redir"} {
		c, ok := byName[name]
		if !ok {
			t.Errorf("missing %q cookie", name)

			continue
		}

		if c.Path != "/admin/auth" {
			t.Errorf("%q cookie path = %q, want %q",
				name, c.Path, "/admin/auth")
		}
	}
}

func TestAuthLogoutWithBasePath(t *testing.T) {
	auth := newTestAuth(t,
		WithBasePath(NewBasePath("/admin")),
		WithSessionCookieName("admin_token"))

	r := httptest.NewRequest("GET", "/auth/logout", nil)
	w := httptest.NewRecorder()

	_, err := auth.authLogout(context.Background(), w, r)
	if err != ErrSkipRender {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	if loc := w.Header().Get("Location"); loc != "/admin/" {
		t.Errorf("redirect location = %q, want %q", loc, "/admin/")
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "admin_token" {
		t.Fatalf("expected a single admin_token cookie, got %v", cookies)
	}

	if cookies[0].Path != "/admin/" {
		t.Errorf("cleared cookie path = %q, want %q",
			cookies[0].Path, "/admin/")
	}
}

func TestAuthDefaultsUnchangedAtRoot(t *testing.T) {
	auth := newTestAuth(t)

	r := httptest.NewRequest("GET", "/things/", nil)
	w := httptest.NewRecorder()

	_, err := auth.RequireAuth(context.Background(), w, r)
	if err == nil {
		t.Fatal("expected RequireAuth to fail without a session cookie")
	}

	loc := w.Header().Get("Location")
	want := "/auth/login?redirect=%2Fthings%2F"

	if loc != want {
		t.Errorf("redirect location = %q, want %q", loc, want)
	}

	r = httptest.NewRequest("POST", "/auth/login?redirect=/things/", nil)
	w = httptest.NewRecorder()

	_, err = auth.authRedirect(context.Background(), w, r)
	if err != ErrSkipRender {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	for _, c := range w.Result().Cookies() {
		if c.Path != "/auth" {
			t.Errorf("%q cookie path = %q, want %q",
				c.Name, c.Path, "/auth")
		}
	}
}
