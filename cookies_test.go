package howdah

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// newTestApplication builds a real application around auth, so the cookie
// tests go through the mux, the PageMux and the handlers a deployment does
// rather than calling the cookie writers directly. bp is registered as a
// component as well as handed to the auth, which is what the README tells
// an application to do.
func newTestApplication(
	t *testing.T, auth *OIDCAuth, bp BasePath,
) http.Handler {
	t.Helper()

	mux := http.NewServeMux()

	_, err := NewApplication(
		slog.New(slog.DiscardHandler),
		mux,
		// ParseFS refuses a pattern that matches no files, and nothing
		// in these tests renders a page.
		fstest.MapFS{"empty.html": &fstest.MapFile{}},
		fstest.MapFS{},
		fstest.MapFS{},
		[]Component{bp, auth},
	)
	if err != nil {
		t.Fatalf("create application: %v", err)
	}

	// Keepalive is not one of the routes RegisterRoutes claims — the
	// application picks the endpoint — so it is mounted here the way the
	// documentation says to mount it.
	mux.HandleFunc("GET /auth/keepalive", auth.Keepalive)

	return mux
}

// wantCookie is a cookie a request is expected to set, and the path it must
// be scoped to.
type wantCookie struct {
	name string
	path string
}

// TestCookieAttributes is the golden test for the attributes of every
// cookie howdah sets: HttpOnly, SameSite=Lax, Secure, a path inside the
// application's mount point, and no Domain at all.
//
// It is driven through the real handlers rather than through the cookie
// writers, so that a cookie set from somewhere the writers are not is
// caught too — a response carrying a cookie this test does not know about
// is a failure, which is the part that keeps it honest as the package
// grows.
func TestCookieAttributes(t *testing.T) {
	mounts := []struct {
		name string
		base BasePath
	}{
		{name: "at the root", base: NewBasePath("/")},
		{name: "under a mount point", base: NewBasePath("/admin")},
	}

	for _, mount := range mounts {
		t.Run(mount.name, func(t *testing.T) {
			t.Run("secure", func(t *testing.T) {
				checkCookieAttributes(t, mount.base, false)
			})

			// The opt-out has to leave everything else alone. It is
			// there so a plain-http development run gets a cookie
			// the browser sends back, not so it gets a lax one.
			t.Run("with insecure cookies", func(t *testing.T) {
				checkCookieAttributes(t, mount.base, true)
			})
		})
	}
}

func checkCookieAttributes(t *testing.T, base BasePath, insecure bool) {
	t.Helper()

	opts := []OIDCAuthOption{WithBasePath(base)}
	if insecure {
		opts = append(opts, WithInsecureCookies())
	}

	provider := newTestProvider(t, tokenResponse(t, 300))
	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t), opts...)
	handler := newTestApplication(t, auth, base)

	// A session whose access token has already expired, so that a request
	// carrying it goes through the refresh and writes the cookie back.
	session := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)),
		time.Now().Add(-time.Minute))

	// The paths are the application-relative ones the handlers see, since
	// a mounted application sits behind http.StripPrefix.
	requests := []struct {
		name    string
		request func() *http.Request
		want    []wantCookie
	}{
		{
			name: "the language switch",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet,
					"/set-language?lang=sv&redirect=/", nil)
			},
			want: []wantCookie{
				{name: "lang", path: base.Path("/")},
			},
		},
		{
			name: "resetting the language",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet,
					"/set-language", nil)
			},
			want: []wantCookie{
				{name: "lang", path: base.Path("/")},
			},
		},
		{
			name: "starting a login",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost,
					"/auth/login?redirect=/config/", nil)
			},
			want: []wantCookie{
				{name: "state", path: base.Path("/auth")},
				{name: "nonce", path: base.Path("/auth")},
				{
					name: authRedirCookieName,
					path: base.Path("/auth"),
				},
			},
		},
		{
			// A login from the login page has no target of its own, and
			// clears whatever an abandoned attempt left behind — a
			// cookie the golden test has to see like any other.
			name: "starting a login without a redirect",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost,
					"/auth/login", nil)
			},
			want: []wantCookie{
				{name: "state", path: base.Path("/auth")},
				{name: "nonce", path: base.Path("/auth")},
				{
					name: authRedirCookieName,
					path: base.Path("/auth"),
				},
			},
		},
		{
			name: "refreshing a session",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet,
					"/auth/keepalive", nil)

				r.AddCookie(&http.Cookie{
					Name:  auth.cookieName,
					Value: session,
				})

				return r
			},
			want: []wantCookie{
				{name: auth.cookieName, path: base.Path("/")},
			},
		},
		{
			name: "logging out",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet,
					"/auth/logout", nil)
			},
			want: []wantCookie{
				{name: auth.cookieName, path: base.Path("/")},
			},
		},
	}

	for _, rc := range requests {
		t.Run(rc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, rc.request())

			res := w.Result()
			headers := res.Header.Values("Set-Cookie")

			got := map[string]*http.Cookie{}

			for _, c := range res.Cookies() {
				if _, seen := got[c.Name]; seen {
					t.Errorf("the %q cookie is set twice: %v",
						c.Name, headers)
				}

				got[c.Name] = c
			}

			for _, want := range rc.want {
				c, ok := got[want.name]
				if !ok {
					t.Errorf("the response sets no %q cookie: %v",
						want.name, headers)

					continue
				}

				delete(got, want.name)

				checkCookie(t, c, base, want.path, insecure)
			}

			// A cookie set from somewhere this test does not know
			// about has not been through the checks above, which is
			// the whole point of asserting on the response rather
			// than on the cookie writers.
			for name := range got {
				t.Errorf(
					"the response sets an unexpected %q cookie: %v",
					name, headers)
			}
		})
	}
}

func checkCookie(
	t *testing.T, c *http.Cookie, base BasePath, wantPath string,
	insecure bool,
) {
	t.Helper()

	if !c.HttpOnly {
		t.Errorf("the %q cookie is not HttpOnly: %s", c.Name, c.String())
	}

	// Lax, and not Strict: the OIDC callback is a cross-site top-level
	// navigation from the provider, and Strict would have the browser
	// withhold state and nonce on exactly that request.
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("the %q cookie has SameSite %v, want %v",
			c.Name, c.SameSite, http.SameSiteLaxMode)
	}

	if c.Secure == insecure {
		t.Errorf("the %q cookie has Secure %v, want %v",
			c.Name, c.Secure, !insecure)
	}

	if c.Path != wantPath {
		t.Errorf("the %q cookie has path %q, want %q",
			c.Name, c.Path, wantPath)
	}

	// The mount point is what a co-hosted application shares the host
	// with, so a cookie escaping it is a cookie sent to somebody else's
	// routes.
	if !strings.HasPrefix(c.Path, base.Path("/")) {
		t.Errorf("the %q cookie has path %q, outside the mount point %q",
			c.Name, c.Path, base.Path("/"))
	}

	// A Set-Cookie without Domain is host-only by definition, which is
	// the posture howdah wants: with one, the session is handed to every
	// subdomain of a host we may only share by accident.
	if c.Domain != "" {
		t.Errorf("the %q cookie has domain %q, want no Domain at all",
			c.Name, c.Domain)
	}
}

// TestCookieSecureIgnoresTheRequest pins the decision the hardening rests
// on: Secure comes from the configuration and from nothing else.
//
// Reading it off the connection is what left the session cookie insecure in
// every real deployment, since a TLS-terminating ingress hands howdah a
// plain http connection, and the X-Forwarded-Proto sniff that repairs that
// from the outside trusts a header the client sets. Neither is consulted
// here, in either direction.
func TestCookieSecureIgnoresTheRequest(t *testing.T) {
	adjustments := []struct {
		name   string
		adjust func(r *http.Request)
	}{
		{name: "plain http"},
		{
			name: "forwarded as http",
			adjust: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "http")
			},
		},
		{
			name: "forwarded as https",
			adjust: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
			},
		},
		{
			name: "TLS all the way",
			adjust: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{}
			},
		},
	}

	for _, insecure := range []bool{false, true} {
		name := "secure"
		if insecure {
			name = "with insecure cookies"
		}

		t.Run(name, func(t *testing.T) {
			base := NewBasePath("/")

			opts := []OIDCAuthOption{WithBasePath(base)}
			if insecure {
				opts = append(opts, WithInsecureCookies())
			}

			auth := newTestAuthWith(t, newTestProvider(
				t, tokenResponse(t, 300)),
				newTestAuthKeyring(t), opts...)
			handler := newTestApplication(t, auth, base)

			for _, a := range adjustments {
				t.Run(a.name, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodGet,
						"/set-language?lang=sv", nil)

					if a.adjust != nil {
						a.adjust(r)
					}

					w := httptest.NewRecorder()

					handler.ServeHTTP(w, r)

					c := responseCookie(t, w, "lang")

					if c.Secure == insecure {
						t.Errorf(
							"the lang cookie has Secure %v, want %v",
							c.Secure, !insecure)
					}
				})
			}
		})
	}
}

// TestClearedSessionCookieExpiresBothWays covers the pair of attributes a
// cleared cookie needs: Max-Age is what current browsers act on, and the
// expiry in the past is what an old one understands.
func TestClearedSessionCookieExpiresBothWays(t *testing.T) {
	auth := newTestAuth(t)

	w := httptest.NewRecorder()

	auth.clearTokenCookie(w)

	c := responseCookie(t, w, auth.cookieName)

	if c.Value != "" {
		t.Errorf("the cleared cookie has value %q, want it empty", c.Value)
	}

	// http.ParseSetCookie and the response parser both report a
	// "Max-Age=0" attribute as MaxAge -1, which is the delete-it-now
	// value.
	if c.MaxAge != -1 {
		t.Errorf("the cleared cookie has Max-Age %d, want -1", c.MaxAge)
	}

	if !c.Expires.Before(time.Now()) {
		t.Errorf("the cleared cookie expires at %s, want a time in the past",
			c.Expires)
	}
}

// responseCookie returns the named cookie the response sets.
func responseCookie(
	t *testing.T, w *httptest.ResponseRecorder, name string,
) *http.Cookie {
	t.Helper()

	res := w.Result()

	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}

	t.Fatalf("the response sets no %q cookie: %v",
		name, res.Header.Values("Set-Cookie"))

	return nil
}

// TestOversizedSessionCookieFailsTheLogin covers the failure that is
// otherwise invisible: a session cookie too large for a browser to store is
// dropped silently, so the user logs in successfully and arrives back at the
// login page with nothing logged anywhere. Failing the write is what turns
// that into something diagnosable.
func TestOversizedSessionCookieFailsTheLogin(t *testing.T) {
	quietLogs(t)

	auth := newTestAuth(t)

	// A provider with a very fat roles claim. The token JSON goes into the
	// sealed payload more or less verbatim, so this is what an oversized
	// access token does.
	token := testToken(time.Now().Add(time.Hour))
	token.AccessToken = strings.Repeat("A", 5000)

	w := httptest.NewRecorder()

	err := auth.setTokenCookie(w, token, time.Now())
	if err == nil {
		t.Fatal("setTokenCookie accepted a session too large for a cookie")
	}

	if !strings.Contains(err.Error(), "over the") {
		t.Errorf("error does not name the limit: %v", err)
	}

	if got := setCookies(w, auth.cookieName); len(got) != 0 {
		t.Errorf("got %d session cookies, want none written", len(got))
	}

	// A normal token still goes through, so the guard is not simply
	// refusing everything.
	w = httptest.NewRecorder()

	err = auth.setTokenCookie(w, testToken(time.Now().Add(time.Hour)), time.Now())
	if err != nil {
		t.Fatalf("setTokenCookie refused a normal session: %v", err)
	}

	if got := setCookies(w, auth.cookieName); len(got) != 1 {
		t.Fatalf("got %d session cookies, want 1", len(got))
	}
}
