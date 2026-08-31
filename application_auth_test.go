package howdah

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// newTestAuthKeyring is the keyring the auth tests seal with, unless they
// need a second key to rotate to.
func newTestAuthKeyring(t *testing.T) *CookieKeyring {
	t.Helper()

	return newTestKeyring(t, CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(1),
	})
}

func newTestAuth(t *testing.T, opts ...OIDCAuthOption) *OIDCAuth {
	t.Helper()

	return newTestAuthWith(t, &oidc.Provider{}, newTestAuthKeyring(t), opts...)
}

func newTestAuthWith(
	t *testing.T, provider *oidc.Provider, keyring *CookieKeyring,
	opts ...OIDCAuthOption,
) *OIDCAuth {
	t.Helper()

	auth, err := NewOIDCAuth(
		provider,
		provider.Verifier(&oidc.Config{ClientID: "test"}),
		oauth2.Config{ClientID: "test"},
		keyring,
		opts...)
	if err != nil {
		t.Fatalf("create auth: %v", err)
	}

	return auth
}

// newTestProvider returns a provider whose token endpoint is served by
// handler, so that a test can watch the refresh exchange happen.
func newTestProvider(t *testing.T, handler http.HandlerFunc) *oidc.Provider {
	t.Helper()

	server := httptest.NewServer(handler)

	t.Cleanup(server.Close)

	conf := oidc.ProviderConfig{
		IssuerURL: server.URL,
		AuthURL:   server.URL + "/auth",
		TokenURL:  server.URL + "/token",
		JWKSURL:   server.URL + "/jwks",
	}

	return conf.NewProvider(context.Background())
}

// tokenResponse answers a refresh the way a provider's token endpoint
// does. The lifetime is the caller's, so that a test can hand back a token
// that is itself due for refresh.
func tokenResponse(t *testing.T, expiresIn int) http.HandlerFunc {
	t.Helper()

	return tokenResponseFields(t, map[string]any{
		"access_token":  "new-access",
		"token_type":    "Bearer",
		"refresh_token": "new-refresh",
		"expires_in":    expiresIn,
	})
}

// tokenResponseFields answers with exactly the fields it is handed, for the
// cases where what a provider leaves out is the point of the test.
func tokenResponseFields(
	t *testing.T, fields map[string]any,
) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := json.Marshal(fields)
		if err != nil {
			t.Errorf("marshal token response: %v", err)

			return
		}

		_, err = w.Write(body)
		if err != nil {
			t.Errorf("write token response: %v", err)
		}
	}
}

// quietLogs keeps the rejection lines a test provokes on purpose out of the
// test output.
func quietLogs(t *testing.T) {
	t.Helper()

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.DiscardHandler))

	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
}

func testToken(expiry time.Time) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  "access",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       expiry,
	}
}

// sealTestSession returns the session cookie value auth would write for a
// session with these tokens and this issued_at.
func sealTestSession(
	t *testing.T, auth *OIDCAuth, token *oauth2.Token, issuedAt time.Time,
) string {
	t.Helper()

	w := httptest.NewRecorder()

	err := auth.setTokenCookie(w, token, issuedAt)
	if err != nil {
		t.Fatalf("seal session cookie: %v", err)
	}

	cookies := setCookies(w, auth.cookieName)
	if len(cookies) != 1 {
		t.Fatalf("got %d session cookies, want 1", len(cookies))
	}

	return cookies[0].Value
}

// openTestSession opens a sealed session cookie value the way
// readTokenCookie does, without the request plumbing.
func openTestSession(
	t *testing.T, auth *OIDCAuth, value string,
) (payload sessionPayload, current bool) {
	t.Helper()

	plaintext, current, err := auth.keyring.open(auth.sessionDomain, value)
	if err != nil {
		t.Fatalf("open session cookie: %v", err)
	}

	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		t.Fatalf("unmarshal session payload: %v", err)
	}

	return payload, current
}

func requestWithSession(auth *OIDCAuth, value string) *http.Request {
	r := httptest.NewRequest("GET", "/things/", nil)

	r.AddCookie(&http.Cookie{Name: auth.cookieName, Value: value})

	return r
}

// setCookies returns every cookie of the given name the response sets, in
// the order they were written. The count is the interesting part: the
// session cookie must be written at most once per response, whichever path
// the request took.
func setCookies(w *httptest.ResponseRecorder, name string) []*http.Cookie {
	var found []*http.Cookie

	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			found = append(found, c)
		}
	}

	return found
}

func TestNewOIDCAuthErrors(t *testing.T) {
	provider := &oidc.Provider{}
	keyring := newTestAuthKeyring(t)

	tests := []struct {
		name    string
		keyring *CookieKeyring
		opts    []OIDCAuthOption
		want    string
	}{
		{
			name:    "without a keyring",
			keyring: nil,
			want:    "cookie keyring is required",
		},
		{
			name:    "with a colon in the cookie name",
			keyring: keyring,
			opts: []OIDCAuthOption{
				WithSessionCookieName("auth_redir:sess"),
			},
			want: "not a valid cookie name",
		},
		{
			name:    "with an empty cookie name",
			keyring: keyring,
			opts:    []OIDCAuthOption{WithSessionCookieName("")},
			want:    "not a valid cookie name",
		},
		{
			name:    "with a zero session age",
			keyring: keyring,
			opts:    []OIDCAuthOption{WithMaxSessionAge(0)},
			want:    "must be positive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, err := NewOIDCAuth(
				provider,
				provider.Verifier(&oidc.Config{ClientID: "test"}),
				oauth2.Config{ClientID: "test"},
				test.keyring,
				test.opts...)
			if err == nil {
				t.Fatalf("got auth %v, want an error", auth)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q does not mention %q",
					err.Error(), test.want)
			}
		})
	}
}

// TestSessionCookieIsSealed is the whole point of the exercise: the refresh
// token must not be readable by anyone holding the cookie value.
func TestSessionCookieIsSealed(t *testing.T) {
	auth := newTestAuth(t)

	token := testToken(time.Now().Add(time.Hour))
	token.RefreshToken = "the-refresh-token"

	value := sealTestSession(t, auth, token, time.Now())

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode cookie value: %v", err)
	}

	if bytes.Contains(raw, []byte("the-refresh-token")) {
		t.Error("the refresh token is readable in the cookie value")
	}

	r := requestWithSession(auth, value)
	w := httptest.NewRecorder()

	session, err := auth.readTokenCookie(w, r)
	if err != nil {
		t.Fatalf("read the session cookie back: %v", err)
	}

	if session.token.RefreshToken != "the-refresh-token" {
		t.Errorf("refresh token = %q, want %q",
			session.token.RefreshToken, "the-refresh-token")
	}

	if session.stale {
		t.Error("a freshly sealed cookie was reported as stale")
	}

	// Reading is not a write. The one-Set-Cookie invariant depends on
	// the read path leaving the response alone.
	if got := setCookies(w, auth.cookieName); len(got) != 0 {
		t.Errorf("reading the cookie wrote %d cookies, want 0", len(got))
	}
}

// TestRequireAuthRejectsLegacyPlaintextCookie covers the rollout: browsers
// hold cookies from before sealing, and those are unset rather than
// migrated.
func TestRequireAuthRejectsLegacyPlaintextCookie(t *testing.T) {
	quietLogs(t)

	auth := newTestAuth(t)

	// Exactly what howdah wrote before the cookie was sealed: base64url
	// of the bare token JSON.
	data, err := json.Marshal(testToken(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("marshal legacy token: %v", err)
	}

	legacy := base64.RawURLEncoding.EncodeToString(data)

	r := requestWithSession(auth, legacy)
	w := httptest.NewRecorder()

	_, err = auth.RequireAuth(context.Background(), w, r)
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	if w.Code != http.StatusFound {
		t.Errorf("got status %d, want %d", w.Code, http.StatusFound)
	}

	if loc := w.Header().Get("Location"); !strings.HasPrefix(
		loc, "/auth/login?") {
		t.Errorf("redirect location = %q, want the login page", loc)
	}

	cookies := setCookies(w, auth.cookieName)
	if len(cookies) != 1 {
		t.Fatalf("got %d session cookies, want 1 clearing it",
			len(cookies))
	}

	if cookies[0].Value != "" {
		t.Errorf("cookie value = %q, want it cleared", cookies[0].Value)
	}
}

// TestSessionCookieReSealedUnderCurrentKey covers the migration a key
// rollover depends on, and the invariant that keeps it honest: exactly one
// Set-Cookie for the session on any response. Two would mean the read path
// and the refresh path are both writing.
func TestSessionCookieReSealedUnderCurrentKey(t *testing.T) {
	retiring := CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(1),
	}

	current := CookieKey{
		UseAfter: testTime(t, "2021-01-01T00:00:00Z"),
		Secret:   testCookieSecret(2),
	}

	issuedAt := time.Now().Add(-time.Minute)

	tests := []struct {
		name   string
		expiry time.Time
	}{
		// Nothing to refresh, so the re-seal is the only write.
		{name: "fresh token", expiry: time.Now().Add(time.Hour)},
		// The refresh writes the cookie, so the re-seal must not.
		{name: "expired token", expiry: time.Now().Add(-time.Minute)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newTestProvider(t, tokenResponse(t, 300))

			before := newTestAuthWith(t, provider,
				newTestKeyring(t, retiring))
			auth := newTestAuthWith(t, provider,
				newTestKeyring(t, retiring, current))

			value := sealTestSession(t, before,
				testToken(test.expiry), issuedAt)

			r := requestWithSession(auth, value)
			w := httptest.NewRecorder()

			auth.Keepalive(w, r)

			if w.Code != http.StatusNoContent {
				t.Fatalf("got status %d, want %d",
					w.Code, http.StatusNoContent)
			}

			cookies := setCookies(w, auth.cookieName)
			if len(cookies) != 1 {
				t.Fatalf("got %d session cookies, want exactly 1",
					len(cookies))
			}

			payload, isCurrent := openTestSession(
				t, auth, cookies[0].Value)
			if !isCurrent {
				t.Error("the cookie was not re-sealed under the current key")
			}

			if !payload.IssuedAt.Equal(issuedAt) {
				t.Errorf("issued_at = %s, want %s",
					payload.IssuedAt, issuedAt)
			}
		})
	}
}

// TestSessionMaxAge pins the server-side session lifetime. A cookie's
// Expires is an instruction to the browser; the sealed issued_at is the
// only part of this a copied cookie value cannot ignore.
func TestSessionMaxAge(t *testing.T) {
	quietLogs(t)

	auth := newTestAuth(t, WithMaxSessionAge(time.Hour))

	// The access token is nowhere near expiry in either case, so the age
	// of the session is the only thing that can end it.
	token := testToken(time.Now().Add(time.Hour))

	inside := sealTestSession(t, auth, token, time.Now().Add(-30*time.Minute))
	outside := sealTestSession(t, auth, token, time.Now().Add(-2*time.Hour))

	w := httptest.NewRecorder()

	_, err := auth.readTokenCookie(w, requestWithSession(auth, inside))
	if err != nil {
		t.Errorf("a session inside the maximum age was rejected: %v", err)
	}

	w = httptest.NewRecorder()

	_, err = auth.readTokenCookie(w, requestWithSession(auth, outside))
	if err == nil {
		t.Fatal("a session past the maximum age was accepted")
	}

	cookies := setCookies(w, auth.cookieName)
	if len(cookies) != 1 {
		t.Fatalf("got %d session cookies, want 1 clearing it",
			len(cookies))
	}

	if cookies[0].Value != "" {
		t.Errorf("cookie value = %q, want it cleared", cookies[0].Value)
	}
}

// TestIssuedAtSurvivesEveryRefresh is the test the session age cap rests
// on. Restart the issued_at on a refresh and the cap slides forward every
// few minutes, which is to say it enforces nothing — and nothing else in
// the suite would notice.
func TestIssuedAtSurvivesEveryRefresh(t *testing.T) {
	// A token that is already due for refresh when it arrives, so that
	// every round trip through Keepalive refreshes again.
	provider := newTestProvider(t, tokenResponse(t, 1))
	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t))

	issuedAt := time.Now().Add(-time.Hour)

	value := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)), issuedAt)

	for round := range 3 {
		r := requestWithSession(auth, value)
		w := httptest.NewRecorder()

		auth.Keepalive(w, r)

		if w.Code != http.StatusNoContent {
			t.Fatalf("round %d: got status %d, want %d",
				round+1, w.Code, http.StatusNoContent)
		}

		cookies := setCookies(w, auth.cookieName)
		if len(cookies) != 1 {
			t.Fatalf("round %d: got %d session cookies, want exactly 1",
				round+1, len(cookies))
		}

		payload, _ := openTestSession(t, auth, cookies[0].Value)

		if !payload.IssuedAt.Equal(issuedAt) {
			t.Fatalf("round %d: issued_at = %s, want %s",
				round+1, payload.IssuedAt, issuedAt)
		}

		if payload.Token.AccessToken != "new-access" {
			t.Fatalf("round %d: access token = %q, want %q",
				round+1, payload.Token.AccessToken, "new-access")
		}

		// The next round starts from the cookie this one wrote, which
		// is where a reset issued_at would show up.
		value = cookies[0].Value
	}
}

// TestRefreshKeepsTheRefreshTokenTheProviderOmits covers RFC 6749 §6: the
// refresh_token field is optional in the answer to a refresh_token grant,
// and a provider that leaves it out means "keep using the one you have".
// x/oauth2 guards this above the round trip token.go copied, so dropping the
// guard drops the session's refresh token into the cookie as an empty
// string — and the next refresh posts nothing, comes back invalid_grant, and
// logs every user out one access token lifetime after they logged in.
func TestRefreshKeepsTheRefreshTokenTheProviderOmits(t *testing.T) {
	// A lifetime shorter than the refresh margin, so that each round trip
	// refreshes again and the second one shows what the first one stored.
	answer := tokenResponseFields(t, map[string]any{
		"access_token": "new-access",
		"token_type":   "Bearer",
		"expires_in":   1,
	})

	var (
		mu     sync.Mutex
		posted []string
	)

	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posted = append(posted, r.PostFormValue("refresh_token"))
		mu.Unlock()

		answer(w, r)
	})

	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t))

	value := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)), time.Now().Add(-time.Minute))

	for round := range 2 {
		r := requestWithSession(auth, value)
		w := httptest.NewRecorder()

		auth.Keepalive(w, r)

		if w.Code != http.StatusNoContent {
			t.Fatalf("round %d: got status %d, want %d",
				round+1, w.Code, http.StatusNoContent)
		}

		cookies := setCookies(w, auth.cookieName)
		if len(cookies) != 1 {
			t.Fatalf("round %d: got %d session cookies, want exactly 1",
				round+1, len(cookies))
		}

		payload, _ := openTestSession(t, auth, cookies[0].Value)

		if payload.Token.RefreshToken != "refresh" {
			t.Fatalf("round %d: refresh token = %q, want the session's own %q",
				round+1, payload.Token.RefreshToken, "refresh")
		}

		value = cookies[0].Value
	}

	mu.Lock()
	defer mu.Unlock()

	if len(posted) != 2 {
		t.Fatalf("the token endpoint was called %d times, want 2",
			len(posted))
	}

	for i, got := range posted {
		if got != "refresh" {
			t.Errorf("exchange %d posted refresh_token=%q, want %q",
				i+1, got, "refresh")
		}
	}
}

// TestRefreshWithoutExpiresIn covers the other optional field. An
// oauth2.Token that arrives without an expires_in carries the zero Expiry,
// which the refresh margin reads as an access token that expired an eternity
// ago: every request would refresh and rewrite the session cookie, forever.
func TestRefreshWithoutExpiresIn(t *testing.T) {
	// The assumed lifetime is warned about, once per exchange.
	quietLogs(t)

	var exchanges atomic.Int64

	answer := tokenResponseFields(t, map[string]any{
		"access_token":  "new-access",
		"token_type":    "Bearer",
		"refresh_token": "new-refresh",
	})

	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)

		answer(w, r)
	})

	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t))

	value := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)), time.Now().Add(-time.Minute))

	for round := range 2 {
		r := requestWithSession(auth, value)
		w := httptest.NewRecorder()

		auth.Keepalive(w, r)

		if w.Code != http.StatusNoContent {
			t.Fatalf("round %d: got status %d, want %d",
				round+1, w.Code, http.StatusNoContent)
		}

		cookies := setCookies(w, auth.cookieName)

		if round > 0 {
			// The second request finds an access token with a usable
			// expiry, so it neither exchanges nor writes.
			if len(cookies) != 0 {
				t.Errorf("the second request rewrote the session cookie %d times, want 0",
					len(cookies))
			}

			continue
		}

		if len(cookies) != 1 {
			t.Fatalf("got %d session cookies, want exactly 1",
				len(cookies))
		}

		payload, _ := openTestSession(t, auth, cookies[0].Value)

		if !payload.Token.Expiry.After(time.Now().Add(tokenRefreshMargin)) {
			t.Fatalf("the refreshed token expires at %s, which is inside the refresh margin",
				payload.Token.Expiry)
		}

		value = cookies[0].Value
	}

	if got := exchanges.Load(); got != 1 {
		t.Errorf("the token endpoint was called %d times, want exactly 1",
			got)
	}
}

// TestSessionPayloadGolden pins the session payload's JSON as the wire
// contract the comment on sessionPayload claims it is. Every other test in
// the suite seals and opens through the same code, so renaming a json tag
// keeps them all green while every outstanding cookie in the fleet
// unmarshals with a zero issued_at — which readTokenCookie reads as a
// session past its maximum age, so one deploy logs everybody out at once.
//
// Both halves are pinned deliberately: the literal JSON says what the tags
// are, and the sealed fixture says that the whole chain — domain, envelope,
// payload — still opens what a v0.2.0 build wrote. A deliberate change to
// either needs a new sessionPayload version, not a new fixture.
func TestSessionPayloadGolden(t *testing.T) {
	const (
		goldenJSON = `{"v":1,"issued_at":"2026-08-01T09:30:00Z",` +
			`"token":{"access_token":"the-access-token",` +
			`"token_type":"Bearer","refresh_token":"the-refresh-token",` +
			`"expiry":"2026-08-01T10:30:00Z"}}`

		// The same payload sealed with testCookieSecret(1) under the
		// domain "cookie:token", which is what an application on the
		// default session cookie name writes.
		goldenCookie = "AQGGlmPBLAll_VopzT2_JTFxD7FPNxTzKfrTOVdzUrMvhf6DXov" +
			"xaS5gFmWEDFCOLUogwP0qwDjxOiKqjRZQYToGHFafcxKTY6MEYlTtNvVz1m" +
			"3ARrHaVVw0Jt6mgm-hAYTXsW1n8HHt2blt8wOPUY0OJz0wh0tsYMccxXyMu" +
			"dsfHCyZWhDU3Vyf-RUpMsMuMIIcAAfUWRTehbdyePXoS4DqJafs_2u3G-eR" +
			"yaPg7LAEVM0D9yjaGG3XvZO6VDkzsatRBMWELdUP24nj98n1uipaT49oGQ"
	)

	issuedAt := testTime(t, "2026-08-01T09:30:00Z")
	expiry := testTime(t, "2026-08-01T10:30:00Z")

	data, err := json.Marshal(sessionPayload{
		Version:  sessionPayloadV1,
		IssuedAt: issuedAt,
		Token: &oauth2.Token{
			AccessToken:  "the-access-token",
			TokenType:    "Bearer",
			RefreshToken: "the-refresh-token",
			Expiry:       expiry,
		},
	})
	if err != nil {
		t.Fatalf("marshal the session payload: %v", err)
	}

	if string(data) != goldenJSON {
		t.Errorf("the session payload marshals as\n\t%s\nwant\n\t%s",
			data, goldenJSON)
	}

	auth := newTestAuth(t)

	plaintext, current, err := auth.keyring.open(
		auth.sessionDomain, goldenCookie)
	if err != nil {
		t.Fatalf("open the golden session cookie: %v\n"+
			"The sealed session payload is a wire contract. If this is a"+
			" deliberate change it needs a new payload version, not a new"+
			" fixture.", err)
	}

	var payload sessionPayload

	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		t.Fatalf("unmarshal the golden session payload: %v", err)
	}

	if payload.Version != sessionPayloadV1 {
		t.Errorf("payload version = %d, want %d",
			payload.Version, sessionPayloadV1)
	}

	if !payload.IssuedAt.Equal(issuedAt) {
		t.Errorf("issued_at = %s, want %s", payload.IssuedAt, issuedAt)
	}

	if payload.Token == nil {
		t.Fatal("the golden payload carries no token")
	}

	if payload.Token.AccessToken != "the-access-token" {
		t.Errorf("access token = %q, want %q",
			payload.Token.AccessToken, "the-access-token")
	}

	if payload.Token.RefreshToken != "the-refresh-token" {
		t.Errorf("refresh token = %q, want %q",
			payload.Token.RefreshToken, "the-refresh-token")
	}

	if !payload.Token.Expiry.Equal(expiry) {
		t.Errorf("token expiry = %s, want %s", payload.Token.Expiry, expiry)
	}

	if !current {
		t.Error("the golden session cookie is not current")
	}
}

// TestRefreshDeduplication is the concurrency case: the several XHRs of one
// page load, plus the keepalive, all find the access token expired at the
// same moment. They must collapse onto one exchange — wasteful otherwise,
// and a mid-session logout for every loser once the realm rotates refresh
// tokens.
func TestRefreshDeduplication(t *testing.T) {
	const goroutines = 8

	var exchanges atomic.Int64

	release := make(chan struct{})

	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)

		// Hold the exchange open until every goroutine has had time to
		// reach the singleflight group.
		<-release

		tokenResponse(t, 300)(w, r)
	})

	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t))

	issuedAt := time.Now().Add(-time.Minute)

	value := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)), issuedAt)

	var (
		wg      sync.WaitGroup
		arrived sync.WaitGroup
		tokens  = make([]*oauth2.Token, goroutines)
		cookies = make([]int, goroutines)
	)

	arrived.Add(goroutines)

	for i := range goroutines {
		wg.Go(func() {
			r := requestWithSession(auth, value)
			w := httptest.NewRecorder()

			session, err := auth.readTokenCookie(w, r)

			// Counted here rather than after the error check, so that a
			// failed read cannot leave the exchange held open forever.
			arrived.Done()

			if err != nil {
				t.Errorf("goroutine %d: read session cookie: %v", i, err)

				return
			}

			token, ok := auth.checkTokenExpiry(w, r, session)
			if !ok {
				t.Errorf("goroutine %d: refresh failed", i)

				return
			}

			tokens[i] = token
			cookies[i] = len(setCookies(w, auth.cookieName))
		})
	}

	// Every goroutine is now one call away from the refresh group, so the
	// assertion no longer rests on all of them being scheduled inside a
	// sleep: a loaded machine would otherwise let a late arrival start a
	// second flight after the winner's had already completed, and the test
	// would go red on a deduplication that works. The sleep is what is left
	// of the wide overlap singleflight's own tests arrange, and nothing
	// depends on its length.
	arrived.Wait()

	time.Sleep(100 * time.Millisecond)

	close(release)

	wg.Wait()

	if got := exchanges.Load(); got != 1 {
		t.Errorf("the token endpoint was called %d times, want exactly 1",
			got)
	}

	for i, token := range tokens {
		if token == nil {
			continue
		}

		if token.AccessToken != "new-access" {
			t.Errorf("goroutine %d: access token = %q, want %q",
				i, token.AccessToken, "new-access")
		}

		if cookies[i] != 1 {
			t.Errorf("goroutine %d: got %d session cookies, want exactly 1",
				i, cookies[i])
		}
	}
}

// TestKeepaliveClearsCookieOnRefreshFailure covers the standing 401 loop: a
// cookie whose refresh token the provider will not honour is dead, but the
// browser has no way of knowing that and re-sends it on every keepalive.
func TestKeepaliveClearsCookieOnRefreshFailure(t *testing.T) {
	quietLogs(t)

	provider := newTestProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`,
			http.StatusBadRequest)
	})

	auth := newTestAuthWith(t, provider, newTestAuthKeyring(t))

	value := sealTestSession(t, auth,
		testToken(time.Now().Add(-time.Minute)), time.Now().Add(-time.Minute))

	r := requestWithSession(auth, value)
	w := httptest.NewRecorder()

	auth.Keepalive(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d",
			w.Code, http.StatusUnauthorized)
	}

	cookies := setCookies(w, auth.cookieName)
	if len(cookies) != 1 {
		t.Fatalf("got %d session cookies, want 1 clearing the dead session",
			len(cookies))
	}

	if cookies[0].Value != "" {
		t.Errorf("cookie value = %q, want it cleared", cookies[0].Value)
	}
}

// TestAuthRedirectCookieSealing covers the split: auth_redir is sealed
// because it is a path the application acts on, while state and nonce are
// deliberately left in the clear.
func TestAuthRedirectCookieSealing(t *testing.T) {
	quietLogs(t)

	auth := newTestAuth(t)

	r := httptest.NewRequest("POST", "/auth/login?redirect=/config/", nil)
	w := httptest.NewRecorder()

	_, err := auth.authRedirect(context.Background(), w, r)
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	byName := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		byName[c.Name] = c
	}

	redir, ok := byName[authRedirCookieName]
	if !ok {
		t.Fatalf("missing %q cookie", authRedirCookieName)
	}

	if strings.Contains(redir.Value, "/config/") {
		t.Errorf("the redirect target is readable in %q", redir.Value)
	}

	// state and nonce are random values compared against what the
	// provider echoes back, so they carry no integrity of their own to
	// protect. Pinned here so that "why isn't this sealed too" has an
	// answer in the suite as well as in the comment.
	for _, name := range []string{"state", "nonce"} {
		c, ok := byName[name]
		if !ok {
			t.Errorf("missing %q cookie", name)

			continue
		}

		_, _, err := auth.keyring.open(auth.sessionDomain, c.Value)
		if !errors.Is(err, ErrNotSealed) {
			t.Errorf("opening the %q cookie gave %v, want ErrNotSealed",
				name, err)
		}
	}

	back := httptest.NewRequest("GET", "/auth/callback", nil)

	back.AddCookie(&http.Cookie{
		Name:  authRedirCookieName,
		Value: redir.Value,
	})

	target, ok := auth.readAuthRedirCookie(back)
	if !ok {
		t.Fatal("the sealed redirect cookie did not open")
	}

	if target != "/config/" {
		t.Errorf("redirect target = %q, want %q", target, "/config/")
	}

	// A co-hosted application sharing the keyring must not be able to
	// supply our redirect target, which is what binding the value to the
	// session cookie name buys.
	other := newTestAuthWith(t, &oidc.Provider{}, auth.keyring,
		WithSessionCookieName("other_token"))

	_, ok = other.readAuthRedirCookie(back)
	if ok {
		t.Error("a co-hosted application opened our redirect cookie")
	}
}

// TestAuthRedirectCookieClearedWithoutATarget covers the abandoned login. A
// target sealed for an attempt the user walked away from stays in the
// browser for the hour the cookie lives, so a later login started from the
// login page — which carries no target of its own — would land them wherever
// the abandoned attempt was headed.
func TestAuthRedirectCookieClearedWithoutATarget(t *testing.T) {
	auth := newTestAuth(t)

	// The visitor asked for a page, RequireAuth sent them to the login page
	// with it, and the login sealed it into the cookie.
	w := httptest.NewRecorder()

	_, err := auth.authRedirect(context.Background(), w,
		httptest.NewRequest("POST", "/auth/login?redirect=/reports/", nil))
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	if abandoned := responseCookie(
		t, w, authRedirCookieName); abandoned.Value == "" {
		t.Fatal("the login set no redirect target")
	}

	// They abandoned the login at the provider, and log in from the login
	// page later, so this attempt carries no target of its own.
	w = httptest.NewRecorder()

	_, err = auth.authRedirect(context.Background(), w,
		httptest.NewRequest("POST", "/auth/login", nil))
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	cleared := responseCookie(t, w, authRedirCookieName)

	if cleared.Value != "" {
		t.Errorf("redirect cookie value = %q, want it cleared",
			cleared.Value)
	}

	if cleared.MaxAge != -1 {
		t.Errorf("the cleared redirect cookie has Max-Age %d, want -1",
			cleared.MaxAge)
	}
}

// TestAuthCallbackClearsTheCallbackCookies is the other half: the callback
// cookies belong to one login attempt, and the callback ends the attempt
// whether or not it succeeds. Left behind, the redirect target hijacks the
// landing page of the next login and state and nonce outlive the exchange
// they were minted for.
func TestAuthCallbackClearsTheCallbackCookies(t *testing.T) {
	quietLogs(t)

	auth := newTestAuth(t)

	start := httptest.NewRecorder()

	_, err := auth.authRedirect(context.Background(), start,
		httptest.NewRequest("POST", "/auth/login?redirect=/reports/", nil))
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	// A state that does not match is both the cheapest way into the
	// consuming path — everything past it needs a live provider — and the
	// case that matters, since an attempt that fails must not leave its
	// cookies behind either.
	r := httptest.NewRequest("GET", "/auth/callback?state=somebody-elses", nil)

	for _, c := range start.Result().Cookies() {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}

	w := httptest.NewRecorder()

	_, err = auth.authCallback(context.Background(), w, r)
	if err == nil {
		t.Fatal("expected a mismatched state to fail the callback")
	}

	for _, name := range []string{"state", "nonce", authRedirCookieName} {
		c := responseCookie(t, w, name)

		if c.Value != "" {
			t.Errorf("the %q cookie has value %q, want it cleared",
				name, c.Value)
		}

		if c.MaxAge != -1 {
			t.Errorf("the cleared %q cookie has Max-Age %d, want -1",
				name, c.MaxAge)
		}
	}
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

// TestCallbackFailureRedirectsToLogin covers the trap that made a real
// failure look permanent: an error page rendered at the callback URL is one a
// reload re-submits, and a provider asked twice about the same authorization
// code answers "code not valid", replacing the real reason with a misleading
// one. The failure has to leave the code behind.
func TestCallbackFailureRedirectsToLogin(t *testing.T) {
	quietLogs(t)

	for _, c := range []struct {
		name  string
		query string
		state string
	}{
		{"no state cookie", "?code=abc&state=xyz", ""},
		{"state did not match", "?code=abc&state=wrong", "xyz"},
	} {
		t.Run(c.name, func(t *testing.T) {
			auth := newTestAuth(t)

			r := httptest.NewRequest(http.MethodGet, "/auth/callback"+c.query, nil)
			if c.state != "" {
				r.AddCookie(&http.Cookie{Name: "state", Value: c.state})
				r.AddCookie(&http.Cookie{Name: "nonce", Value: "n"})
			}

			w := httptest.NewRecorder()

			_, err := auth.authCallback(context.Background(), w, r)
			if !errors.Is(err, ErrSkipRender) {
				t.Fatalf("got error %v, want ErrSkipRender", err)
			}

			if w.Code != http.StatusFound {
				t.Fatalf("got status %d, want a redirect", w.Code)
			}

			loc := w.Header().Get("Location")

			if !strings.HasPrefix(loc, "/auth/login?") {
				t.Errorf("redirect = %q, want the login page", loc)
			}

			// The code must not survive into the URL the visitor lands on,
			// or reloading that page re-submits it.
			if strings.Contains(loc, "code=") {
				t.Errorf("redirect %q still carries the authorization code", loc)
			}

			if !strings.Contains(loc, loginFailedParam+"=1") {
				t.Errorf("redirect %q does not mark the login as failed", loc)
			}
		})
	}
}

// TestLoginPageReportsAFailedAttempt checks that the flag reaches the
// template, so an application can say something rather than silently
// re-showing the login button.
func TestLoginPageReportsAFailedAttempt(t *testing.T) {
	auth := newTestAuth(t)

	plain, err := auth.authLogin(context.Background(), httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if err != nil {
		t.Fatalf("login page: %v", err)
	}

	if c, ok := plain.Contents.(LoginPage); !ok || c.Failed {
		t.Errorf("a plain login page reports Failed=%v, want false", c.Failed)
	}

	failed, err := auth.authLogin(context.Background(), httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet,
			"/auth/login?"+loginFailedParam+"=1", nil))
	if err != nil {
		t.Fatalf("login page after a failure: %v", err)
	}

	if c, ok := failed.Contents.(LoginPage); !ok || !c.Failed {
		t.Errorf("login page after a failure reports Failed=%v, want true",
			c.Failed)
	}
}
