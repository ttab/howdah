package howdah

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func newTestCookieStore(
	t *testing.T, keys ...CookieKey,
) *CookieTokenStore {
	t.Helper()

	if len(keys) == 0 {
		keys = []CookieKey{{
			UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
			Secret:   testCookieSecret(1),
		}}
	}

	store, err := NewCookieTokenStore(
		newTestKeyring(t, keys...), "token", time.Hour)
	if err != nil {
		t.Fatalf("create the cookie token store: %v", err)
	}

	return store
}

func TestNewCookieTokenStoreErrors(t *testing.T) {
	keyring := newTestAuthKeyring(t)

	tests := []struct {
		name    string
		keyring *CookieKeyring
		cookie  string
		maxAge  time.Duration
		want    string
	}{
		{
			name:   "without a keyring",
			cookie: "token",
			maxAge: time.Hour,
			want:   "cookie keyring is required",
		},
		{
			name:    "with a colon in the cookie name",
			keyring: keyring,
			cookie:  "auth_redir:sess",
			maxAge:  time.Hour,
			want:    "not a valid cookie name",
		},
		{
			name:    "with a zero session age",
			keyring: keyring,
			cookie:  "token",
			want:    "must be positive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewCookieTokenStore(
				test.keyring, test.cookie, test.maxAge)
			if err == nil {
				t.Fatalf("got store %v, want an error", store)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q does not mention %q",
					err.Error(), test.want)
			}
		})
	}
}

// TestCookieTokenStoreRoundTrip covers the store's own contract: what Create
// returns, Get gives back.
func TestCookieTokenStoreRoundTrip(t *testing.T) {
	store := newTestCookieStore(t)
	ctx := t.Context()

	token := testToken(time.Now().Add(time.Hour))

	created, err := store.Create(ctx, NewSession{
		Subject: "the-subject",
		Token:   token,
		IDToken: "the.id.token",
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	if created.Handle == "" {
		t.Fatal("the created session has no handle")
	}

	if created.Subject != "the-subject" {
		t.Errorf("subject = %q, want %q", created.Subject, "the-subject")
	}

	// The handle is the whole session, so there is nowhere to keep a
	// second JWT. This is the documented give-up, and a change of mind
	// about it is a change to what fits in a cookie.
	if created.IDToken != "" {
		t.Errorf("id token = %q, want it dropped", created.IDToken)
	}

	if want := created.IssuedAt.Add(time.Hour); !created.ExpiresAt.Equal(want) {
		t.Errorf("expires at %s, want %s", created.ExpiresAt, want)
	}

	got, err := store.Get(ctx, created.Handle)
	if err != nil {
		t.Fatalf("get the session: %v", err)
	}

	if got.Handle != created.Handle {
		t.Error("Get changed the handle it was given")
	}

	if got.Subject != "the-subject" {
		t.Errorf("subject = %q, want %q", got.Subject, "the-subject")
	}

	if got.Token.RefreshToken != token.RefreshToken {
		t.Errorf("refresh token = %q, want %q",
			got.Token.RefreshToken, token.RefreshToken)
	}

	if !got.IssuedAt.Equal(created.IssuedAt) {
		t.Errorf("issued at %s, want %s", got.IssuedAt, created.IssuedAt)
	}

	if got.Stale {
		t.Error("a freshly sealed session came back stale")
	}

	// Nothing is stored, so there is nothing to delete and nothing to
	// sweep. Both still have to answer without complaint.
	err = store.Delete(ctx, created.Handle)
	if err != nil {
		t.Errorf("delete the session: %v", err)
	}

	swept, err := store.DeleteExpired(ctx, 100)
	if err != nil {
		t.Errorf("delete expired sessions: %v", err)
	}

	if swept != 0 {
		t.Errorf("swept %d sessions, want 0", swept)
	}

	// Delete really is a no-op: the handle still opens.
	_, err = store.Get(ctx, created.Handle)
	if err != nil {
		t.Errorf("a store-less session survives Delete, got: %v", err)
	}
}

// TestCookieTokenStoreGetErrors pins the ErrNoSession contract, and that the
// reason survives alongside it — the read path picks the log level off
// ErrAuthentication, so a wrapper that swallowed it would silently mute the
// one row worth alerting on.
func TestCookieTokenStoreGetErrors(t *testing.T) {
	store := newTestCookieStore(t)
	ctx := t.Context()

	expired, err := store.seal(&StoredToken{
		Token:    testToken(time.Now().Add(time.Hour)),
		IssuedAt: time.Now().Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seal an expired session: %v", err)
	}

	other := newTestCookieStore(t, CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(9),
	})

	elsewhere, err := other.seal(&StoredToken{
		Token:    testToken(time.Now().Add(time.Hour)),
		IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("seal a session under another keyring: %v", err)
	}

	tests := []struct {
		name   string
		handle string
		is     error
	}{
		{name: "not sealed at all", handle: "nonsense", is: ErrNotSealed},
		{name: "past the absolute expiry", handle: expired.Handle},
		{
			name:   "sealed under a key we do not have",
			handle: elsewhere.Handle,
			is:     ErrUnknownKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.Get(ctx, test.handle)
			if !errors.Is(err, ErrNoSession) {
				t.Fatalf("got error %v, want it to wrap ErrNoSession", err)
			}

			if test.is != nil && !errors.Is(err, test.is) {
				t.Errorf("got error %v, want it to wrap %v", err, test.is)
			}
		})
	}
}

// TestCookieTokenStoreStale covers the key migration signal. A session
// sealed under a retiring key opens, comes back stale, and Reseal moves it to
// the current key without moving its issued_at.
func TestCookieTokenStoreStale(t *testing.T) {
	retiring := CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(1),
	}

	current := CookieKey{
		UseAfter: testTime(t, "2021-01-01T00:00:00Z"),
		Secret:   testCookieSecret(2),
	}

	before := newTestCookieStore(t, retiring)
	store := newTestCookieStore(t, retiring, current)

	ctx := t.Context()
	issuedAt := time.Now().Add(-time.Minute)

	old, err := before.seal(&StoredToken{
		Subject:  "the-subject",
		Token:    testToken(time.Now().Add(time.Hour)),
		IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("seal under the retiring key: %v", err)
	}

	session, err := store.Get(ctx, old.Handle)
	if err != nil {
		t.Fatalf("get a session sealed under the retiring key: %v", err)
	}

	if !session.Stale {
		t.Fatal("a session sealed under the retiring key is not stale")
	}

	resealed, err := store.Reseal(ctx, session)
	if err != nil {
		t.Fatalf("reseal the session: %v", err)
	}

	if resealed.Handle == session.Handle {
		t.Error("resealing did not change the handle")
	}

	if !resealed.IssuedAt.Equal(issuedAt) {
		t.Errorf("issued at %s, want %s carried forward",
			resealed.IssuedAt, issuedAt)
	}

	again, err := store.Get(ctx, resealed.Handle)
	if err != nil {
		t.Fatalf("get the resealed session: %v", err)
	}

	if again.Stale {
		t.Error("the resealed session is still stale")
	}

	if again.Subject != "the-subject" {
		t.Errorf("subject = %q, want it carried forward", again.Subject)
	}
}

// TestCookieTokenStoreUpdate covers the out-of-band token replacement, and
// that it carries the session forward rather than starting a new one.
func TestCookieTokenStoreUpdate(t *testing.T) {
	store := newTestCookieStore(t)
	ctx := t.Context()

	issuedAt := time.Now().Add(-time.Minute)

	session, err := store.seal(&StoredToken{
		Subject:  "the-subject",
		Token:    testToken(time.Now().Add(time.Hour)),
		IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("seal the session: %v", err)
	}

	replacement := &oauth2.Token{
		AccessToken:  "other-access",
		TokenType:    "Bearer",
		RefreshToken: "other-refresh",
		Expiry:       time.Now().Add(2 * time.Hour),
	}

	updated, err := store.Update(ctx, session.Handle, replacement)
	if err != nil {
		t.Fatalf("update the session: %v", err)
	}

	if !updated.IssuedAt.Equal(issuedAt) {
		t.Errorf("issued at %s, want %s carried forward",
			updated.IssuedAt, issuedAt)
	}

	got, err := store.Get(ctx, updated.Handle)
	if err != nil {
		t.Fatalf("get the updated session: %v", err)
	}

	if got.Token.AccessToken != "other-access" {
		t.Errorf("access token = %q, want %q",
			got.Token.AccessToken, "other-access")
	}

	if got.Subject != "the-subject" {
		t.Errorf("subject = %q, want it carried forward", got.Subject)
	}
}

// TestCookieTokenStoreRefreshDeduplication is the store's half of the
// concurrency case: the several requests of one page load collapse onto one
// exchange, and every one of them comes back with the same session rather
// than with whatever it managed to obtain for itself.
func TestCookieTokenStoreRefreshDeduplication(t *testing.T) {
	const goroutines = 8

	store := newTestCookieStore(t)
	ctx := t.Context()

	session, err := store.seal(&StoredToken{
		Token:    testToken(time.Now().Add(-time.Minute)),
		IssuedAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("seal the session: %v", err)
	}

	var exchanges atomic.Int64

	release := make(chan struct{})

	exchange := func(
		_ context.Context, tok *oauth2.Token,
	) (*oauth2.Token, error) {
		exchanges.Add(1)

		// Held open until every goroutine has reached the group, so the
		// assertion does not rest on the scheduler.
		<-release

		return &oauth2.Token{
			AccessToken:  "new-access",
			TokenType:    "Bearer",
			RefreshToken: tok.RefreshToken,
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}

	var (
		wg      sync.WaitGroup
		arrived sync.WaitGroup
		results = make([]*StoredToken, goroutines)
	)

	arrived.Add(goroutines)

	for i := range goroutines {
		wg.Go(func() {
			arrived.Done()

			refreshed, err := store.Refresh(ctx, session, exchange)
			if err != nil {
				t.Errorf("goroutine %d: refresh: %v", i, err)

				return
			}

			results[i] = refreshed
		})
	}

	arrived.Wait()

	time.Sleep(100 * time.Millisecond)

	close(release)

	wg.Wait()

	if got := exchanges.Load(); got != 1 {
		t.Errorf("the exchange ran %d times, want exactly 1", got)
	}

	for i, got := range results {
		if got == nil {
			continue
		}

		if got.Handle == session.Handle {
			t.Errorf("goroutine %d: the handle did not change", i)
		}

		if got.Token.AccessToken != "new-access" {
			t.Errorf("goroutine %d: access token = %q, want %q",
				i, got.Token.AccessToken, "new-access")
		}
	}
}

// TestCookieTokenStoreRefreshFailure covers the losers of a failed exchange:
// they get the winner's error rather than each trying their own.
func TestCookieTokenStoreRefreshFailure(t *testing.T) {
	store := newTestCookieStore(t)

	session, err := store.seal(&StoredToken{
		Token:    testToken(time.Now().Add(-time.Minute)),
		IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("seal the session: %v", err)
	}

	refused := errors.New("invalid_grant")

	_, err = store.Refresh(t.Context(), session,
		func(_ context.Context, _ *oauth2.Token) (*oauth2.Token, error) {
			return nil, refused
		})
	if !errors.Is(err, refused) {
		t.Errorf("got error %v, want it to wrap the provider's", err)
	}
}
