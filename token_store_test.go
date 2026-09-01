package howdah

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// stableHandleStore is a store shaped like the database-backed one: the
// handle identifies a row and does not change when the tokens do, so the
// only thing that moves it is a key rollover. It is here because that shape
// is what the Set-Cookie condition in checkTokenExpiry has to get right, and
// no cookie-backed store can exercise it — a store-less handle changes on
// every write, so the condition would look correct while being half of
// itself.
type stableHandleStore struct {
	mu      sync.Mutex
	session StoredToken
	deleted []string
	sealed  int
}

var _ TokenStore = (*stableHandleStore)(nil)

func (s *stableHandleStore) Create(
	_ context.Context, session NewSession,
) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.session = StoredToken{
		Handle:    "row-handle",
		Subject:   session.Subject,
		Token:     session.Token,
		IDToken:   session.IDToken,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	return s.get()
}

func (s *stableHandleStore) Get(
	_ context.Context, handle string,
) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if handle != s.session.Handle {
		return nil, ErrNoSession
	}

	return s.get()
}

func (s *stableHandleStore) get() (*StoredToken, error) {
	session := s.session

	return &session, nil
}

func (s *stableHandleStore) Update(
	_ context.Context, handle string, tok *oauth2.Token,
) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if handle != s.session.Handle {
		return nil, ErrNoSession
	}

	s.session.Token = tok

	return s.get()
}

// Reseal moves nothing but the envelope: the row is untouched, and the
// handle changes only because it is sealed again — under the current key,
// and with a fresh nonce, so the value is never the one that came in.
func (s *stableHandleStore) Reseal(
	_ context.Context, _ *StoredToken,
) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sealed++
	s.session.Stale = false
	s.session.Handle = fmt.Sprintf("row-handle-resealed-%d", s.sealed)

	return s.get()
}

func (s *stableHandleStore) Delete(_ context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleted = append(s.deleted, handle)

	return nil
}

func (s *stableHandleStore) Refresh(
	ctx context.Context, t *StoredToken,
	exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
) (*StoredToken, error) {
	tok, err := exchange(ctx, t.Token)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.session.Token = tok

	return s.get()
}

func (s *stableHandleStore) DeleteExpired(
	_ context.Context, _ int,
) (int64, error) {
	return 0, nil
}

// newStoreAuth wires an auth component up around a store of the
// application's own, the way WithTokenStore is meant to be used.
func newStoreAuth(
	t *testing.T, store TokenStore, opts ...OIDCAuthOption,
) *OIDCAuth {
	t.Helper()

	provider := newTestProvider(t, tokenResponse(t, 300))

	return newTestAuthWith(t, provider, newTestAuthKeyring(t),
		append(opts, WithTokenStore(store))...)
}

// TestStoredSessionRefreshWritesNoCookie is the seam. A store whose handle
// survives a refresh has nothing new to put in the cookie, so the response
// carries no Set-Cookie at all — and OIDCAuth reaches that outcome without
// knowing which store it is holding.
func TestStoredSessionRefreshWritesNoCookie(t *testing.T) {
	store := &stableHandleStore{
		session: StoredToken{
			Handle:    "row-handle",
			Token:     testToken(time.Now().Add(-time.Minute)),
			IssuedAt:  time.Now().Add(-time.Minute),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	auth := newStoreAuth(t, store)

	w := httptest.NewRecorder()

	auth.Keepalive(w, requestWithSession(auth, "row-handle"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusNoContent)
	}

	if got := setCookies(w, auth.cookieName); len(got) != 0 {
		t.Errorf("the refresh wrote %d session cookies, want 0", len(got))
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if store.session.Token.AccessToken != "new-access" {
		t.Errorf("the stored access token is %q, want %q",
			store.session.Token.AccessToken, "new-access")
	}
}

// TestStoredSessionStaleHandleIsResealed is the other half of the same
// condition, and the reason it cannot be "the handle changed" alone: a
// stored session's handle does not change, so a key rollover would never
// reach one.
func TestStoredSessionStaleHandleIsResealed(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
	}{
		// Nothing to refresh, so the re-seal is the only write.
		{name: "fresh token", expiry: time.Now().Add(time.Hour)},
		// The refresh writes the cookie, so the re-seal must not: the
		// one-Set-Cookie invariant holds for a stored session too.
		{name: "expired token", expiry: time.Now().Add(-time.Minute)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &stableHandleStore{
				session: StoredToken{
					Handle:    "row-handle",
					Token:     testToken(test.expiry),
					IssuedAt:  time.Now().Add(-time.Minute),
					ExpiresAt: time.Now().Add(time.Hour),
					Stale:     true,
				},
			}

			auth := newStoreAuth(t, store)

			w := httptest.NewRecorder()

			auth.Keepalive(w, requestWithSession(auth, "row-handle"))

			if w.Code != http.StatusNoContent {
				t.Fatalf("got status %d, want %d",
					w.Code, http.StatusNoContent)
			}

			cookies := setCookies(w, auth.cookieName)
			if len(cookies) != 1 {
				t.Fatalf("got %d session cookies, want exactly 1",
					len(cookies))
			}

			store.mu.Lock()
			defer store.mu.Unlock()

			if store.sealed != 1 {
				t.Errorf("the store re-sealed %d times, want exactly 1",
					store.sealed)
			}

			if cookies[0].Value != store.session.Handle {
				t.Errorf("cookie value = %q, want the re-sealed handle %q",
					cookies[0].Value, store.session.Handle)
			}
		})
	}
}

// TestStoredSessionLogoutDeletes covers what a store is for: logging out
// ends the session everywhere rather than in one browser.
func TestStoredSessionLogoutDeletes(t *testing.T) {
	store := &stableHandleStore{
		session: StoredToken{
			Handle:    "row-handle",
			Token:     testToken(time.Now().Add(time.Hour)),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	auth := newStoreAuth(t, store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)

	r.AddCookie(&http.Cookie{Name: auth.cookieName, Value: "row-handle"})

	_, err := auth.authLogout(r.Context(), w, r)
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.deleted) != 1 || store.deleted[0] != "row-handle" {
		t.Errorf("the store was asked to delete %v, want [row-handle]",
			store.deleted)
	}
}

// TestStoredSessionLogoutWithoutACookie covers the visitor who logs out
// twice: there is no handle to delete, and nothing may go wrong over it.
func TestStoredSessionLogoutWithoutACookie(t *testing.T) {
	store := &stableHandleStore{}
	auth := newStoreAuth(t, store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)

	_, err := auth.authLogout(r.Context(), w, r)
	if !errors.Is(err, ErrSkipRender) {
		t.Fatalf("got error %v, want ErrSkipRender", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.deleted) != 0 {
		t.Errorf("the store was asked to delete %v, want nothing",
			store.deleted)
	}
}

// TestWithTokenStoreRefusesMaxSessionAge covers the option that would
// otherwise do nothing. The session lifetime belongs to the store, so an
// application that sets both has a misunderstanding worth failing at
// startup rather than a cap that is quietly not applied.
func TestWithTokenStoreRefusesMaxSessionAge(t *testing.T) {
	provider := &oidc.Provider{}

	_, err := NewOIDCAuth(
		provider,
		provider.Verifier(&oidc.Config{ClientID: "test"}),
		oauth2.Config{ClientID: "test"},
		newTestAuthKeyring(t),
		WithTokenStore(&stableHandleStore{}),
		WithMaxSessionAge(time.Hour))
	if err == nil {
		t.Fatal("got an auth component, want an error")
	}

	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("error %q does not say the options conflict", err.Error())
	}
}

// TestDefaultStoreIsCookieBacked pins the default: an application that says
// nothing about storage gets the store-less session howdah has always
// written, so v0.3.0 is not an upgrade that logs anybody out.
func TestDefaultStoreIsCookieBacked(t *testing.T) {
	auth := newTestAuth(t)

	store, ok := auth.store.(*CookieTokenStore)
	if !ok {
		t.Fatalf("the default store is a %T, want a *CookieTokenStore",
			auth.store)
	}

	if store.maxSessionAge != DefaultMaxSessionAge {
		t.Errorf("the default store's session age is %s, want %s",
			store.maxSessionAge, DefaultMaxSessionAge)
	}

	if store.domain != auth.sessionDomain {
		t.Errorf("the default store seals for %q, want %q",
			store.domain, auth.sessionDomain)
	}
}

// brokenStore fails the way a store backed by something outside the process
// can fail, and lets each test say what kind of failure it is: one that means
// the session is over, or one that means the store could not answer.
type brokenStore struct {
	stableHandleStore

	getErr     error
	refreshErr error
	tokenless  bool
}

var _ TokenStore = (*brokenStore)(nil)

func (s *brokenStore) Get(
	ctx context.Context, handle string,
) (*StoredToken, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}

	return s.stableHandleStore.Get(ctx, handle)
}

func (s *brokenStore) Refresh(
	ctx context.Context, t *StoredToken,
	exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
) (*StoredToken, error) {
	if s.refreshErr != nil {
		return nil, s.refreshErr
	}

	if s.tokenless {
		// A store that answers with a session carrying no token at all.
		// pgstore refuses to write one; a store of the application's own
		// may hand one back, and everything downstream of here reads the
		// token without checking.
		return &StoredToken{
			Handle:    t.Handle,
			IssuedAt:  t.IssuedAt,
			ExpiresAt: t.ExpiresAt,
		}, nil
	}

	return s.stableHandleStore.Refresh(ctx, t, exchange)
}

// TestSessionSurvivesAStoreThatCannotAnswer is the split that only became
// real when the tokens moved into a store: which failures clear the session
// cookie and which leave it alone.
//
// A store-less session is the cookie, so every failure to use it was a
// failure of the session and clearing it cost nothing. A stored session is a
// row and the cookie is the only handle to it, so a cookie cleared over a
// two-second failover logs out every user whose access token happened to be
// inside the refresh margin and orphans their rows until the sweep. Only a
// session that really is over — unknown to the store, expired, or one the
// provider has refused to refresh — may take the cookie with it.
func TestSessionSurvivesAStoreThatCannotAnswer(t *testing.T) {
	quietLogs(t)

	tests := []struct {
		name string
		// store is built per caller, since each of them gets its own
		// request and response.
		store func() *brokenStore
		// gone says the session is over, so the cookie is cleared and
		// the user is sent to log in again.
		gone bool
	}{
		{
			name: "the store could not be read",
			store: func() *brokenStore {
				return &brokenStore{
					getErr: errors.New(
						"read the session row: dial tcp: connection refused"),
				}
			},
		},
		{
			name: "the handle is unknown to the store",
			store: func() *brokenStore {
				return &brokenStore{
					getErr: fmt.Errorf(
						"%w: unknown session handle", ErrNoSession),
				}
			},
			gone: true,
		},
		{
			name: "the wait for another caller's refresh ran out",
			store: func() *brokenStore {
				return &brokenStore{
					refreshErr: errors.New(
						"timed out waiting for a concurrent refresh"),
				}
			},
		},
		{
			name: "the provider refused the refresh",
			store: func() *brokenStore {
				return &brokenStore{
					refreshErr: fmt.Errorf(
						"%w: invalid_grant", ErrRefreshRejected),
				}
			},
			gone: true,
		},
		{
			// A store that answers without a token is a store with
			// a bug rather than a session that ended, and it is
			// treated as a session that ended anyway — the same way
			// a read that comes back token-less is. The reason is
			// what would otherwise happen: everything downstream
			// reads the token without checking, so the alternative
			// to a login redirect is a nil dereference in whichever
			// handler called RequireAuth. Retrying it is no better,
			// since the next request gets the same answer.
			name: "the refresh produced a session with no token",
			store: func() *brokenStore {
				return &brokenStore{tokenless: true}
			},
			gone: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("RequireAuth", func(t *testing.T) {
				store := test.store()
				auth := newStoreAuth(t, withBrokenSession(store))

				w := httptest.NewRecorder()
				r := requestWithSession(auth, "row-handle")

				_, err := auth.RequireAuth(r.Context(), w, r)

				if test.gone {
					if !errors.Is(err, ErrSkipRender) {
						t.Errorf("got error %v, want ErrSkipRender", err)
					}

					if w.Code != http.StatusFound {
						t.Errorf("got status %d, want %d",
							w.Code, http.StatusFound)
					}
				} else {
					httpErr := &HTTPError{}
					if !errors.As(err, &httpErr) {
						t.Fatalf("got error %v, want an HTTPError", err)
					}

					if httpErr.Code != http.StatusServiceUnavailable {
						t.Errorf("got the status %d, want %d",
							httpErr.Code,
							http.StatusServiceUnavailable)
					}
				}

				assertSessionCookie(t, w, auth, test.gone)
			})

			t.Run("Keepalive", func(t *testing.T) {
				store := test.store()
				auth := newStoreAuth(t, withBrokenSession(store))

				w := httptest.NewRecorder()

				auth.Keepalive(w, requestWithSession(auth, "row-handle"))

				want := http.StatusServiceUnavailable
				if test.gone {
					want = http.StatusUnauthorized
				}

				if w.Code != want {
					t.Errorf("got status %d, want %d", w.Code, want)
				}

				assertSessionCookie(t, w, auth, test.gone)
			})
		})
	}
}

// withBrokenSession gives the store a session whose access token is already
// past the refresh margin, so that a request reaches the refresh rather than
// stopping at the read.
func withBrokenSession(store *brokenStore) *brokenStore {
	store.session = StoredToken{
		Handle:    "row-handle",
		Token:     testToken(time.Now().Add(-time.Minute)),
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	return store
}

// assertSessionCookie checks whether the response cleared the session cookie,
// which is the whole point: a cleared cookie is the last handle to a stored
// session, so clearing one over a failure the next request would recover from
// is the bug.
func assertSessionCookie(
	t *testing.T, w *httptest.ResponseRecorder, auth *OIDCAuth, cleared bool,
) {
	t.Helper()

	cookies := setCookies(w, auth.cookieName)

	if !cleared {
		if len(cookies) != 0 {
			t.Errorf("the response wrote %d session cookies, want none: the session is still there and the cookie is the only handle to it",
				len(cookies))
		}

		return
	}

	if len(cookies) != 1 {
		t.Fatalf("got %d session cookies, want exactly 1 clearing the session",
			len(cookies))
	}

	if cookies[0].Value != "" {
		t.Errorf("the session cookie holds %q, want it cleared",
			cookies[0].Value)
	}
}
