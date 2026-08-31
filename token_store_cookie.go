package howdah

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// CookieTokenStore keeps nothing. It seals the whole session — the token
// set, the subject and the issued_at — into the cookie value, so the handle
// *is* the session and a new handle comes out of every write. It is what
// howdah did before there was a TokenStore at all, behind the interface and
// otherwise unchanged, and it is the right store for a small backoffice tool
// that should not need a database to have a login.
//
// What it cannot do, plainly:
//
//   - **It cannot revoke.** Delete is a no-op. Logout clears the cookie in
//     one browser, and a copied cookie value keeps working until the session
//     reaches its absolute expiry. You cannot revoke what you do not store.
//   - **It cannot serialise refresh across replicas.** Refresh collapses the
//     concurrent refreshes of one session onto one exchange within a single
//     process — the several XHRs of one page load, which is where most of
//     the duplication comes from — and there is no shared state for two
//     replicas to coordinate through. Two replicas serving the same session
//     inside the refresh margin can still both refresh. That is harmless
//     while the provider does not rotate refresh tokens, and an intermittent
//     mid-session logout once it does: turning rotation on fleet-wide is a
//     decision to move every application onto a stored session.
//   - **It cannot be swept.** There is no Rekey, because outstanding cookies
//     cannot be reached. A retired key has to stay in the keyring until
//     every session sealed under it has aged out.
//
// The absolute expiry it does enforce, from the sealed issued_at, which is
// what gives store-less key retirement a defined end.
type CookieTokenStore struct {
	keyring       *CookieKeyring
	domain        string
	maxSessionAge time.Duration

	// refresh collapses the concurrent refreshes of one session onto a
	// single token endpoint round trip. A page load that fires several
	// XHRs, plus the keepalive, otherwise posts the same refresh token
	// several times over: wasteful today, and a mid-session logout for
	// every loser the day the realm turns on refresh token rotation.
	// Collapsing them also settles which token wins the cookie, since
	// every caller gets the same one.
	refresh singleflight.Group
}

// CookieTokenStore implements TokenStore, and deliberately not Rekeyer.
var _ TokenStore = (*CookieTokenStore)(nil)

// NewCookieTokenStore builds a store that seals sessions into the cookie
// named cookieName. The name is part of what a session is sealed against, so
// two applications sharing a host and a keyring cannot open each other's
// sessions, and it has to be an HTTP token for the reason cookieDomain
// gives.
//
// maxSessionAge is the absolute session lifetime, counted from the login and
// not from the last request. Raising it is not free: a store-less session
// cannot be revoked, so it is also how long a copied cookie value keeps
// working and how long a retired key has to stay in the keyring.
//
// An application that registers OIDCAuth without a store of its own gets one
// of these built from the keyring, the session cookie name and
// WithMaxSessionAge, so this constructor is for the application that wants to
// hold the store itself.
func NewCookieTokenStore(
	keyring *CookieKeyring, cookieName string, maxSessionAge time.Duration,
) (*CookieTokenStore, error) {
	if keyring == nil {
		return nil, errors.New("a cookie keyring is required")
	}

	if maxSessionAge <= 0 {
		return nil, fmt.Errorf(
			"the maximum session age must be positive, got %s",
			maxSessionAge)
	}

	domain, err := cookieDomain(cookieDomainSession, cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie: %w", err)
	}

	return newCookieTokenStore(keyring, domain, maxSessionAge), nil
}

// newCookieTokenStore is the constructor OIDCAuth uses, since it has already
// built and validated the session domain.
func newCookieTokenStore(
	keyring *CookieKeyring, domain string, maxSessionAge time.Duration,
) *CookieTokenStore {
	return &CookieTokenStore{
		keyring:       keyring,
		domain:        domain,
		maxSessionAge: maxSessionAge,
	}
}

// Create seals a new session into a cookie value.
//
// The id_token is dropped, and that is a size decision rather than an
// oversight. A store-less session already carries the access and refresh
// tokens, and a measured one is about 2.4 KB of the 4 KB a browser
// guarantees; an id_token is another JWT of the same order, so keeping it
// would push a good many sessions over the limit and fail the login outright.
// Nothing store-less could use it for anyway: RP-initiated logout is a
// revocation, and a store that cannot revoke has no use for the hint.
func (s *CookieTokenStore) Create(
	_ context.Context, session NewSession,
) (*StoredToken, error) {
	if session.Token == nil {
		return nil, errors.New("a session needs a token")
	}

	return s.seal(&StoredToken{
		Subject:  session.Subject,
		Token:    session.Token,
		IssuedAt: time.Now(),
	})
}

// Get opens a sealed session. Every failure wraps ErrNoSession, and the
// reason it wraps alongside is what decides how loudly the caller logs it.
func (s *CookieTokenStore) Get(
	_ context.Context, handle string,
) (*StoredToken, error) {
	plaintext, current, err := s.keyring.open(s.domain, handle)
	if err != nil {
		return nil, fmt.Errorf("%w: open session cookie: %w",
			ErrNoSession, err)
	}

	var payload sessionPayload

	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		return nil, fmt.Errorf("%w: unmarshal session payload: %w",
			ErrNoSession, err)
	}

	if payload.Version != sessionPayloadV1 {
		return nil, fmt.Errorf(
			"%w: unsupported session payload version %d",
			ErrNoSession, payload.Version)
	}

	if payload.Token == nil {
		return nil, fmt.Errorf("%w: the session payload carries no token",
			ErrNoSession)
	}

	if age := time.Since(payload.IssuedAt); age >= s.maxSessionAge {
		return nil, fmt.Errorf(
			"%w: the session is %s old, past the maximum age of %s",
			ErrNoSession, age.Round(time.Second), s.maxSessionAge)
	}

	return &StoredToken{
		Handle:    handle,
		Subject:   payload.Subject,
		Token:     payload.Token,
		IssuedAt:  payload.IssuedAt,
		ExpiresAt: payload.IssuedAt.Add(s.maxSessionAge),
		Stale:     !current,
	}, nil
}

// Update re-seals the session with a new token set, carrying its issued_at
// and subject forward.
func (s *CookieTokenStore) Update(
	ctx context.Context, handle string, tok *oauth2.Token,
) (*StoredToken, error) {
	if tok == nil {
		return nil, errors.New("a session needs a token")
	}

	session, err := s.Get(ctx, handle)
	if err != nil {
		return nil, err
	}

	session.Token = tok

	return s.seal(session)
}

// Reseal seals the session again, which for a store-less session means
// sealing the whole payload under the current key. The issued_at is carried
// forward, so a re-seal does not extend the session.
func (s *CookieTokenStore) Reseal(
	_ context.Context, t *StoredToken,
) (*StoredToken, error) {
	return s.seal(t)
}

// Delete does nothing, and cannot do anything: there is nothing stored to
// remove. The caller still clears the cookie, which ends the session in that
// one browser. A copied cookie value keeps working until the session reaches
// its absolute expiry.
func (s *CookieTokenStore) Delete(_ context.Context, _ string) error {
	return nil
}

// Refresh exchanges the session's refresh token for a new one, collapsing
// the concurrent refreshes of a single session onto one round trip.
//
// The deduplication is per process and does not reach across replicas — see
// the caveat on CookieTokenStore. Every caller of a collapsed refresh gets
// the same new session, cookie value and all.
func (s *CookieTokenStore) Refresh(
	ctx context.Context, t *StoredToken,
	exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
) (*StoredToken, error) {
	// Keyed on the handle, so only requests carrying the same session
	// share an exchange.
	res, err, _ := s.refresh.Do(t.Handle, func() (any, error) {
		tok, err := exchange(ctx, t.Token)
		if err != nil {
			return nil, err //nolint: wrapcheck
		}

		// A token that is not there is a failure rather than something
		// to seal. Sealing it writes a cookie whose payload carries
		// "token": null, which every reader downstream would dereference
		// — and this is the store an application holds itself, so the
		// exchange is not necessarily the one OIDCAuth passes in.
		if tok == nil {
			return nil, errors.New("the exchange returned no token")
		}

		return s.seal(&StoredToken{
			Subject:  t.Subject,
			Token:    tok,
			IssuedAt: t.IssuedAt,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("exchange refresh token: %w", err)
	}

	session, ok := res.(*StoredToken)
	if !ok {
		return nil, fmt.Errorf("unexpected refresh result of type %T", res)
	}

	return session, nil
}

// DeleteExpired has nothing to sweep: a session past its absolute expiry is
// refused by Get, and the cookie holding it is cleared and forgotten.
func (s *CookieTokenStore) DeleteExpired(
	_ context.Context, _ int,
) (int64, error) {
	return 0, nil
}

// seal produces the session's cookie value, and is the only place a
// store-less session is written. The result is a new StoredToken rather than
// a mutated one, because a refresh hands the same value to every caller that
// collapsed onto it.
func (s *CookieTokenStore) seal(t *StoredToken) (*StoredToken, error) {
	// The backstop for every path in, Reseal included: a session with no
	// token seals into a cookie nothing can use, and one that opens
	// without a token is worse than one that does not open at all, since
	// only the second is refused as ErrNoSession.
	if t == nil || t.Token == nil {
		return nil, errors.New("a session needs a token")
	}

	data, err := json.Marshal(sessionPayload{
		Version:  sessionPayloadV1,
		IssuedAt: t.IssuedAt,
		Token:    t.Token,
		Subject:  t.Subject,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal session payload: %w", err)
	}

	value, err := s.keyring.seal(s.domain, data)
	if err != nil {
		return nil, fmt.Errorf("seal session payload: %w", err)
	}

	return &StoredToken{
		Handle:    value,
		Subject:   t.Subject,
		Token:     t.Token,
		IssuedAt:  t.IssuedAt,
		ExpiresAt: t.IssuedAt.Add(s.maxSessionAge),
	}, nil
}
