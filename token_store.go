package howdah

import (
	"context"
	"errors"
	"time"

	"golang.org/x/oauth2"
)

// ErrNoSession is what a store returns for a handle it cannot resolve to a
// live session: one it has never seen, one past its absolute expiry, or one
// sealed under a key that is no longer configured.
//
// Every store error a session read can produce wraps it, so a caller that
// only wants to know whether there is a session has one thing to check. The
// specific reason is wrapped alongside it — the sealing taxonomy in
// cookie_crypto.go, ErrAuthentication in particular — because the reason is
// what decides how loudly the failure is logged. See rejectTokenCookie.
var ErrNoSession = errors.New("no session")

// ErrRefreshRejected says that a refresh failed in a way that ends the
// session: the token endpoint refused the exchange, or refused the exchange
// another caller was already running on this session's behalf. The refresh
// token is gone, so there is nothing left to try and the user logs in again.
//
// It is the discriminator that keeps a store outage from looking like a dead
// session. Every other failure a Refresh can report — the storage could not
// be read, the wait for another caller's refresh ran out, the write-back was
// refused — means "I could not find out", and the session it belongs to is
// very likely still there. In store mode the cookie is the only handle to
// it, so clearing the cookie over one of those turns a two-second database
// failover into a logout for every user whose access token happened to be
// inside the refresh margin, and orphans their rows until the sweep. Only a
// failure wrapping this one, or one wrapping ErrNoSession, is a reason to
// unset the session cookie; see sessionGone.
//
// A store does not have to produce it for the exchange failures it merely
// passes on, because the exchange OIDCAuth hands to Refresh already wraps
// its own. A store that answers a caller waiting on somebody else's failed
// refresh has to wrap it itself — that caller never saw the exchange error.
var ErrRefreshRejected = errors.New("the token refresh was rejected")

// TokenStore holds a session's OAuth2 tokens. Implementations must be safe
// for concurrent use by multiple goroutines and, where the storage is
// shared, by multiple processes.
//
// The store owns sealing. That is the decision behind the shape of this
// interface, and it is worth stating because the alternative looks cheaper:
// if OIDCAuth sealed the handle itself, it would have to choose the envelope
// kind byte — payload for a store-less session, handle for a stored one —
// and know which kind to expect when it reads the cookie back. That is
// exactly the "which implementation have I got" switch the interface exists
// to remove, so instead each implementation takes the keyring and produces a
// Handle that is already a cookie value. OIDCAuth writes the handle to the
// cookie and reads it back; it never learns what is inside one.
//
// The seam that keeps it that way is the Handle a write returns. Refresh,
// Update and Reseal all return a StoredToken whose Handle may or may not
// differ from the one that went in, and the caller writes a Set-Cookie when
// it changed or when the value it read was not sealed under the current key
// (Stale). For a cookie-backed store the handle is the sealed session, so it
// changes on every write; for a Postgres-backed one it is stable across a
// refresh and only a key rollover moves it. Same code path, no type switch.
type TokenStore interface {
	// Create stores a new session and returns it. The Handle is what goes
	// in the session cookie.
	Create(ctx context.Context, session NewSession) (*StoredToken, error)

	// Get resolves a cookie handle. It returns an error wrapping
	// ErrNoSession for a handle that is unknown, past its absolute expiry,
	// or sealed under a key that is no longer configured.
	Get(ctx context.Context, handle string) (*StoredToken, error)

	// Update replaces the tokens for an existing session, carrying the
	// session's issued_at and subject forward. It is for an application
	// that obtains a token set out of band; OIDCAuth does not call it, so
	// do not go looking for the caller. A refresh goes through Refresh,
	// which deduplicates, and a key migration goes through Reseal, which
	// does not touch the stored tokens at all.
	Update(
		ctx context.Context, handle string, tok *oauth2.Token,
	) (*StoredToken, error)

	// Reseal returns the session with a Handle sealed under the key the
	// keyring seals with now. It is what a caller does about a StoredToken
	// that came back Stale, and it changes nothing about the session
	// itself.
	//
	// It is a method of its own rather than an Update with the tokens the
	// caller just read, and that distinction is not cosmetic: a session is
	// read on one replica and may be refreshed on another, so writing back
	// tokens that were only ever read risks landing on top of a fresher
	// set. With refresh token rotation on, that write resurrects a token
	// the provider has already invalidated and kills the session. Reseal
	// re-seals the envelope around the handle and writes no tokens, so
	// there is nothing to clobber.
	Reseal(ctx context.Context, t *StoredToken) (*StoredToken, error)

	// Delete removes a session: logout, and revoke-this-session.
	Delete(ctx context.Context, handle string) error

	// Refresh obtains a new token, deduplicating the concurrent refreshes
	// of the same session as far as the implementation is able. exchange
	// performs the token endpoint round trip; callers that lose the race
	// wait for the winner's result rather than repeating it.
	//
	// How far "as far as it is able" reaches is the main thing that
	// separates the implementations, and each one documents its own reach:
	// per process for a cookie-backed store, fleet-wide for one backed by
	// a database. Callers must not assume exchange runs exactly once, and
	// must not assume it ran in their own goroutine.
	Refresh(ctx context.Context, t *StoredToken,
		exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
	) (*StoredToken, error)

	// DeleteExpired removes sessions past their absolute expiry, at most
	// batch at a time, and returns how many it removed. Call it until it
	// returns 0.
	//
	// The application schedules it. howdah starts no goroutines of its
	// own, and a store with nothing to sweep answers 0.
	DeleteExpired(ctx context.Context, batch int) (int64, error)
}

// NewSession is a session at the moment it is created: what the login
// produced, and nothing a store decides for itself. The issued_at and the
// absolute expiry are the store's to set, which is what keeps the session
// lifetime a property of the store rather than something every caller could
// pick.
type NewSession struct {
	// Subject is the OIDC sub claim, and is what makes "log this person
	// out everywhere" possible in a store that keeps a row per session.
	Subject string

	// Token is the token set the login produced. Required.
	Token *oauth2.Token

	// IDToken is the raw, verified id_token from the login.
	//
	// It is here because RP-initiated logout at the provider's end-session
	// endpoint needs it as id_token_hint, and json.Marshal on an
	// oauth2.Token drops the Extra map it arrives in — so a store that
	// does not persist it at creation cannot get it back later. Nothing in
	// howdah talks to the provider on the way out yet; this is what makes
	// it possible to.
	//
	// A store is allowed to drop it, and one that does says so: an
	// id_token is a JWT of the same order of size as the access token, and
	// a store-less session has nowhere to put it.
	IDToken string
}

// StoredToken is a session as a store holds it.
type StoredToken struct {
	// Handle is the opaque value that identifies the session, and is the
	// session cookie's value. It is produced by the store, which seals it,
	// and is never interpreted by the caller.
	Handle string

	// Subject is the OIDC sub claim.
	Subject string

	// Token is the session's OAuth2 token set.
	Token *oauth2.Token

	// IDToken is the raw id_token from the login, or empty if the store
	// does not keep it.
	IDToken string

	// IssuedAt is when the session began. It is carried forward unchanged
	// across every refresh and every re-seal: restart it and the absolute
	// expiry slides forward every few minutes, which is to say it enforces
	// nothing.
	IssuedAt time.Time

	// ExpiresAt is the absolute session expiry, after which the store
	// refuses the handle whatever the state of the tokens. A cookie's own
	// Expires is an instruction to the browser and means nothing to
	// somebody holding a copied value; this is the one that counts.
	ExpiresAt time.Time

	// Stale reports that the handle was sealed under a key that is no
	// longer the one the keyring seals with, so it wants re-sealing on the
	// way out. Get sets it; Reseal is what clears it.
	//
	// It is what drains a retired key during a rollover. Without it the
	// caller would only write a cookie when the handle changed, and a
	// store whose handles are stable across a refresh would never migrate
	// a key at all.
	Stale bool
}
