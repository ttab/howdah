package howdah

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// KeyID identifies the cookie key a value was sealed under. It is the first
// eight bytes of a hash of the secret, so it moves with the key rather than
// with the environment variable the key was written down in.
//
// A store that keeps sealed payloads of its own keeps the id beside them, so
// that a rollover sweep can find the rows under a retiring key through an
// index instead of opening every one of them to discover which key it used.
type KeyID [cookieKeyIDLength]byte

// String returns the hex key id, which is what the startup log line and the
// rollover runbook name a key by.
func (k KeyID) String() string {
	return hex.EncodeToString(k[:])
}

// Bytes returns the key id as a slice, for a store that keeps it in a
// column.
func (k KeyID) Bytes() []byte {
	return k[:]
}

// SessionSealer seals and opens the two things a TokenStore holds: the
// handle it puts in the session cookie, and — for a store that keeps the
// tokens somewhere of its own — the sealed payload it writes to its own
// storage. It is the whole of what a store outside this package needs from
// the keyring, and it is safe for concurrent use.
//
// It exists because sealing is the store's job and the domain a value is
// sealed under is not a string a caller should be writing. The domain
// carries cookie identity rather than merely the kind of value — "cookie:"
// plus the session cookie name, not "cookie:token" — because two
// applications sharing a host and a keyring would otherwise be able to open
// each other's sessions, and NewOIDCAuth verifies access tokens with
// SkipClientIDCheck, so that is a privilege escalation and not just an
// oddity. A hand-written domain is exactly the mistake this type is shaped
// to prevent: ask for a sealer, and the domains come out right.
type SessionSealer struct {
	keyring *CookieKeyring

	// cookieDomain binds a handle to the session cookie it lives in, and
	// storeDomain binds a payload to this application's storage. They are
	// different labels, so a payload lifted out of a database row does
	// not open as a cookie and a cookie does not open as a row.
	cookieDomain string
	storeDomain  string
}

// NewSessionSealer returns the sealer for the sessions of the application
// whose session cookie is named cookieName. The name has to be an HTTP
// token, colons in particular excluded: the domains are colon-joined
// prefixes rather than fixed-width fields, so a name holding a colon lets
// two different labels collide, which is the cross-cookie replay the domain
// exists to prevent.
func NewSessionSealer(
	keyring *CookieKeyring, cookieName string,
) (*SessionSealer, error) {
	if keyring == nil {
		return nil, errors.New("a cookie keyring is required")
	}

	cookie, err := cookieDomain(cookieDomainSession, cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie: %w", err)
	}

	store, err := cookieDomain(cookieDomainStore, cookieName)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}

	return &SessionSealer{
		keyring:      keyring,
		cookieDomain: cookie,
		storeDomain:  store,
	}, nil
}

// SealHandle seals a session handle into a cookie value. The handle is
// opaque to everything but the store that made it.
func (s *SessionSealer) SealHandle(handle []byte) (string, error) {
	value, err := s.keyring.sealKind(
		sessionKindHandle, s.cookieDomain, handle)
	if err != nil {
		return "", fmt.Errorf("seal session handle: %w", err)
	}

	return value, nil
}

// OpenHandle opens a session cookie's value into the handle it wraps. The
// current return reports whether the value was sealed under the key the
// keyring seals with now; false is what a store reports as
// StoredToken.Stale, and it is what drains a retiring key during a
// rollover.
//
// The error is one of ErrNotSealed, ErrUnknownVersion, ErrUnknownKey,
// ErrWrongSessionKind or ErrAuthentication. Only the last is worth alerting
// on.
func (s *SessionSealer) OpenHandle(
	value string,
) (handle []byte, current bool, err error) {
	handle, current, err = s.keyring.openKind(
		sessionKindHandle, s.cookieDomain, value)
	if err != nil {
		return nil, false, fmt.Errorf("open session handle: %w", err)
	}

	return handle, current, nil
}

// SealPayload seals a session payload for the store's own storage, bound to
// the id of the row it is going to be written to, and reports the id of the
// key it sealed under.
//
// The row id is in the additional authenticated data, which is what stops
// a writer with access to the storage from transplanting one session's
// payload into another session's row: the payload opens for that row and
// nowhere else. It costs nothing — the AAD is not stored — and it is a
// different threat from sealing the payload in the first place.
func (s *SessionSealer) SealPayload(
	rowID, payload []byte,
) (sealed []byte, kid KeyID, err error) {
	raw, id, err := s.keyring.sealKindRaw(
		sessionKindPayload, s.payloadDomain(rowID), payload)
	if err != nil {
		return nil, KeyID{}, fmt.Errorf("seal session payload: %w", err)
	}

	return raw, KeyID(id), nil
}

// OpenPayload opens a sealed session payload from the store's own storage,
// and reports the key it was sealed under and whether that is still the key
// the keyring seals with. A payload that is not current is what a rollover
// sweep re-seals.
//
// The errors are the same set OpenHandle returns.
func (s *SessionSealer) OpenPayload(
	rowID, sealed []byte,
) (payload []byte, kid KeyID, current bool, err error) {
	plaintext, id, current, err := s.keyring.openKindRaw(
		sessionKindPayload, s.payloadDomain(rowID), sealed)
	if err != nil {
		return nil, KeyID(id), false, fmt.Errorf(
			"open session payload: %w", err)
	}

	return plaintext, KeyID(id), current, nil
}

// SealingKeyID is the id of the key payloads are sealed under right now. It
// moves as a key's UseAfter passes, so it is a snapshot rather than a
// constant, and it is what a rollover sweep compares a stored key id
// against.
func (s *SessionSealer) SealingKeyID() KeyID {
	key := s.keyring.sealingKey()
	if key == nil {
		return KeyID{}
	}

	return KeyID(key.kid)
}

// payloadDomain binds a payload to one row. The cookie name cannot hold a
// colon and the row id is hex, so the concatenation is unambiguous.
func (s *SessionSealer) payloadDomain(rowID []byte) string {
	return s.storeDomain + ":" + hex.EncodeToString(rowID)
}
