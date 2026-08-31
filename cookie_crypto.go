package howdah

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// The sealed cookie envelope, base64url-encoded into the cookie value:
//
//	 1 B   1 B     8 B        12 B         n B        16 B
//	┌─────┬─────┬─────────┬────────────┬────────────┬───────┐
//	│ ver │kind │   kid   │   nonce    │ ciphertext │  tag  │
//	└─────┴─────┴─────────┴────────────┴────────────┴───────┘
//
// Version 1 is AES-256-GCM with a random 12 byte nonce. A later format
// takes a new version byte; readers dispatch on it, writers only ever emit
// the current one.
const (
	cookieEnvelopeV1 = 1

	// cookieEnvelopeMaxVersion is the highest version byte that counts as
	// a plausible envelope. Anything above it is not an envelope at all,
	// which is what keeps a legacy plaintext cookie — base64 of JSON, so
	// a first byte of '{' (0x7B) — out of the ErrUnknownVersion bucket
	// that is supposed to mean "we rolled back".
	cookieEnvelopeMaxVersion = 16

	cookieKeyIDLength = 8
	cookieNonceLength = 12
	cookieTagLength   = 16

	cookieEnvelopeHeaderLength = 1 + 1 + cookieKeyIDLength + cookieNonceLength
)

// sessionKind says what an envelope's ciphertext wraps. It sits in the
// header rather than the plaintext so that a reader can reject a value
// from the other mode without holding the right key at all, and it is
// covered by the AAD so it cannot be edited.
type sessionKind byte

const (
	// sessionKindPayload wraps a whole session payload.
	sessionKindPayload sessionKind = 1
	// sessionKindHandle wraps a handle to a session held elsewhere.
	sessionKindHandle sessionKind = 2
)

func (k sessionKind) String() string {
	switch k {
	case sessionKindPayload:
		return "payload"
	case sessionKindHandle:
		return "handle"
	default:
		return fmt.Sprintf("kind %d", byte(k))
	}
}

// valid reports whether the kind is one of ours. A kind outside the set is
// part of the envelope's shape rather than a mode mismatch: it says the
// value is not one of our envelopes at all, so it belongs in ErrNotSealed
// and not in the ErrWrongSessionKind bucket an operator reads as "somebody
// switched this service between store-less and store mode".
func (k sessionKind) valid() bool {
	switch k {
	case sessionKindPayload, sessionKindHandle:
		return true
	}

	return false
}

// Opening a sealed value can fail in five distinct ways. They all end the
// same way — unset the cookie, redirect to login — but they mean different
// things, and only ErrAuthentication is worth alerting on.
var (
	// ErrNotSealed means the value does not parse as an envelope at all.
	// Expected while a release that seals cookies rolls out, since
	// browsers still hold plaintext ones.
	ErrNotSealed = errors.New("not a sealed value")

	// ErrUnknownVersion means the envelope carries a version byte this
	// version of howdah does not know. Expected during a rollback.
	ErrUnknownVersion = errors.New("unknown envelope version")

	// ErrUnknownKey means the envelope's key id is not in the keyring.
	// Expected after retiring a key.
	ErrUnknownKey = errors.New("unknown cookie key")

	// ErrWrongSessionKind means the envelope holds a payload where a
	// handle was expected, or the reverse. Expected after switching a
	// service between store-less and store mode.
	ErrWrongSessionKind = errors.New("wrong session kind")

	// ErrAuthentication means the key was known but the envelope failed
	// authentication. Rare, and the one to log loudly: tampering,
	// crossed environments, or a cookie an intermediary truncated.
	ErrAuthentication = errors.New("envelope failed authentication")
)

// errNoCookieKeyring is what a keyring that never came out of
// NewCookieKeyring gets instead of a nil pointer dereference on every
// request.
var errNoCookieKeyring = errors.New("the cookie keyring is not initialised")

// seal encrypts plaintext into a cookie value bound to domain, which must
// come from cookieDomain: the domain has to carry cookie identity rather
// than just value kind — "cookie:" plus the session cookie name rather than
// "cookie:token" — so that a value cannot be moved between the cookies of
// two applications sharing a host and a keyring, and cookieDomain is where
// the cookie name is checked for the colon that would let two labels
// collide.
//
// This pair is deliberately unexported, even though the keyring itself is a
// type applications construct. An exported Seal whose domain argument can
// only be built correctly by unexported code is an invitation to hand-write
// the string, and a hand-written "cookie:token" is the privilege escalation
// the domain exists to close.
//
// Sealing is a store's job — see TokenStore, which settles that — and
// CookieTokenStore is in this package, so it uses these directly. A store in
// a subpackage cannot, so the release that adds the Postgres-backed one is
// what exports them: both halves together, with the store purpose, the
// handle kind, and a domain builder, so that the only way to name a domain
// from outside is still to ask for one.
func (k *CookieKeyring) seal(domain string, plaintext []byte) (string, error) {
	return k.sealKind(sessionKindPayload, domain, plaintext)
}

// open decrypts a cookie value sealed for domain. The current return
// reports whether the value was sealed under the key we would seal with
// now; false is the migration trigger, re-seal it on the way out.
//
// The returned error is one of ErrNotSealed, ErrUnknownVersion,
// ErrUnknownKey, ErrWrongSessionKind or ErrAuthentication.
func (k *CookieKeyring) open(
	domain, value string,
) (plaintext []byte, current bool, err error) {
	return k.openKind(sessionKindPayload, domain, value)
}

func (k *CookieKeyring) sealKind(
	kind sessionKind, domain string, plaintext []byte,
) (string, error) {
	key := k.sealingKey()
	if key == nil {
		return "", errNoCookieKeyring
	}

	buf := make([]byte, cookieEnvelopeHeaderLength,
		cookieEnvelopeHeaderLength+len(plaintext)+cookieTagLength)

	buf[0] = cookieEnvelopeV1
	buf[1] = byte(kind)
	copy(buf[2:], key.kid[:])

	nonce := buf[2+cookieKeyIDLength:]

	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := key.aead.Seal(buf, nonce, plaintext,
		cookieEnvelopeAAD(cookieEnvelopeV1, kind, key.kid, domain))

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (k *CookieKeyring) openKind(
	kind sessionKind, domain, value string,
) ([]byte, bool, error) {
	sealWith := k.sealingKey()
	if sealWith == nil {
		return nil, false, errNoCookieKeyring
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false, ErrNotSealed
	}

	// Check the shape before dispatching on the version, or every legacy
	// plaintext cookie is reported as an envelope from the future. The
	// kind byte is part of the shape: a value carrying a kind that is
	// neither of ours is not our envelope, whereas the mismatch below is
	// a well-formed envelope from the other mode.
	if len(raw) < cookieEnvelopeHeaderLength+cookieTagLength ||
		raw[0] == 0 || raw[0] > cookieEnvelopeMaxVersion ||
		!sessionKind(raw[1]).valid() {
		return nil, false, ErrNotSealed
	}

	if raw[0] != cookieEnvelopeV1 {
		return nil, false, fmt.Errorf("version %d: %w",
			raw[0], ErrUnknownVersion)
	}

	// The kind is checked before the keyring is consulted, so a value
	// from the other mode is rejected without holding its key.
	if got := sessionKind(raw[1]); got != kind {
		return nil, false, fmt.Errorf("expected %s, got %s: %w",
			kind, got, ErrWrongSessionKind)
	}

	var kid [cookieKeyIDLength]byte

	copy(kid[:], raw[2:])

	key, ok := k.keys[kid]
	if !ok {
		return nil, false, fmt.Errorf("key %x: %w", kid, ErrUnknownKey)
	}

	nonce := raw[2+cookieKeyIDLength : cookieEnvelopeHeaderLength]

	plaintext, err := key.aead.Open(nil, nonce, raw[cookieEnvelopeHeaderLength:],
		cookieEnvelopeAAD(raw[0], kind, kid, domain))
	if err != nil {
		return nil, false, fmt.Errorf("key %x: %w", kid, ErrAuthentication)
	}

	return plaintext, kid == sealWith.kid, nil
}

// cookieEnvelopeAAD builds the additional authenticated data an envelope is
// sealed with: version, kind and kid are in the envelope in the clear, so
// authenticating them stops the header being edited, and the domain is
// never transmitted at all, so it acts as a label the ciphertext has to
// match. Only the last field is variable-length, so the concatenation is
// unambiguous.
//
// The field set and its order are a wire contract — reorder it and every
// cookie the previous build sealed fails authentication, which presents as
// a fleet-wide tampering alarm. TestCookieEnvelopeGolden pins it.
func cookieEnvelopeAAD(
	version byte, kind sessionKind, kid [cookieKeyIDLength]byte, domain string,
) []byte {
	aad := make([]byte, 0, 2+cookieKeyIDLength+len(domain))

	aad = append(aad, version, byte(kind))
	aad = append(aad, kid[:]...)
	aad = append(aad, domain...)

	return aad
}

// cookieDomainPurpose is what a sealed value is for. It is the leading,
// fixed part of a domain string; the cookie name is the tail.
type cookieDomainPurpose string

const (
	// cookieDomainSession labels the value of a session cookie.
	cookieDomainSession cookieDomainPurpose = "cookie:"
	// cookieDomainAuthRedirect labels the post-login redirect target.
	cookieDomainAuthRedirect cookieDomainPurpose = "cookie:auth_redir:"
)

// cookieDomain builds the domain string a value is sealed under: a purpose
// and the name of the cookie it lives in.
//
// The cookie name is validated here because the purposes are colon-joined
// prefixes rather than a fixed-width field, so a name holding a colon makes
// two different labels collide: "cookie:" + "auth_redir:sess" is
// byte-identical to "cookie:auth_redir:" + "sess". That is exactly the
// cross-cookie replay the domain exists to prevent, so the name is
// constrained to an RFC 6265 token — colons and all other separators
// excluded — and howdah's cookie names go through here rather than being
// concatenated at the call site.
func cookieDomain(purpose cookieDomainPurpose, name string) (string, error) {
	if !validCookieName(name) {
		return "", fmt.Errorf(
			"%q is not a valid cookie name: expected a non-empty HTTP token", name)
	}

	return string(purpose) + name, nil
}

// cookieNameSeparators are RFC 6265's separators, none of which may appear
// in a cookie name. The colon is the one that matters to cookieDomain.
const cookieNameSeparators = `"(),/:;<=>?@[\]{}`

// validCookieName reports whether name is a cookie name RFC 6265 allows: a
// non-empty HTTP token, so no control characters, no space, and none of the
// separators.
func validCookieName(name string) bool {
	if name == "" {
		return false
	}

	for i := range len(name) {
		c := name[i]

		if c <= 0x20 || c >= 0x7f ||
			strings.IndexByte(cookieNameSeparators, c) >= 0 {
			return false
		}
	}

	return true
}
