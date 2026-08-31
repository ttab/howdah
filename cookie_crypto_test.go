package howdah

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"golang.org/x/oauth2"
)

// envelopeTestKeyring returns a keyring sealing with the secret 1 key, and
// one sealing with the secret 4 key that the first one does not know about.
func envelopeTestKeyring(t *testing.T) (ours, stranger *CookieKeyring) {
	t.Helper()

	past := testTime(t, "2020-01-01T00:00:00Z")

	ours = newTestKeyring(t, CookieKey{
		UseAfter: past,
		Secret:   testCookieSecret(1),
	})

	stranger = newTestKeyring(t, CookieKey{
		UseAfter: past,
		Secret:   testCookieSecret(4),
	})

	return ours, stranger
}

// mutate decodes an envelope, hands the raw bytes to fn, and re-encodes it.
func mutate(t *testing.T, value string, fn func(raw []byte)) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	fn(raw)

	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestCookieEnvelopeRoundTrip(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	const (
		domain    = "cookie:token"
		plaintext = "the refresh token nobody should be able to read"
	)

	value, err := keyring.seal(domain, []byte(plaintext))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// version + kind + kid + nonce + tag, and no plaintext length leak
	// beyond the ciphertext itself.
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	// Searched in the decoded bytes, not in the base64 text where the
	// substring could not appear even if nothing were encrypted.
	if bytes.Contains(raw, []byte(plaintext)) {
		t.Errorf("the sealed value carries its plaintext: %s", value)
	}

	if want := cookieEnvelopeHeaderLength + len(plaintext) + cookieTagLength; len(raw) != want {
		t.Errorf("envelope is %d bytes, want %d", len(raw), want)
	}

	if raw[0] != cookieEnvelopeV1 {
		t.Errorf("version byte is %d, want %d", raw[0], cookieEnvelopeV1)
	}

	if sessionKind(raw[1]) != sessionKindPayload {
		t.Errorf("kind byte is %d, want %d", raw[1], sessionKindPayload)
	}

	got, current, err := keyring.open(domain, value)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("opened %q, want %q", got, plaintext)
	}

	if !current {
		t.Error("a value we just sealed is not current")
	}

	// The nonce is per-value, so sealing the same thing twice must not
	// produce the same cookie.
	other, err := keyring.seal(domain, []byte(plaintext))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if other == value {
		t.Error("two seals of the same plaintext produced the same value")
	}
}

// TestCookieEnvelopeEmptyPlaintext is the minimum-length boundary the shape
// check in openKind accepts: header plus tag exactly. Pinned from both
// sides, or an off-by-one there turns every empty payload into
// ErrNotSealed.
func TestCookieEnvelopeEmptyPlaintext(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	const domain = "cookie:token"

	for name, plaintext := range map[string][]byte{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := keyring.seal(domain, plaintext)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}

			raw, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				t.Fatalf("decode envelope: %v", err)
			}

			if want := cookieEnvelopeHeaderLength + cookieTagLength; len(raw) != want {
				t.Errorf("envelope is %d bytes, want %d",
					len(raw), want)
			}

			got, current, err := keyring.open(domain, value)
			if err != nil {
				t.Fatalf("open: %v", err)
			}

			if len(got) != 0 {
				t.Errorf("opened %q, want nothing", got)
			}

			if !current {
				t.Error("a value we just sealed is not current")
			}
		})
	}
}

// TestCookieEnvelopeGolden pins the envelope format, and with it the AAD's
// field set and its order. A reordering keeps Seal and Open consistent with
// each other, so without a fixture the suite stays green while every cookie
// the previous build sealed fails GCM open on deploy — a fleet-wide logout
// presenting as a tampering alarm.
func TestCookieEnvelopeGolden(t *testing.T) {
	const (
		domain    = "cookie:token"
		plaintext = "the golden session payload"
		golden    = "AQGGlmPBLAll_WdOeFvdRjj2v3lZ6-bSvopbxbFHz5E1hiBYvx3bK2qyI7xuAN9MsF402zh2QLiNjq8hiGf38Q"
	)

	keyring := newTestKeyring(t, CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(1),
	})

	got, current, err := keyring.open(domain, golden)
	if err != nil {
		t.Fatalf("open the golden envelope: %v\n"+
			"The envelope format is a wire contract. If this is a deliberate"+
			" change it needs a new version byte, not a new fixture.", err)
	}

	if string(got) != plaintext {
		t.Errorf("opened %q, want %q", got, plaintext)
	}

	if !current {
		t.Error("the golden envelope is not current")
	}
}

// TestCookieEnvelopeDomainBinding is the proof that the AAD binding works,
// and specifically that it binds cookie identity: two co-hosted
// applications sharing a keyring cannot open each other's session cookies.
func TestCookieEnvelopeDomainBinding(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	value, err := keyring.seal("cookie:token_a", []byte("session a"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, domain := range []string{
		"cookie:token_b",
		"cookie:auth_redir:token_a",
		"store:token_a",
		"cookie:token",
		"",
	} {
		_, _, err := keyring.open(domain, value)
		if !errors.Is(err, ErrAuthentication) {
			t.Errorf("open with domain %q: got %v, want ErrAuthentication",
				domain, err)
		}
	}
}

// TestCookieDomain covers the one way two purposes can produce the same
// domain string: the purposes are colon-joined prefixes rather than a
// fixed-width field, so a cookie name holding a colon makes
// "cookie:" + "auth_redir:sess" byte-identical to
// "cookie:auth_redir:" + "sess". Since NewOIDCAuth verifies access tokens
// with SkipClientIDCheck, that would be a privilege escalation between
// co-hosted applications rather than a curiosity, so the name is validated
// where it enters.
func TestCookieDomain(t *testing.T) {
	session, err := cookieDomain(cookieDomainSession, "token")
	if err != nil {
		t.Fatalf("build a session domain: %v", err)
	}

	if want := "cookie:token"; session != want {
		t.Errorf("session domain is %q, want %q", session, want)
	}

	redirect, err := cookieDomain(cookieDomainAuthRedirect, "token")
	if err != nil {
		t.Fatalf("build an auth redirect domain: %v", err)
	}

	if want := "cookie:auth_redir:token"; redirect != want {
		t.Errorf("auth redirect domain is %q, want %q", redirect, want)
	}

	// The collision is real if the name is not constrained, so assert
	// that before asserting that the name is refused.
	if collision := string(cookieDomainSession) + "auth_redir:token"; collision != redirect {
		t.Fatalf("expected %q to collide with the auth redirect domain %q",
			collision, redirect)
	}

	_, err = cookieDomain(cookieDomainSession, "auth_redir:token")
	if err == nil {
		t.Error("built a session domain that collides with an auth redirect domain")
	}
}

func TestValidCookieName(t *testing.T) {
	valid := []string{"token", "token_a", "imagereporting-session", "a", "T0k3n!"}

	for _, name := range valid {
		if !validCookieName(name) {
			t.Errorf("cookie name %q was rejected", name)
		}
	}

	invalid := map[string]string{
		"empty":       "",
		"colon":       "auth_redir:token",
		"space":       "my token",
		"semicolon":   "token;a",
		"equals":      "token=a",
		"comma":       "token,a",
		"quote":       `"token"`,
		"brace":       "{token}",
		"control":     "token\x00",
		"tab":         "token\t",
		"newline":     "token\n",
		"non-ascii":   "tokenå",
		"at":          "token@host",
		"parenthesis": "token(a)",
	}

	for name, value := range invalid {
		if validCookieName(value) {
			t.Errorf("%s: cookie name %q was accepted", name, value)
		}
	}
}

func TestCookieEnvelopeFlippedByte(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	const domain = "cookie:token"

	value, err := keyring.seal(domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The nonce, the ciphertext and the tag. The kid gets its own tests,
	// since editing it names a different key.
	offsets := map[string]int{
		"nonce":      cookieEnvelopeHeaderLength - 1,
		"ciphertext": cookieEnvelopeHeaderLength + 1,
		"tag":        cookieEnvelopeHeaderLength + len("session payload"),
	}

	for name, offset := range offsets {
		tampered := mutate(t, value, func(raw []byte) {
			raw[offset] ^= 0x01
		})

		_, _, err := keyring.open(domain, tampered)
		if !errors.Is(err, ErrAuthentication) {
			t.Errorf("flipped a bit in the %s: got %v, want ErrAuthentication",
				name, err)
		}
	}
}

func TestCookieEnvelopeUnknownKey(t *testing.T) {
	keyring, stranger := envelopeTestKeyring(t)

	const domain = "cookie:token"

	value, err := stranger.seal(domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	_, _, err = keyring.open(domain, value)
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("open a value from a retired key: got %v, want ErrUnknownKey",
			err)
	}
}

// TestCookieEnvelopeEditedKeyID covers what the flipped-byte test defers:
// the kid rewritten on a value the keyring can otherwise handle. Rewriting
// it to a key nobody has is routine rotation noise; rewriting it to another
// key the keyring holds is a tampering alarm, because the named key cannot
// open somebody else's ciphertext. The kid's presence in the AAD is pinned
// by TestCookieEnvelopeGolden — a swap alone cannot prove it, since a
// different kid means a different cipher either way.
func TestCookieEnvelopeEditedKeyID(t *testing.T) {
	const domain = "cookie:token"

	past := testTime(t, "2020-01-01T00:00:00Z")

	keyring := newTestKeyring(t,
		CookieKey{UseAfter: past, Secret: testCookieSecret(1)},
		CookieKey{
			UseAfter: past.AddDate(1, 0, 0),
			Secret:   testCookieSecret(2),
		})

	value, err := keyring.seal(domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	unknown := mutate(t, value, func(raw []byte) {
		raw[2] ^= 0xff
	})

	_, _, err = keyring.open(domain, unknown)
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("open a value with an edited kid: got %v, want ErrUnknownKey",
			err)
	}

	// Sealed under key 2 — the sealing key — relabelled as key 1, which
	// the keyring holds and can therefore try.
	other := cookieKeyID(testCookieSecret(1))

	relabelled := mutate(t, value, func(raw []byte) {
		copy(raw[2:], other[:])
	})

	_, _, err = keyring.open(domain, relabelled)
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("open a value relabelled with another configured key: got %v, want ErrAuthentication",
			err)
	}
}

// TestCookieEnvelopeNotSealed pins the taxonomy's easiest mistake: a legacy
// plaintext cookie is base64 of JSON, so its first byte is '{'. Dispatching
// on the version byte without a shape check reports it as ErrUnknownVersion,
// polluting the code that is supposed to mean "we rolled back".
func TestCookieEnvelopeNotSealed(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	legacy, err := json.Marshal(&oauth2.Token{
		AccessToken:  "an access token",
		TokenType:    "Bearer",
		RefreshToken: "a refresh token",
	})
	if err != nil {
		t.Fatalf("marshal a legacy token: %v", err)
	}

	if legacy[0] != '{' {
		t.Fatalf("a legacy cookie starts with %q, expected '{'", legacy[0])
	}

	sealed, err := keyring.seal("cookie:token", []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	cases := map[string]string{
		"empty":               "",
		"not base64":          "not base64 at all!",
		"legacy plaintext":    base64.RawURLEncoding.EncodeToString(legacy),
		"too short":           base64.RawURLEncoding.EncodeToString(make([]byte, cookieEnvelopeHeaderLength+cookieTagLength-1)),
		"zero version":        mutate(t, sealed, func(raw []byte) { raw[0] = 0 }),
		"implausible version": mutate(t, sealed, func(raw []byte) { raw[0] = cookieEnvelopeMaxVersion + 1 }),
		// A kind that is neither of ours says the value is not one of
		// our envelopes, not that somebody switched the service
		// between store-less and store mode.
		"zero kind":        mutate(t, sealed, func(raw []byte) { raw[1] = 0 }),
		"implausible kind": mutate(t, sealed, func(raw []byte) { raw[1] = 99 }),
		"kind 255":         mutate(t, sealed, func(raw []byte) { raw[1] = 255 }),
	}

	for name, value := range cases {
		_, _, err := keyring.open("cookie:token", value)
		if !errors.Is(err, ErrNotSealed) {
			t.Errorf("open a %s value: got %v, want ErrNotSealed", name, err)
		}
	}
}

func TestCookieEnvelopeUnknownVersion(t *testing.T) {
	keyring, _ := envelopeTestKeyring(t)

	const domain = "cookie:token"

	value, err := keyring.seal(domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// A plausible envelope from a howdah that emits a newer format, which
	// is what a rollback looks like.
	for version := byte(cookieEnvelopeV1 + 1); version <= cookieEnvelopeMaxVersion; version++ {
		newer := mutate(t, value, func(raw []byte) {
			raw[0] = version
		})

		_, _, err := keyring.open(domain, newer)
		if !errors.Is(err, ErrUnknownVersion) {
			t.Errorf("open a version %d envelope: got %v, want ErrUnknownVersion",
				version, err)
		}
	}
}

// TestCookieEnvelopeWrongSessionKind covers both halves of the kind check:
// a value from the other mode is rejected without the reader holding its
// key at all, and an edited kind byte fails authentication because the kind
// is covered by the AAD.
func TestCookieEnvelopeWrongSessionKind(t *testing.T) {
	keyring, stranger := envelopeTestKeyring(t)

	const domain = "cookie:token"

	// Sealed by a key our keyring does not have. Getting
	// ErrWrongSessionKind rather than ErrUnknownKey is what proves the
	// kind is checked before the keyring is consulted.
	foreign, err := stranger.sealKind(
		sessionKindPayload, domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	_, _, err = keyring.openKind(sessionKindHandle, domain, foreign)
	if !errors.Is(err, ErrWrongSessionKind) {
		t.Errorf("read a payload envelope as a handle: got %v, want ErrWrongSessionKind",
			err)
	}

	// And the other direction.
	handle, err := keyring.sealKind(
		sessionKindHandle, domain, []byte("a handle"))
	if err != nil {
		t.Fatalf("seal a handle: %v", err)
	}

	_, _, err = keyring.open(domain, handle)
	if !errors.Is(err, ErrWrongSessionKind) {
		t.Errorf("read a handle envelope as a payload: got %v, want ErrWrongSessionKind",
			err)
	}

	payload, err := keyring.sealKind(
		sessionKindPayload, domain, []byte("session payload"))
	if err != nil {
		t.Fatalf("seal a payload: %v", err)
	}

	relabelled := mutate(t, payload, func(raw []byte) {
		raw[1] = byte(sessionKindHandle)
	})

	_, _, err = keyring.openKind(sessionKindHandle, domain, relabelled)
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("read a relabelled payload envelope: got %v, want ErrAuthentication",
			err)
	}
}
