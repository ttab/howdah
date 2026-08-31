package howdah

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// testCookieSecret returns a deterministic 32 byte secret. The key ids the
// seeds derive are pinned by TestCookieKeyID.
func testCookieSecret(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, cookieKeySecretLength)
}

// discardKeyringLogs keeps the sealing key line out of the test output
// without touching the process-wide default logger.
func discardKeyringLogs() CookieKeyringOption {
	return WithCookieKeyLogger(slog.New(slog.DiscardHandler))
}

func newTestKeyring(t *testing.T, keys ...CookieKey) *CookieKeyring {
	t.Helper()

	keyring, err := NewCookieKeyring(keys, discardKeyringLogs())
	if err != nil {
		t.Fatalf("create keyring: %v", err)
	}

	return keyring
}

func testTime(t *testing.T, value string) time.Time {
	t.Helper()

	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}

	return ts
}

// testSealingKID is the hex key id the keyring would seal with right now.
func testSealingKID(t *testing.T, keyring *CookieKeyring) string {
	t.Helper()

	kid, _ := keyring.SealingKey()

	return kid
}

// testKID is the hex key id a secret derives, for comparing against
// SealingKey.
func testKID(secret []byte) string {
	kid := cookieKeyID(secret)

	return hex.EncodeToString(kid[:])
}

// clearAmbientCookieKeys unsets every variable with the given prefix that
// the developer's own environment happens to hold. Under ttrun or direnv in
// an application that already configures cookie keys that is a real risk,
// and CookieKeyringFromEnv sweeps the whole environment rather than reading
// the one variable a test set.
func clearAmbientCookieKeys(t *testing.T, prefix string) {
	t.Helper()

	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")

		if !strings.HasPrefix(name, prefix) {
			continue
		}

		err := os.Unsetenv(name)
		if err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}

		t.Cleanup(func() {
			err := os.Setenv(name, value)
			if err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
		})
	}
}

// TestCookieKeyID pins the key id derivation. Changing it invalidates every
// outstanding cookie in the fleet, so it must be a deliberate act with a
// new envelope version, not a refactoring accident.
func TestCookieKeyID(t *testing.T) {
	want := map[byte]string{
		1: "869663c12c0965fd",
		2: "579c3eea8c3b6bd4",
		3: "01ca27196f015fb5",
	}

	for seed, expected := range want {
		kid := cookieKeyID(testCookieSecret(seed))

		if got := hex.EncodeToString(kid[:]); got != expected {
			t.Errorf("key id for secret %d = %s, want %s",
				seed, got, expected)
		}
	}
}

func TestNewCookieKeyringErrors(t *testing.T) {
	past := testTime(t, "2020-01-01T00:00:00Z")
	future := testTime(t, "3000-01-01T00:00:00Z")

	cases := map[string][]CookieKey{
		"no keys at all": {},
		"short secret": {
			{UseAfter: past, Secret: []byte("too short")},
		},
		"long secret": {
			{UseAfter: past, Secret: bytes.Repeat([]byte{1}, 33)},
		},
		"no eligible key": {
			{UseAfter: future, Secret: testCookieSecret(1)},
			{UseAfter: future.AddDate(1, 0, 0), Secret: testCookieSecret(2)},
		},
		"tied use-after": {
			{UseAfter: past, Secret: testCookieSecret(1)},
			{UseAfter: past, Secret: testCookieSecret(2)},
		},
		// A tie between two keys that are not eligible yet has to fail
		// at the deploy that introduces it. Checking ties only among
		// the eligible keys lets it through, and the coin flip then
		// happens unannounced when the timestamp passes.
		"tied use-after in the future": {
			{UseAfter: past, Secret: testCookieSecret(1)},
			{UseAfter: future, Secret: testCookieSecret(2)},
			{UseAfter: future, Secret: testCookieSecret(3)},
		},
		"same secret twice": {
			{UseAfter: past, Secret: testCookieSecret(1)},
			{UseAfter: past.AddDate(1, 0, 0), Secret: testCookieSecret(1)},
		},
	}

	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			keyring, err := NewCookieKeyring(keys, discardKeyringLogs())
			if err == nil {
				t.Fatalf("got a keyring sealing with %s, want an error",
					testSealingKID(t, keyring))
			}

			t.Logf("got expected error: %v", err)
		})
	}
}

// TestNewCookieKeyringErrorsNameBothKeys covers the errors an operator reads
// during a rollover: a collision is between two keys, so naming one of them
// sends them looking at the wrong variable.
func TestNewCookieKeyringErrorsNameBothKeys(t *testing.T) {
	past := testTime(t, "2020-01-01T00:00:00Z")

	cases := map[string][]CookieKey{
		"tie": {
			{UseAfter: past, Secret: testCookieSecret(1)},
			{UseAfter: past, Secret: testCookieSecret(2)},
		},
		"duplicate secret": {
			{UseAfter: past, Secret: testCookieSecret(1)},
			{UseAfter: past.AddDate(1, 0, 0), Secret: testCookieSecret(1)},
		},
	}

	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewCookieKeyring(keys, discardKeyringLogs())
			if err == nil {
				t.Fatal("got a keyring, want an error")
			}

			for _, want := range []string{"cookie key 1", "cookie key 2"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q",
						err, want)
				}
			}
		})
	}
}

// TestCookieKeyringSelection covers the two selection rules that matter: the
// latest key whose use-after has passed is the one we seal with, and a
// future-dated key opens without ever sealing.
func TestCookieKeyringSelection(t *testing.T) {
	const domain = "cookie:token"

	retired := CookieKey{
		UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
		Secret:   testCookieSecret(1),
	}
	sealing := CookieKey{
		UseAfter: testTime(t, "2021-01-01T00:00:00Z"),
		Secret:   testCookieSecret(2),
	}
	upcoming := CookieKey{
		UseAfter: testTime(t, "3000-01-01T00:00:00Z"),
		Secret:   testCookieSecret(3),
	}

	keyring := newTestKeyring(t, retired, sealing, upcoming)

	if len(keyring.keys) != 3 {
		t.Errorf("keyring holds %d keys, want 3", len(keyring.keys))
	}

	kid, useAfter := keyring.SealingKey()

	if want := testKID(sealing.Secret); kid != want {
		t.Errorf("sealing with key %s, want %s", kid, want)
	}

	if !useAfter.Equal(sealing.UseAfter) {
		t.Errorf("sealing key use-after is %s, want %s",
			useAfter, sealing.UseAfter)
	}

	value, err := keyring.seal(domain, []byte("hello"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	_, current, err := keyring.open(domain, value)
	if err != nil {
		t.Fatalf("open own value: %v", err)
	}

	if !current {
		t.Error("a value we just sealed is not current")
	}

	// A replica whose clock has crossed the use-after boundary seals with
	// the upcoming key. Our keyring must open that, and report it as not
	// current so that it gets re-sealed on the way out.
	ahead := newTestKeyring(t, CookieKey{
		UseAfter: testTime(t, "2020-06-01T00:00:00Z"),
		Secret:   upcoming.Secret,
	})

	value, err = ahead.seal(domain, []byte("hello"))
	if err != nil {
		t.Fatalf("seal with the upcoming key: %v", err)
	}

	plaintext, current, err := keyring.open(domain, value)
	if err != nil {
		t.Fatalf("open a value sealed with a future-dated key: %v", err)
	}

	if string(plaintext) != "hello" {
		t.Errorf("opened %q, want %q", plaintext, "hello")
	}

	if current {
		t.Error("a value sealed with a future-dated key is reported as current")
	}
}

// TestCookieKeyringCrossesUseAfter is the rollover the whole use-after
// design exists for: a running process must start sealing with a key when
// that key's timestamp passes, without a restart. Pick the sealing key once
// at construction and no replica ever crosses the boundary, so the runbook's
// drain step — old values opened and re-sealed under the new key — never
// happens and dropping the old key logs out the entire fleet at once.
func TestCookieKeyringCrossesUseAfter(t *testing.T) {
	const domain = "cookie:token"

	boundary := time.Now().Add(100 * time.Millisecond)

	sealing := CookieKey{
		UseAfter: boundary.Add(-time.Hour),
		Secret:   testCookieSecret(1),
	}
	upcoming := CookieKey{
		UseAfter: boundary,
		Secret:   testCookieSecret(2),
	}

	keyring := newTestKeyring(t, sealing, upcoming)

	if got, want := testSealingKID(t, keyring), testKID(sealing.Secret); got != want {
		t.Fatalf("before the boundary the keyring seals with %s, want %s",
			got, want)
	}

	before, err := keyring.seal(domain, []byte("sealed under the old key"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	time.Sleep(time.Until(boundary) + 50*time.Millisecond)

	if got, want := testSealingKID(t, keyring), testKID(upcoming.Secret); got != want {
		t.Fatalf("after the boundary the keyring seals with %s, want %s",
			got, want)
	}

	after, err := keyring.seal(domain, []byte("sealed under the new key"))
	if err != nil {
		t.Fatalf("seal after the boundary: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(after)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	if got, want := hex.EncodeToString(raw[2:2+cookieKeyIDLength]),
		testKID(upcoming.Secret); got != want {
		t.Errorf("the envelope names key %s, want %s", got, want)
	}

	// The value from before the boundary still opens — it has to, or the
	// rollover is a logout — but it is no longer current, which is what
	// makes the caller re-seal it.
	_, current, err := keyring.open(domain, before)
	if err != nil {
		t.Fatalf("open a value sealed before the boundary: %v", err)
	}

	if current {
		t.Error("a value sealed under the previous key is reported as current")
	}

	_, current, err = keyring.open(domain, after)
	if err != nil {
		t.Fatalf("open a value sealed after the boundary: %v", err)
	}

	if !current {
		t.Error("a value sealed under the new key is not current")
	}
}

// TestCookieKeyringNotInitialised covers a keyring that never came out of
// NewCookieKeyring — a caller that ignored the constructor's error, or a
// zero value. It has to be an error rather than a nil dereference on every
// request that carries a cookie.
func TestCookieKeyringNotInitialised(t *testing.T) {
	for name, keyring := range map[string]*CookieKeyring{
		"nil":        nil,
		"zero value": {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keyring.seal("cookie:token", []byte("hello"))
			if err == nil {
				t.Error("sealed a value with an uninitialised keyring")
			}

			_, _, err = keyring.open("cookie:token", "whatever")
			if err == nil {
				t.Error("opened a value with an uninitialised keyring")
			}

			if kid, _ := keyring.SealingKey(); kid != "" {
				t.Errorf("an uninitialised keyring seals with %q", kid)
			}
		})
	}
}

// TestCookieKeyringLogger pins the sealing key line to the logger the
// caller passed. It is the only warning an operator gets that a key has
// been dated wrongly, and a keyring built early in main can easily be
// constructed before the application has installed its own handler.
func TestCookieKeyringLogger(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	_, err := NewCookieKeyring([]CookieKey{
		{
			UseAfter: testTime(t, "2020-01-01T00:00:00Z"),
			Secret:   testCookieSecret(1),
		},
		{
			UseAfter: testTime(t, "3000-01-01T00:00:00Z"),
			Secret:   testCookieSecret(2),
		},
	}, WithCookieKeyLogger(logger))
	if err != nil {
		t.Fatalf("create keyring: %v", err)
	}

	var line struct {
		Message      string `json:"msg"`
		KID          string `json:"kid"`
		UseAfter     string `json:"use_after"`
		NextKID      string `json:"next_kid"`
		NextUseAfter string `json:"next_use_after"`
	}

	err = json.Unmarshal(buf.Bytes(), &line)
	if err != nil {
		t.Fatalf("parse the log line %q: %v", buf.String(), err)
	}

	want := map[string]string{
		"msg":            "selected cookie sealing key",
		"kid":            testKID(testCookieSecret(1)),
		"use_after":      "2020-01-01T00:00:00Z",
		"next_kid":       testKID(testCookieSecret(2)),
		"next_use_after": "3000-01-01T00:00:00Z",
	}

	got := map[string]string{
		"msg":            line.Message,
		"kid":            line.KID,
		"use_after":      line.UseAfter,
		"next_kid":       line.NextKID,
		"next_use_after": line.NextUseAfter,
	}

	for key, value := range want {
		if got[key] != value {
			t.Errorf("log line %s is %q, want %q",
				key, got[key], value)
		}
	}
}

func TestCookieKeyringFromEnv(t *testing.T) {
	clearAmbientCookieKeys(t, DefaultCookieKeyPrefix)

	secret := base64.StdEncoding.EncodeToString(testCookieSecret(1))

	t.Setenv(DefaultCookieKeyPrefix+"1", "2020-01-01T00:00:00Z_"+secret)

	keyring, err := CookieKeyringFromEnv(discardKeyringLogs())
	if err != nil {
		t.Fatalf("read keyring from the environment: %v", err)
	}

	kid, useAfter := keyring.SealingKey()

	if want := testKID(testCookieSecret(1)); kid != want {
		t.Errorf("sealing with key %s, want %s", kid, want)
	}

	if !useAfter.Equal(testTime(t, "2020-01-01T00:00:00Z")) {
		t.Errorf("use-after is %s, want 2020-01-01T00:00:00Z", useAfter)
	}
}

func TestCookieKeyringFromEnvPrefix(t *testing.T) {
	const prefix = "TEST_COOKIE_KEY_"

	t.Setenv(prefix+"1", "2020-01-01T00:00:00Z_"+
		base64.StdEncoding.EncodeToString(testCookieSecret(1)))
	t.Setenv(prefix+"2", "2021-01-01T00:00:00Z_"+
		base64.StdEncoding.EncodeToString(testCookieSecret(2)))

	// The default prefix must not be consulted when another one is asked
	// for.
	t.Setenv(DefaultCookieKeyPrefix+"1", "garbage")

	keyring, err := CookieKeyringFromEnv(
		WithCookieKeyPrefix(prefix), discardKeyringLogs())
	if err != nil {
		t.Fatalf("read keyring from the environment: %v", err)
	}

	if len(keyring.keys) != 2 {
		t.Errorf("keyring holds %d keys, want 2", len(keyring.keys))
	}

	if got, want := testSealingKID(t, keyring),
		testKID(testCookieSecret(2)); got != want {
		t.Errorf("sealing with key %s, want %s", got, want)
	}
}

// TestCookieKeyringFromEnvNamesVariables pins the variable name into the
// errors. An operator reads these mid-rollover, and the numbering in the
// environment stops matching the position in the keyring as soon as a key
// is dropped without renumbering — which the runbook's last step invites.
func TestCookieKeyringFromEnvNamesVariables(t *testing.T) {
	const prefix = "TEST2_COOKIE_KEY_"

	secret := base64.StdEncoding.EncodeToString(testCookieSecret(1))

	t.Setenv(prefix+"9", "2020-01-01T00:00:00Z_"+
		base64.StdEncoding.EncodeToString(testCookieSecret(2)))
	t.Setenv(prefix+"10", "2021-01-01T00:00:00Z_"+secret)
	t.Setenv(prefix+"11", "2022-01-01T00:00:00Z_"+secret)

	_, err := CookieKeyringFromEnv(
		WithCookieKeyPrefix(prefix), discardKeyringLogs())
	if err == nil {
		t.Fatal("got a keyring, want an error")
	}

	for _, want := range []string{prefix + "10", prefix + "11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestCookieKeyringFromEnvEmptyPrefix covers an application that plumbs the
// prefix from its own configuration and leaves it unset: every variable in
// the process would otherwise be read as a cookie key, and the startup
// error would name an unrelated one.
func TestCookieKeyringFromEnvEmptyPrefix(t *testing.T) {
	_, err := CookieKeyringFromEnv(
		WithCookieKeyPrefix(""), discardKeyringLogs())
	if err == nil {
		t.Fatal("got a keyring from an empty prefix, want an error")
	}

	// Failing on whichever unrelated variable happened to sort first is
	// also an error, and it is the failure this test exists to reject:
	// the message has to point at the prefix.
	if !strings.Contains(err.Error(), "prefix") {
		t.Errorf("error %q does not mention the prefix", err)
	}
}

func TestCookieKeyringFromEnvErrors(t *testing.T) {
	const prefix = "TEST_COOKIE_KEY_"

	secret := base64.StdEncoding.EncodeToString(testCookieSecret(1))

	cases := map[string]map[string]string{
		"no keys at all": {},
		"missing separator": {
			"1": "2020-01-01T00:00:00Z" + secret,
		},
		"unparseable timestamp": {
			"1": "yesterday_" + secret,
		},
		"empty timestamp": {
			"1": "_" + secret,
		},
		"secret is not base64": {
			"1": "2020-01-01T00:00:00Z_not base64",
		},
		"wrong secret length": {
			"1": "2020-01-01T00:00:00Z_" +
				base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		},
		"tied use-after": {
			"1": "2020-01-01T00:00:00Z_" + secret,
			"2": "2020-01-01T00:00:00Z_" +
				base64.StdEncoding.EncodeToString(testCookieSecret(2)),
		},
		"every key is future-dated": {
			"1": "3000-01-01T00:00:00Z_" + secret,
		},
	}

	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for suffix, value := range env {
				t.Setenv(prefix+suffix, value)
			}

			keyring, err := CookieKeyringFromEnv(
				WithCookieKeyPrefix(prefix), discardKeyringLogs())
			if err == nil {
				t.Fatalf("got a keyring sealing with %s, want an error",
					testSealingKID(t, keyring))
			}

			t.Logf("got expected error: %v", err)
		})
	}
}

func TestGenerateCookieKey(t *testing.T) {
	first, err := GenerateCookieKey()
	if err != nil {
		t.Fatalf("generate cookie key: %v", err)
	}

	second, err := GenerateCookieKey()
	if err != nil {
		t.Fatalf("generate cookie key: %v", err)
	}

	if first == second {
		t.Fatal("two generated keys are identical")
	}

	// The generated secret is the second half of an environment variable
	// value, so it has to parse as one once a timestamp is prefixed.
	key, err := parseCookieKey("2020-01-01T00:00:00Z_" + first)
	if err != nil {
		t.Fatalf("parse a generated key: %v", err)
	}

	if len(key.Secret) != cookieKeySecretLength {
		t.Errorf("generated secret is %d bytes, want %d",
			len(key.Secret), cookieKeySecretLength)
	}

	_, err = NewCookieKeyring([]CookieKey{key}, discardKeyringLogs())
	if err != nil {
		t.Errorf("build a keyring from a generated key: %v", err)
	}
}
