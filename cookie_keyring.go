package howdah

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"
)

// DefaultCookieKeyPrefix is the environment variable prefix cookie keys are
// read from unless an application says otherwise.
const DefaultCookieKeyPrefix = "COOKIE_KEY_"

// cookieKeySecretLength is the length of a cookie key secret: AES-256 takes
// a 32 byte key, and anything else is a startup error rather than a runtime
// surprise.
const cookieKeySecretLength = 32

// cookieKeyIDLabel is mixed into the key id derivation, so the id is a
// function of the secret and of this particular use of it.
const cookieKeyIDLabel = "howdah-cookie-key-v1"

// CookieKey is one key in a CookieKeyring.
type CookieKey struct {
	// UseAfter is when the key starts being used for sealing. Every
	// configured key opens, whether or not UseAfter has passed.
	UseAfter time.Time
	// Secret is the AES-256 key, exactly 32 bytes.
	Secret []byte
}

// cookieKey is a validated key with its cipher built. Parsing, validation
// and AEAD construction all happen at startup; nothing in the request path
// reads an environment variable or derives a key.
type cookieKey struct {
	kid      [cookieKeyIDLength]byte
	useAfter time.Time
	aead     cipher.AEAD
}

// CookieKeyring seals and opens the values howdah stores in cookies. It is
// immutable once built, and safe for concurrent use.
type CookieKeyring struct {
	keys map[[cookieKeyIDLength]byte]*cookieKey
	// byUseAfter holds every key, latest UseAfter first, so that
	// sealingKey can pick the current one with a walk.
	byUseAfter []*cookieKey
}

// NewCookieKeyring validates keys and builds a cipher for each of them. The
// key to seal with is the one whose UseAfter is the latest of those that
// have passed, and it is chosen per call rather than here — see sealingKey.
//
// No keys at all is an error, and so is no eligible key — a fresh
// environment handed the fleet's rollover-dated key must fail here rather
// than boot cleanly and fail on the first login. Two keys sharing a
// UseAfter is an error too, rather than a coin flip.
func NewCookieKeyring(
	keys []CookieKey, opts ...CookieKeyringOption,
) (*CookieKeyring, error) {
	// The keys came in as a slice, so their position is the only name
	// they have. CookieKeyringFromEnv passes variable names instead.
	labels := make([]string, len(keys))

	for i := range keys {
		labels[i] = fmt.Sprintf("cookie key %d", i+1)
	}

	return newCookieKeyring(keys, labels,
		resolveCookieKeyringConf(opts))
}

// newCookieKeyring builds the keyring from keys labelled by whatever named
// them to the operator: an environment variable, or a position in a slice.
// Every error it reports is read during a key rollover, so it names the
// offending key — both of them, where two keys collide.
func newCookieKeyring(
	keys []CookieKey, labels []string, conf cookieKeyringConf,
) (*CookieKeyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("no cookie keys configured")
	}

	k := CookieKeyring{
		keys:       make(map[[cookieKeyIDLength]byte]*cookieKey, len(keys)),
		byUseAfter: make([]*cookieKey, 0, len(keys)),
	}

	var (
		kidLabels      = make(map[[cookieKeyIDLength]byte]string, len(keys))
		useAfterLabels = make(map[cookieKeyInstant]string, len(keys))
	)

	for i, key := range keys {
		label := labels[i]

		if len(key.Secret) != cookieKeySecretLength {
			return nil, fmt.Errorf("%s: secret must be %d bytes, got %d",
				label, cookieKeySecretLength, len(key.Secret))
		}

		block, err := aes.NewCipher(key.Secret)
		if err != nil {
			return nil, fmt.Errorf("%s: create cipher: %w", label, err)
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("%s: create GCM: %w", label, err)
		}

		entry := cookieKey{
			kid:      cookieKeyID(key.Secret),
			useAfter: key.UseAfter,
			aead:     aead,
		}

		if other, ok := kidLabels[entry.kid]; ok {
			return nil, fmt.Errorf(
				"%s and %s hold the same secret, key id %s",
				other, label, hex.EncodeToString(entry.kid[:]))
		}

		// Ties are checked across every configured key, not just the
		// eligible ones. Two future-dated keys sharing a UseAfter
		// would otherwise pass the deploy that introduces them and
		// become a silent coin flip the moment the timestamp passes,
		// which is a long way from the change that caused it.
		instant := newCookieKeyInstant(key.UseAfter)

		if other, ok := useAfterLabels[instant]; ok {
			return nil, fmt.Errorf(
				"%s and %s share the use-after %s, so the sealing key would be a coin flip",
				other, label, key.UseAfter.Format(time.RFC3339))
		}

		kidLabels[entry.kid] = label
		useAfterLabels[instant] = label

		k.keys[entry.kid] = &entry
		k.byUseAfter = append(k.byUseAfter, &entry)
	}

	slices.SortFunc(k.byUseAfter, func(a, b *cookieKey) int {
		return b.useAfter.Compare(a.useAfter)
	})

	sealWith := k.sealingKey()
	if sealWith == nil {
		return nil, errors.New(
			"no cookie key is eligible for sealing: every configured key is dated in the future")
	}

	// The opposite operator error to a missing key — a new key dated in
	// the past by accident — starts sealing on the first replica to
	// notice while its siblings cannot open the result. There is no way
	// to prevent that in code; this is the log line that makes it
	// visible, and SealingKey is here for applications that would rather
	// log it themselves.
	attrs := []any{
		"kid", hex.EncodeToString(sealWith.kid[:]),
		"use_after", sealWith.useAfter.Format(time.RFC3339),
		"keyring_size", len(k.keys),
	}

	// byUseAfter is sorted latest first, so the entry before the sealing
	// key is the next one to take over.
	if i := slices.Index(k.byUseAfter, sealWith); i > 0 {
		next := k.byUseAfter[i-1]

		attrs = append(attrs,
			"next_kid", hex.EncodeToString(next.kid[:]),
			"next_use_after", next.useAfter.Format(time.RFC3339))
	}

	conf.logger.Info("selected cookie sealing key", attrs...)

	return &k, nil
}

// sealingKey returns the key to seal with now: of the keys whose UseAfter
// has passed, the one with the latest UseAfter.
//
// The choice is made per call rather than at construction because a replica
// has to start sealing with a key when that key's UseAfter passes. Freezing
// the choice at startup means no running process ever crosses the boundary,
// so the runbook's drain window — where values under the old key are opened
// and re-sealed under the new one — never opens, and dropping the old key
// logs out the entire fleet at once.
//
// It stays cheap enough for the request path: a walk over a pre-sorted
// slice of two or three pointers, with no allocation, no environment read
// and no key derivation.
func (k *CookieKeyring) sealingKey() *cookieKey {
	if k == nil {
		return nil
	}

	now := time.Now()

	for _, key := range k.byUseAfter {
		if !key.useAfter.After(now) {
			return key
		}
	}

	return nil
}

// SealingKey returns the hex key id and the UseAfter of the key values are
// sealed under right now. The answer moves as a key's UseAfter passes, so
// it is a snapshot rather than a constant: it is what an application logs
// through its own logger, and what the rollover runbook checks against.
func (k *CookieKeyring) SealingKey() (string, time.Time) {
	key := k.sealingKey()
	if key == nil {
		return "", time.Time{}
	}

	return hex.EncodeToString(key.kid[:]), key.useAfter
}

// cookieKeyInstant identifies a UseAfter exactly, and is comparable so it
// can key a map. UnixNano would be tidier but overflows outside
// 1678-2262, and a keyring is allowed to hold an absurdly future-dated key.
type cookieKeyInstant struct {
	seconds     int64
	nanoseconds int
}

func newCookieKeyInstant(t time.Time) cookieKeyInstant {
	return cookieKeyInstant{
		seconds:     t.Unix(),
		nanoseconds: t.Nanosecond(),
	}
}

// CookieKeyringFromEnv reads the keyring from the environment. Each key is
// its own variable:
//
//	COOKIE_KEY_1=2026-08-01T00:00:00Z_TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IA==
//	COOKIE_KEY_2=2026-09-15T00:00:00Z_aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXIgcGE=
//
// The value is an RFC 3339 timestamp and the standard base64 of exactly 32
// bytes, separated by an underscore. See NewCookieKeyring for how the
// sealing key is picked, and GenerateCookieKey for making a secret.
func CookieKeyringFromEnv(opts ...CookieKeyringOption) (*CookieKeyring, error) {
	conf := resolveCookieKeyringConf(opts)

	// Without this an empty prefix matches every variable in the
	// process, and the startup error names whichever unrelated one
	// failed to parse first.
	if conf.prefix == "" {
		return nil, errors.New("the cookie key environment prefix must not be empty")
	}

	var names []string

	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")

		if strings.HasPrefix(name, conf.prefix) && len(name) > len(conf.prefix) {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil, fmt.Errorf(
			"no cookie keys configured, expected at least one %s* environment variable",
			conf.prefix)
	}

	// Sorted so that the keyring is the same on every replica whatever
	// order the environment came in.
	slices.Sort(names)

	keys := make([]CookieKey, 0, len(names))

	for _, name := range names {
		key, err := parseCookieKey(os.Getenv(name))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		keys = append(keys, key)
	}

	return newCookieKeyring(keys, names, conf)
}

// cookieKeyringConf is the configuration a keyring is built with.
type cookieKeyringConf struct {
	prefix string
	logger *slog.Logger
}

// CookieKeyringOption configures NewCookieKeyring and
// CookieKeyringFromEnv.
type CookieKeyringOption func(*cookieKeyringConf)

func resolveCookieKeyringConf(opts []CookieKeyringOption) cookieKeyringConf {
	conf := cookieKeyringConf{
		prefix: DefaultCookieKeyPrefix,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(&conf)
	}

	if conf.logger == nil {
		conf.logger = slog.Default()
	}

	return conf
}

// WithCookieKeyPrefix reads the keys from a different environment variable
// prefix. An application only needs this if it hosts two independent
// keyrings; everything else stays on DefaultCookieKeyPrefix, so that one
// secret naming convention holds across the fleet. Ignored by
// NewCookieKeyring, which is handed its keys.
func WithCookieKeyPrefix(prefix string) CookieKeyringOption {
	return func(conf *cookieKeyringConf) {
		conf.prefix = prefix
	}
}

// WithCookieKeyLogger writes the sealing key line to the application's own
// logger rather than to slog.Default(). Worth passing: the line is the only
// warning an operator gets that a key has been dated wrongly, and a
// constructor called early in main can easily run before the application
// has installed its handler.
func WithCookieKeyLogger(logger *slog.Logger) CookieKeyringOption {
	return func(conf *cookieKeyringConf) {
		conf.logger = logger
	}
}

// GenerateCookieKey returns the standard base64 of a new 32 byte cookie key
// secret. Prefix it with the RFC 3339 timestamp the key should start
// sealing after, separated by an underscore, to get the value of a
// COOKIE_KEY_* variable:
//
//	COOKIE_KEY_2=2026-09-15T00:00:00Z_<secret>
//
// The timestamp is deliberately not this function's to pick: it has to be
// far enough ahead that the rollout finishes first, since no replica may
// seal with a key another replica hasn't got yet.
func GenerateCookieKey() (string, error) {
	secret := make([]byte, cookieKeySecretLength)

	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(secret), nil
}

// parseCookieKey parses the value of a COOKIE_KEY_* environment variable.
func parseCookieKey(value string) (CookieKey, error) {
	// RFC 3339 contains no underscore, so splitting on the first one is
	// unambiguous whatever alphabet the secret uses.
	timestamp, secret, ok := strings.Cut(value, "_")
	if !ok {
		return CookieKey{}, errors.New(
			"expected an RFC 3339 timestamp and a base64 secret separated by an underscore")
	}

	// The timestamp is echoed into the error below, and it cannot be a
	// fragment of the secret: standard base64 has no underscore, so a
	// value that is nothing but a pasted secret takes the branch above
	// instead of splitting somewhere inside it.
	useAfter, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return CookieKey{}, fmt.Errorf("parse use-after timestamp: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return CookieKey{}, fmt.Errorf("decode secret: %w", err)
	}

	if len(data) != cookieKeySecretLength {
		return CookieKey{}, fmt.Errorf("secret must be %d bytes, got %d",
			cookieKeySecretLength, len(data))
	}

	return CookieKey{
		UseAfter: useAfter,
		Secret:   data,
	}, nil
}

// cookieKeyID derives a key's id from the secret rather than from the
// number in its variable name. Reusing COOKIE_KEY_1 for a new secret then
// makes outstanding cookies come back as ErrUnknownKey — routine rotation
// noise — instead of as ErrAuthentication, which is the signal that stays
// loud because it means tampering or crossed environments.
func cookieKeyID(secret []byte) [cookieKeyIDLength]byte {
	buf := make([]byte, 0, len(cookieKeyIDLabel)+len(secret))

	buf = append(buf, cookieKeyIDLabel...)
	buf = append(buf, secret...)

	sum := sha256.Sum256(buf)

	var kid [cookieKeyIDLength]byte

	copy(kid[:], sum[:])

	return kid
}
