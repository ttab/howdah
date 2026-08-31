// Package pgstore keeps howdah's sessions in Postgres. It is a
// howdah.TokenStore and a howdah.Rekeyer, so an application hands it to
// howdah.WithTokenStore and nothing else changes.
//
// What a row buys over a session sealed into the cookie:
//
//   - **Revocation.** Logout deletes the row, so a copied cookie value dies
//     with it, and DeleteSubject logs one person out of every browser they
//     ever logged in from.
//   - **A session lifetime the server enforces.** A cookie's Expires is an
//     instruction to the browser and means nothing to somebody holding a
//     copied value. The expires_at column is checked on every read.
//   - **One refresh per session, fleet-wide.** A refresh takes a lease in
//     the row, so the several requests of a page load — on however many
//     replicas — collapse onto a single token endpoint round trip. That is
//     what makes it safe to turn refresh token rotation on at the provider:
//     without it the first exchange invalidates the refresh token and every
//     other request comes back invalid_grant and bounces the user to login.
//   - **A key rollover a retired key cannot spoil.** A stored session is
//     sealed in two places, and only the handle in the cookie is re-sealed
//     by the request that carries it; the row moves when a refresh writes
//     it, which is to say never for a session nobody is using. Rekey
//     re-seals the rows, so dropping the old key costs the idle sessions
//     their cookie and nothing else. It does not make that wait shorter —
//     nothing reaches a cookie in a browser that sends no requests.
//
// The cookie holds a sealed handle of about ninety bytes; the tokens live in
// the row, sealed under the same keyring, and the row id is sha256 of the
// handle so that a database dump yields nothing anybody can log in with.
//
// Nothing here starts a goroutine and nothing here migrates a schema. The
// application applies the migrations as a deliberate step (see Migrate) and
// calls DeleteExpired on a schedule of its own.
package pgstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ttab/howdah"
	"github.com/ttab/howdah/tokenstore/pgstore/postgres"
	"golang.org/x/oauth2"
)

// Defaults for everything New takes an option for.
const (
	// DefaultMaxSessionAge is how long a session lives before the user has
	// to log in again, counted from the login and not from the last
	// request.
	DefaultMaxSessionAge = howdah.DefaultMaxSessionAge

	// DefaultRefreshLease is how long a refresher holds the right to do
	// the token endpoint round trip and write the result back. It has to
	// outlast DefaultTokenRequestTimeout plus DefaultWriteTimeout
	// together, or a refresher can lose its lease while still legitimately
	// working — see WithRefreshLease.
	DefaultRefreshLease = 20 * time.Second

	// DefaultTokenRequestTimeout bounds the token endpoint round trip.
	DefaultTokenRequestTimeout = 10 * time.Second

	// DefaultRefreshMargin is how little life an access token may have
	// left before it is worth refreshing. It is only used to recognise a
	// token somebody else just refreshed.
	DefaultRefreshMargin = 10 * time.Second

	// DefaultWriteTimeout bounds the writes that must happen even though
	// the request they belong to is gone: recording a refresh, and
	// recording that one failed.
	DefaultWriteTimeout = 5 * time.Second

	// handleLength is the size of a session handle. It is a random value
	// that identifies a row and nothing more, so 256 bits is ample.
	handleLength = 32

	// leaseNonceLength is the size of the value that fences a refresh
	// write-back.
	leaseNonceLength = 16

	// refreshPollMin and refreshPollMax bound the backoff a caller waiting
	// for somebody else's refresh polls on.
	refreshPollMin = 25 * time.Millisecond
	refreshPollMax = 500 * time.Millisecond
)

// ErrRefreshFailed is what a caller waiting for another caller's refresh
// gets when that refresh failed. It means "the provider said no to the
// exchange that was already in flight", so the right thing to do with it is
// what would have been done with the failure itself: end the session.
//
// It exists so that an identity provider outage costs one exchange per
// session rather than one per request. Without the refresh_failed_at column
// behind it, every waiting caller would poll a refreshed_at that never
// moves, burn its whole backoff, and then attempt an exchange of its own.
//
// It wraps howdah.ErrRefreshRejected, which is what tells OIDCAuth that this
// is a session to end rather than a store to retry. The caller that ran the
// exchange gets the provider's own error, already wrapping the same sentinel;
// a caller that only waited never saw it, so the store supplies it.
var ErrRefreshFailed = fmt.Errorf(
	"%w: a concurrent refresh of the session failed",
	howdah.ErrRefreshRejected)

// ErrRefreshTimeout is what a caller gets when it waited out its budget
// without the refresh it was waiting for either landing or failing. The
// refresher it was waiting for is neither finished nor timed out, which in
// practice means a process that died while holding the lease and a lease
// that has not expired yet.
//
// It deliberately does **not** wrap howdah.ErrRefreshRejected. Nothing here
// says the session is over — the row is intact, and by the time the caller
// reads this another caller may already have refreshed it — so the request
// fails and the next one tries again, rather than the user being logged out
// of a session that was never in danger.
var ErrRefreshTimeout = errors.New("timed out waiting for a concurrent refresh")

// DB is what pgstore reads and writes through: a *pgxpool.Pool, a *pgx.Conn,
// or anything else speaking the same three methods. A pool is what an
// application normally has, and pgstore never holds a connection across
// anything slower than a single statement — the refresh lease exists
// precisely so that no transaction is open while the identity provider is
// being called.
type DB interface {
	Exec(
		ctx context.Context, sql string, arguments ...any,
	) (pgconn.CommandTag, error)
	Query(
		ctx context.Context, sql string, args ...any,
	) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store keeps sessions in Postgres. It is safe for concurrent use by
// multiple goroutines and multiple processes.
type Store struct {
	q      *postgres.Queries
	sealer *howdah.SessionSealer
	conf   conf
}

// Store implements both halves of the store contract.
var (
	_ howdah.TokenStore = (*Store)(nil)
	_ howdah.Rekeyer    = (*Store)(nil)
)

// conf is the resolved configuration of a store.
type conf struct {
	maxSessionAge       time.Duration
	refreshLease        time.Duration
	tokenRequestTimeout time.Duration
	refreshMargin       time.Duration
	writeTimeout        time.Duration
	refreshWait         time.Duration
	refreshWaitSet      bool
}

// Option configures New.
type Option func(*conf)

// WithMaxSessionAge sets the absolute session lifetime, counted from the
// login and not from the last request, so refreshing the access token does
// not extend it.
func WithMaxSessionAge(age time.Duration) Option {
	return func(c *conf) {
		c.maxSessionAge = age
	}
}

// WithRefreshLease sets how long a refresher holds the right to refresh the
// session: the token endpoint round trip **and the write-back afterwards**,
// which is the half that is easy to forget. The lease has to cover both, so
// it must be longer than the token request timeout plus the write timeout
// added together, and New refuses a store where it is not.
//
// The lease is what a caller waits out when the refresher holding it died,
// so it is also the worst case one request pays for a process that was
// killed mid-exchange: too long makes that request slow, and too short lets
// a refresher that is still legitimately working lose its lease to a second
// caller, which posts the same refresh token again. With refresh token
// rotation on, that second exchange is the one that ends the session.
func WithRefreshLease(lease time.Duration) Option {
	return func(c *conf) {
		c.refreshLease = lease
	}
}

// WithTokenRequestTimeout bounds the token endpoint round trip. The exchange
// runs on a context detached from the request, so nothing the client does
// stops it and this is the budget it gets — an upper bound, since the
// exchange is the caller's own function and may hold itself to something
// shorter. howdah's does: OIDCAuth caps a refresh at ten seconds and honours
// whichever of the two deadlines comes first.
//
// It is also half of what sizes the refresh lease, so lowering it is not
// only a matter of how long a request waits: see WithRefreshLease.
//
// An exchange that ignores its context entirely is beyond the store's reach,
// and a lease sized against a timeout nothing honours is a lease a second
// caller can take while the first is still exchanging.
func WithTokenRequestTimeout(timeout time.Duration) Option {
	return func(c *conf) {
		c.tokenRequestTimeout = timeout
	}
}

// WithRefreshMargin sets how little life an access token may have left
// before a refresh is worth doing. It is not what decides that a caller
// refreshes — that is the caller's own margin — but what lets a caller
// recognise that somebody else refreshed the session between its read and
// its call, and use that token instead of exchanging again.
func WithRefreshMargin(margin time.Duration) Option {
	return func(c *conf) {
		c.refreshMargin = margin
	}
}

// WithRefreshWait sets how long a caller waits for another caller's refresh
// before giving up with ErrRefreshTimeout. It defaults to a little over the
// lease, which is what lets a caller outlive a refresher that died holding
// one and take the lease over itself. Shortening it below the lease turns a
// dead refresher into a failed request rather than a slow one.
func WithRefreshWait(wait time.Duration) Option {
	return func(c *conf) {
		c.refreshWait = wait
		c.refreshWaitSet = true
	}
}

// WithWriteTimeout bounds the writes that have to happen even though the
// request they belong to may be gone: recording the result of a refresh, and
// recording that one failed.
func WithWriteTimeout(timeout time.Duration) Option {
	return func(c *conf) {
		c.writeTimeout = timeout
	}
}

// New builds a store over db. The keyring is what the store seals with —
// both the handle that goes in the cookie and the token set that goes in the
// row — and cookieName is the session cookie's name, which is part of what a
// value is sealed against: two applications sharing a host and a keyring
// cannot open each other's sessions. Pass the same name to
// howdah.WithSessionCookieName.
func New(
	db DB, keyring *howdah.CookieKeyring, cookieName string,
	opts ...Option,
) (*Store, error) {
	if db == nil {
		return nil, errors.New("a database is required")
	}

	c := conf{
		maxSessionAge:       DefaultMaxSessionAge,
		refreshLease:        DefaultRefreshLease,
		tokenRequestTimeout: DefaultTokenRequestTimeout,
		refreshMargin:       DefaultRefreshMargin,
		writeTimeout:        DefaultWriteTimeout,
	}

	for _, opt := range opts {
		opt(&c)
	}

	if !c.refreshWaitSet {
		// Long enough that a caller waiting on a refresher that died
		// outlives the lease and gets to take it over, rather than
		// timing out one poll short of it.
		c.refreshWait = c.refreshLease + refreshPollMax
	}

	err := c.validate()
	if err != nil {
		return nil, err
	}

	sealer, err := howdah.NewSessionSealer(keyring, cookieName)
	if err != nil {
		return nil, fmt.Errorf("create the session sealer: %w", err)
	}

	return &Store{
		q:      postgres.New(db),
		sealer: sealer,
		conf:   c,
	}, nil
}

func (c conf) validate() error {
	durations := []struct {
		name  string
		value time.Duration
	}{
		{"the maximum session age", c.maxSessionAge},
		{"the refresh lease", c.refreshLease},
		{"the token request timeout", c.tokenRequestTimeout},
		{"the refresh wait", c.refreshWait},
		{"the write timeout", c.writeTimeout},
	}

	for _, d := range durations {
		if d.value <= 0 {
			return fmt.Errorf("%s must be positive, got %s",
				d.name, d.value)
		}
	}

	if c.refreshMargin < 0 {
		return fmt.Errorf(
			"the refresh margin must not be negative, got %s",
			c.refreshMargin)
	}

	// A lease that expires while its holder is still legitimately working
	// is a lease that lets a second caller post the same refresh token,
	// which is the whole failure this store exists to prevent.
	//
	// The window the lease has to cover is the round trip *and* the
	// write-back, not the round trip alone: the refresher holds the lease
	// from the moment it takes it until CommitRefresh lands, so a lease
	// that only outlasts the exchange expires while the winner is still
	// committing. The winner's own write is safe either way — the nonce
	// fence rejects it — but the duplicate exchange the expired lease
	// authorised in the meantime is not.
	if window := c.tokenRequestTimeout + c.writeTimeout; c.refreshLease <= window {
		return fmt.Errorf(
			"the refresh lease (%s) must be longer than the token request timeout (%s) and the write timeout (%s) together, which is what it has to cover",
			c.refreshLease, c.tokenRequestTimeout, c.writeTimeout)
	}

	return nil
}

// Create stores a new session. The handle is random, the row id is sha256 of
// it, and the tokens are sealed against that id — so the row is useless to
// anybody who has the database but not the cookie, and a payload cannot be
// transplanted into another session's row.
func (s *Store) Create(
	ctx context.Context, session howdah.NewSession,
) (*howdah.StoredToken, error) {
	if session.Token == nil {
		return nil, errors.New("a session needs a token")
	}

	handle := make([]byte, handleLength)

	_, err := rand.Read(handle)
	if err != nil {
		return nil, fmt.Errorf("generate a session handle: %w", err)
	}

	id := sha256.Sum256(handle)

	// The cookie value is produced before the row is written, so a
	// keyring that cannot seal leaves nothing behind.
	value, err := s.sealer.SealHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("seal the session handle: %w", err)
	}

	sealed, kid, err := s.sealPayload(id[:], sessionPayload{
		Version: sessionPayloadV1,
		Subject: session.Subject,
		Token:   session.Token,
		IDToken: session.IDToken,
	})
	if err != nil {
		return nil, err
	}

	row, err := s.q.CreateSession(ctx, postgres.CreateSessionParams{
		ID:              id[:],
		Subject:         session.Subject,
		KeyID:           kid.Bytes(),
		Payload:         sealed,
		AccessExpiresAt: timestamp(session.Token.Expiry),
		MaxSessionAge:   interval(s.conf.maxSessionAge),
	})
	if err != nil {
		return nil, fmt.Errorf("create the session row: %w", err)
	}

	return &howdah.StoredToken{
		Handle:    value,
		Subject:   session.Subject,
		Token:     session.Token,
		IDToken:   session.IDToken,
		IssuedAt:  row.CreatedAt.Time,
		ExpiresAt: row.ExpiresAt.Time,
	}, nil
}

// Get resolves a cookie value to the session it identifies. Everything that
// can go wrong wraps howdah.ErrNoSession, and the reason it wraps alongside
// is what decides how loudly the caller logs it: a handle sealed under a
// retired key is routine, and howdah.ErrAuthentication is not.
//
// The absolute expiry is checked against the database's clock rather than
// this process's, so a replica whose clock has drifted cannot hand out a
// session the others consider dead.
func (s *Store) Get(
	ctx context.Context, handle string,
) (*howdah.StoredToken, error) {
	id, current, err := s.rowID(handle)
	if err != nil {
		return nil, err
	}

	row, err := s.q.GetSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: unknown session handle",
			howdah.ErrNoSession)
	} else if err != nil {
		return nil, fmt.Errorf("read the session row: %w", err)
	}

	if !row.ExpiresAt.Time.After(row.DbNow.Time) {
		return nil, fmt.Errorf("%w: the session expired %s ago",
			howdah.ErrNoSession,
			row.DbNow.Time.Sub(row.ExpiresAt.Time).Round(time.Second))
	}

	payload, err := s.openPayload(id, row.Payload)
	if err != nil {
		return nil, err
	}

	return &howdah.StoredToken{
		Handle:    handle,
		Subject:   payload.Subject,
		Token:     payload.Token,
		IDToken:   payload.IDToken,
		IssuedAt:  row.CreatedAt.Time,
		ExpiresAt: row.ExpiresAt.Time,
		Stale:     !current,
	}, nil
}

// Update replaces the tokens of an existing session, carrying its subject,
// id_token and issued_at forward. It is for an application that obtains a
// token set out of band; a refresh goes through Refresh, which
// deduplicates.
//
// It is deliberately unfenced — it is a write the application asked for, not
// one racing a refresh — so an application that calls it while a refresh of
// the same session is in flight is choosing which of the two wins, and the
// answer is whichever writes last.
func (s *Store) Update(
	ctx context.Context, handle string, tok *oauth2.Token,
) (*howdah.StoredToken, error) {
	if tok == nil {
		return nil, errors.New("a session needs a token")
	}

	session, err := s.Get(ctx, handle)
	if err != nil {
		return nil, err
	}

	id, _, err := s.rowID(handle)
	if err != nil {
		return nil, err
	}

	sealed, kid, err := s.sealPayload(id, sessionPayload{
		Version: sessionPayloadV1,
		Subject: session.Subject,
		Token:   tok,
		IDToken: session.IDToken,
	})
	if err != nil {
		return nil, err
	}

	rows, err := s.q.UpdateSession(ctx, postgres.UpdateSessionParams{
		ID:              id,
		KeyID:           kid.Bytes(),
		Payload:         sealed,
		AccessExpiresAt: timestamp(tok.Expiry),
	})
	if err != nil {
		return nil, fmt.Errorf("write the session row: %w", err)
	}

	if rows == 0 {
		return nil, fmt.Errorf("%w: the session was removed while it was being updated",
			howdah.ErrNoSession)
	}

	session.Token = tok

	return session, nil
}

// Reseal seals the handle again under the key the keyring seals with now,
// and writes nothing at all: the handle it wraps is unchanged, so the row it
// identifies is unchanged too. It is how a session that came in under a
// retiring key migrates to the current one.
//
// The row's own payload is not re-sealed here. That is Rekey's job, because
// it needs the fence a request path has no business taking.
func (s *Store) Reseal(
	_ context.Context, t *howdah.StoredToken,
) (*howdah.StoredToken, error) {
	if t == nil {
		return nil, errors.New("a session is required")
	}

	handle, _, err := s.sealer.OpenHandle(t.Handle)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", howdah.ErrNoSession, err)
	}

	value, err := s.sealer.SealHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("seal the session handle: %w", err)
	}

	resealed := *t
	resealed.Handle = value
	resealed.Stale = false

	return &resealed, nil
}

// Delete removes the session, which is what makes logout a revocation: the
// row is gone, so a copied cookie value stops working everywhere at once.
//
// It is idempotent, and a handle it cannot even open is not an error: there
// is no row it could name, and a logout during a key rollover would
// otherwise report a failure for a session that has already ended.
func (s *Store) Delete(ctx context.Context, handle string) error {
	id, _, err := s.rowID(handle)
	if errors.Is(err, howdah.ErrNoSession) {
		return nil
	} else if err != nil {
		return err
	}

	_, err = s.q.DeleteSession(ctx, id)
	if err != nil {
		return fmt.Errorf("delete the session row: %w", err)
	}

	return nil
}

// DeleteSubject removes every session belonging to one OIDC subject and
// returns how many it removed. This is "log this person out everywhere", and
// it is the thing a store makes possible that a cookie cannot.
func (s *Store) DeleteSubject(
	ctx context.Context, subject string,
) (int64, error) {
	if subject == "" {
		return 0, errors.New("a subject is required")
	}

	deleted, err := s.q.DeleteSubjectSessions(ctx, subject)
	if err != nil {
		return 0, fmt.Errorf("delete the subject's session rows: %w", err)
	}

	return deleted, nil
}

// DeleteExpired removes sessions past their absolute expiry, at most batch
// at a time, and returns how many it removed. Call it until it returns 0.
//
// The application schedules it. An application that already depends on
// elephantine can wrap it in pg.RunInJobLock so that only one replica
// sweeps; one that does not can run it on a ticker and let the replicas
// overlap.
//
// Overlapping sweeps are safe but not necessarily complete on either
// replica. The batch is selected FOR UPDATE SKIP LOCKED in a deterministic
// order, so two sweepers take disjoint batches rather than deadlocking or
// both finding their rows deleted under them — but a sweeper whose remaining
// rows are all locked by the other returns 0 with rows still in the table,
// and the other one deletes them. Which is to say: 0 means "nothing here for
// me right now", not "the table is clean". For a single sweeper, which is
// what a job lock gives, it means both.
func (s *Store) DeleteExpired(
	ctx context.Context, batch int,
) (int64, error) {
	size, err := batchSize(batch)
	if err != nil {
		return 0, err
	}

	deleted, err := s.q.DeleteExpiredSessions(ctx, size)
	if err != nil {
		return 0, fmt.Errorf("delete expired session rows: %w", err)
	}

	return deleted, nil
}

// rowID opens a cookie value and returns the id of the row it names, plus
// whether the value was sealed under the key we seal with now.
func (s *Store) rowID(handle string) ([]byte, bool, error) {
	plaintext, current, err := s.sealer.OpenHandle(handle)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", howdah.ErrNoSession, err)
	}

	// The id is a hash of the handle rather than the handle itself, so a
	// database dump, a backup on a laptop or a read through an injection
	// yields nothing that can be put in a cookie.
	id := sha256.Sum256(plaintext)

	return id[:], current, nil
}

// batchSize checks a batch size and narrows it to what the query takes.
func batchSize(batch int) (int32, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("the batch size must be positive, got %d", batch)
	}

	if batch > math.MaxInt32 {
		return math.MaxInt32, nil
	}

	return int32(batch), nil
}

// timestamp is a time.Time as the queries take it.
func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// interval is a duration as the queries take it. Durations that reach the
// database are deadlines the database computes from its own clock, which is
// the only clock every replica shares.
func interval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{
		Microseconds: d.Microseconds(),
		Valid:        true,
	}
}
