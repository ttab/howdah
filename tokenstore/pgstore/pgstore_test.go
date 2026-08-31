package pgstore_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ttab/eltest"
	"github.com/ttab/howdah"
	"github.com/ttab/howdah/tokenstore/pgstore"
	"golang.org/x/oauth2"
)

func TestMain(m *testing.M) {
	code := m.Run()

	err := eltest.PurgeBackingServices()
	if err != nil {
		log.Printf("purge backing services: %v", err)
	}

	os.Exit(code)
}

// testDB hands the test its own freshly migrated database in a container of
// eltest's, never anything running on the host.
//
// The migrations are applied through pgstore.Migrate rather than through
// eltest's own migrator, which is not incidental: howdah tracks its schema
// version in a table of its own so that its numbering cannot collide with a
// consuming application's, and going through the exported entry point is
// what proves the exported entry point works.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pg := eltest.NewPostgres(t, eltest.Postgres17_6)
	env := pg.Database(t, "pgstore", pgstore.Migrations, false)

	pool, err := pgxpool.New(t.Context(), env.PostgresURI)
	eltest.Must(t, err, "create the connection pool")

	t.Cleanup(pool.Close)

	err = pgstore.Migrate(t.Context(), pool)
	eltest.Must(t, err, "apply howdah's migrations")

	return pool
}

// testKeyring builds a keyring from the given key numbers, each of them
// dated a day further into the past than the last, so that the highest
// number is the key that seals.
func testKeyring(t *testing.T, numbers ...byte) *howdah.CookieKeyring {
	t.Helper()

	if len(numbers) == 0 {
		numbers = []byte{1}
	}

	keys := make([]howdah.CookieKey, 0, len(numbers))

	for i, n := range numbers {
		keys = append(keys, howdah.CookieKey{
			UseAfter: time.Date(2020, 1, 1+i, 0, 0, 0, 0, time.UTC),
			Secret:   bytes.Repeat([]byte{n}, 32),
		})
	}

	keyring, err := howdah.NewCookieKeyring(keys,
		howdah.WithCookieKeyLogger(slog.New(
			slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatalf("create the keyring: %v", err)
	}

	return keyring
}

func testStore(
	t *testing.T, pool *pgxpool.Pool, keyring *howdah.CookieKeyring,
	opts ...pgstore.Option,
) *pgstore.Store {
	t.Helper()

	store, err := pgstore.New(pool, keyring, "token", opts...)
	if err != nil {
		t.Fatalf("create the store: %v", err)
	}

	return store
}

func testToken(access string, expiresIn time.Duration) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  access,
		TokenType:    "Bearer",
		RefreshToken: access + "-refresh",
		Expiry:       time.Now().Add(expiresIn),
	}
}

func TestSessionRoundTrip(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	created, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", time.Hour),
		IDToken: "the.id.token",
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	// The cookie only names the session, so it stays small however big
	// the token set is.
	if len(created.Handle) > 128 {
		t.Errorf("the handle is %d bytes, expected a short one",
			len(created.Handle))
	}

	if created.ExpiresAt.Sub(created.IssuedAt) < time.Hour {
		t.Errorf("the session expires %s after it was issued",
			created.ExpiresAt.Sub(created.IssuedAt))
	}

	got, err := store.Get(t.Context(), created.Handle)
	if err != nil {
		t.Fatalf("get the session: %v", err)
	}

	if got.Subject != "user-1" {
		t.Errorf("got the subject %q, want %q", got.Subject, "user-1")
	}

	if got.Token.AccessToken != "access-1" {
		t.Errorf("got the access token %q, want %q",
			got.Token.AccessToken, "access-1")
	}

	if got.Token.RefreshToken != "access-1-refresh" {
		t.Errorf("got the refresh token %q, want %q",
			got.Token.RefreshToken, "access-1-refresh")
	}

	// The id_token is kept, unlike in a session sealed into a cookie:
	// RP-initiated logout needs it and there is no getting it back later.
	if got.IDToken != "the.id.token" {
		t.Errorf("got the id token %q, want %q",
			got.IDToken, "the.id.token")
	}

	if got.Stale {
		t.Error("the session came back stale under its own sealing key")
	}

	updated, err := store.Update(
		t.Context(), created.Handle, testToken("access-2", time.Hour))
	if err != nil {
		t.Fatalf("update the session: %v", err)
	}

	// A stored session's handle does not move, which is what lets the
	// caller write a Set-Cookie only when something changed.
	if updated.Handle != created.Handle {
		t.Error("the handle moved on an update")
	}

	if !updated.IssuedAt.Equal(created.IssuedAt) {
		t.Errorf("the issued_at moved from %s to %s",
			created.IssuedAt, updated.IssuedAt)
	}

	got, err = store.Get(t.Context(), created.Handle)
	if err != nil {
		t.Fatalf("get the updated session: %v", err)
	}

	if got.Token.AccessToken != "access-2" {
		t.Errorf("got the access token %q, want %q",
			got.Token.AccessToken, "access-2")
	}

	if got.IDToken != "the.id.token" {
		t.Errorf("the update dropped the id token")
	}

	err = store.Delete(t.Context(), created.Handle)
	if err != nil {
		t.Fatalf("delete the session: %v", err)
	}

	_, err = store.Get(t.Context(), created.Handle)
	if !errors.Is(err, howdah.ErrNoSession) {
		t.Errorf("got %v after the delete, want ErrNoSession", err)
	}

	// Idempotent: a second logout, a retried request, or two replicas
	// deleting the same session must not be an error.
	err = store.Delete(t.Context(), created.Handle)
	if err != nil {
		t.Errorf("delete the session again: %v", err)
	}
}

func TestGetExpiredSession(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t),
		pgstore.WithMaxSessionAge(200*time.Millisecond))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		// An access token with plenty of life left: it is the
		// session's own expiry that ends this, not the token's.
		Token: testToken("access-1", time.Hour),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	_, err = store.Get(t.Context(), session.Handle)
	if !errors.Is(err, howdah.ErrNoSession) {
		t.Fatalf("got %v for an expired session, want ErrNoSession", err)
	}

	// The row is still there until it is swept, which is what makes the
	// expiry a check the server does rather than a promise the browser
	// keeps.
	deleted, err := store.DeleteExpired(t.Context(), 10)
	if err != nil {
		t.Fatalf("delete the expired sessions: %v", err)
	}

	if deleted != 1 {
		t.Errorf("swept %d sessions, want 1", deleted)
	}

	deleted, err = store.DeleteExpired(t.Context(), 10)
	if err != nil {
		t.Fatalf("delete the expired sessions again: %v", err)
	}

	if deleted != 0 {
		t.Errorf("swept %d sessions on the second pass, want 0", deleted)
	}
}

func TestDeleteExpiredBatches(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t),
		pgstore.WithMaxSessionAge(200*time.Millisecond))

	for i := range 5 {
		_, err := store.Create(t.Context(), howdah.NewSession{
			Subject: fmt.Sprintf("user-%d", i),
			Token:   testToken("access", time.Hour),
		})
		if err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}

	time.Sleep(300 * time.Millisecond)

	var (
		total  int64
		passes int
	)

	for {
		deleted, err := store.DeleteExpired(t.Context(), 2)
		if err != nil {
			t.Fatalf("delete the expired sessions: %v", err)
		}

		passes++

		if deleted == 0 {
			break
		}

		if deleted > 2 {
			t.Fatalf("swept %d sessions in one pass of 2", deleted)
		}

		total += deleted
	}

	if total != 5 {
		t.Errorf("swept %d sessions in %d passes, want 5",
			total, passes)
	}
}

func TestDeleteSubject(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	var handles []string

	for i := range 3 {
		subject := "user-1"
		if i == 2 {
			subject = "user-2"
		}

		session, err := store.Create(t.Context(), howdah.NewSession{
			Subject: subject,
			Token:   testToken("access", time.Hour),
		})
		if err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}

		handles = append(handles, session.Handle)
	}

	deleted, err := store.DeleteSubject(t.Context(), "user-1")
	if err != nil {
		t.Fatalf("delete the subject's sessions: %v", err)
	}

	if deleted != 2 {
		t.Errorf("deleted %d sessions, want 2", deleted)
	}

	for i, handle := range handles[:2] {
		_, err := store.Get(t.Context(), handle)
		if !errors.Is(err, howdah.ErrNoSession) {
			t.Errorf("session %d: got %v, want ErrNoSession", i, err)
		}
	}

	_, err = store.Get(t.Context(), handles[2])
	if err != nil {
		t.Errorf("the other subject's session: %v", err)
	}
}

// TestPayloadIsBoundToItsRow is the proof that the row id in the sealed
// payload's additional authenticated data does what it is there for: a
// writer with access to the database cannot transplant one session's tokens
// into another session's row.
func TestPayloadIsBoundToItsRow(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	var handles []string

	for i := range 2 {
		session, err := store.Create(t.Context(), howdah.NewSession{
			Subject: fmt.Sprintf("user-%d", i),
			Token:   testToken(fmt.Sprintf("access-%d", i), time.Hour),
		})
		if err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}

		handles = append(handles, session.Handle)
	}

	rows, err := pool.Query(t.Context(),
		"SELECT id, payload FROM howdah_session ORDER BY subject")
	if err != nil {
		t.Fatalf("read the rows: %v", err)
	}

	type row struct {
		id      []byte
		payload []byte
	}

	var stored []row

	for rows.Next() {
		var r row

		err := rows.Scan(&r.id, &r.payload)
		if err != nil {
			rows.Close()
			t.Fatalf("scan a row: %v", err)
		}

		stored = append(stored, r)
	}

	rows.Close()

	err = rows.Err()
	if err != nil {
		t.Fatalf("read the rows: %v", err)
	}

	if len(stored) != 2 {
		t.Fatalf("got %d rows, want 2", len(stored))
	}

	for i, r := range stored {
		other := stored[(i+1)%len(stored)]

		_, err := pool.Exec(t.Context(),
			"UPDATE howdah_session SET payload = $1 WHERE id = $2",
			other.payload, r.id)
		if err != nil {
			t.Fatalf("transplant payload %d: %v", i, err)
		}
	}

	for i, handle := range handles {
		_, err := store.Get(t.Context(), handle)
		if !errors.Is(err, howdah.ErrNoSession) {
			t.Errorf("session %d: got %v for a transplanted payload, want ErrNoSession",
				i, err)
		}

		if !errors.Is(err, howdah.ErrAuthentication) {
			t.Errorf("session %d: got %v, want an authentication failure",
				i, err)
		}
	}
}

func TestNewRefusesABadConfiguration(t *testing.T) {
	keyring := testKeyring(t)
	pool := &pgxpool.Pool{}

	tests := []struct {
		name    string
		keyring *howdah.CookieKeyring
		cookie  string
		opts    []pgstore.Option
		want    string
	}{
		{
			name:   "without a keyring",
			cookie: "token",
			want:   "cookie keyring is required",
		},
		{
			name:    "with a colon in the cookie name",
			keyring: keyring,
			cookie:  "auth_redir:sess",
			want:    "not a valid cookie name",
		},
		{
			name:    "with a lease shorter than the token request",
			keyring: keyring,
			cookie:  "token",
			opts: []pgstore.Option{
				pgstore.WithRefreshLease(5 * time.Second),
				pgstore.WithTokenRequestTimeout(10 * time.Second),
			},
			want: "must be longer than the token request timeout",
		},
		{
			name:    "with a zero session age",
			keyring: keyring,
			cookie:  "token",
			opts: []pgstore.Option{
				pgstore.WithMaxSessionAge(0),
			},
			want: "maximum session age must be positive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := pgstore.New(
				pool, test.keyring, test.cookie, test.opts...)
			if err == nil {
				t.Fatalf("got the store %v, want an error", store)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("the error %q does not mention %q",
					err.Error(), test.want)
			}
		})
	}
}

func TestNewRefusesAMissingDatabase(t *testing.T) {
	_, err := pgstore.New(nil, testKeyring(t), "token")
	if err == nil {
		t.Fatal("got a store without a database, want an error")
	}
}

// keyIDs reads the key ids the rows are sealed under, so a test can check
// what a rollover sweep did.
func keyIDs(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()

	rows, err := pool.Query(t.Context(),
		"SELECT encode(key_id, 'hex'), count(*) FROM howdah_session GROUP BY 1")
	if err != nil {
		t.Fatalf("read the key ids: %v", err)
	}

	defer rows.Close()

	counts := make(map[string]int)

	for rows.Next() {
		var (
			kid   string
			count int
		)

		err := rows.Scan(&kid, &count)
		if err != nil {
			t.Fatalf("scan a key id: %v", err)
		}

		counts[kid] = count
	}

	err = rows.Err()
	if err != nil {
		t.Fatalf("read the key ids: %v", err)
	}

	return counts
}
