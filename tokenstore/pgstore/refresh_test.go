package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ttab/howdah"
	"github.com/ttab/howdah/tokenstore/pgstore"
	"golang.org/x/oauth2"
)

// TestRefreshRunsExactlyOnce is the test this whole store exists to pass.
//
// A page load fires several requests, plus the keepalive, and every one of
// them finds the same access token a few seconds from death. Without the
// lease they each post the same refresh token to the token endpoint: merely
// wasteful while the provider hands the same refresh token back, and a
// mid-session logout for every loser the day the realm turns on refresh
// token rotation, since the first exchange invalidates the token and the
// rest come back invalid_grant.
//
// So: n callers, one exchange, and the same new token for everybody.
func TestRefreshRunsExactlyOnce(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	// An access token that has just expired, which is the state every
	// request of that page load finds the session in.
	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	const callers = 16

	var (
		exchanges atomic.Int64
		ready     sync.WaitGroup
		done      sync.WaitGroup
		start     = make(chan struct{})
		results   = make([]*howdah.StoredToken, callers)
		errs      = make([]error, callers)
	)

	exchange := func(
		_ context.Context, tok *oauth2.Token,
	) (*oauth2.Token, error) {
		n := exchanges.Add(1)

		if tok.RefreshToken != "access-1-refresh" {
			return nil, fmt.Errorf(
				"exchange %d was handed the refresh token %q",
				n, tok.RefreshToken)
		}

		// Wide enough that every caller is inside the window when the
		// winner is in the middle of its round trip.
		time.Sleep(100 * time.Millisecond)

		return testToken("access-2", time.Hour), nil
	}

	ready.Add(callers)
	done.Add(callers)

	for i := range callers {
		go func() {
			defer done.Done()

			// Each caller reads the session for itself, the way a
			// request of its own would.
			read, err := store.Get(t.Context(), session.Handle)

			ready.Done()
			<-start

			if err != nil {
				errs[i] = err

				return
			}

			results[i], errs[i] = store.Refresh(
				t.Context(), read, exchange)
		}()
	}

	ready.Wait()
	close(start)
	done.Wait()

	if got := exchanges.Load(); got != 1 {
		t.Errorf("the token endpoint was called %d times for %d callers, want exactly 1",
			got, callers)
	}

	for i := range callers {
		if errs[i] != nil {
			t.Errorf("caller %d: %v", i, errs[i])

			continue
		}

		if results[i].Token.AccessToken != "access-2" {
			t.Errorf("caller %d got the access token %q, want %q",
				i, results[i].Token.AccessToken, "access-2")
		}

		// A stored session's handle does not move on a refresh, so no
		// caller writes a new cookie.
		if results[i].Handle != session.Handle {
			t.Errorf("caller %d came back with a different handle", i)
		}
	}

	// And the refreshed token is what the row holds, so the next request
	// on any replica gets it too.
	got, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the refreshed session: %v", err)
	}

	if got.Token.AccessToken != "access-2" {
		t.Errorf("the row holds the access token %q, want %q",
			got.Token.AccessToken, "access-2")
	}

	t.Logf("%d concurrent callers, %d token endpoint call, every caller on %q",
		callers, exchanges.Load(), got.Token.AccessToken)
}

// TestRefreshLeaseOutlivesAPanickingRefresher pins what happens when the
// refresher dies mid-exchange: nothing releases the lease, so the next
// caller waits it out and then takes it over. A dead refresher costs one
// slow request, not a wedged session.
func TestRefreshLeaseOutlivesAPanickingRefresher(t *testing.T) {
	pool := testDB(t)
	// The lease has to cover the round trip and the write-back together,
	// which is why the write timeout is set here as well: the defaults
	// would make the sum larger than this deliberately short lease.
	store := testStore(t, pool, testKeyring(t),
		pgstore.WithRefreshLease(700*time.Millisecond),
		pgstore.WithTokenRequestTimeout(300*time.Millisecond),
		pgstore.WithWriteTimeout(300*time.Millisecond))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	read, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the session: %v", err)
	}

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("the panic did not propagate to the caller")
			}
		}()

		_, _ = store.Refresh(t.Context(), read,
			func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
				panic("the refresher died")
			})
	}()

	begin := time.Now()

	refreshed, err := store.Refresh(t.Context(), read,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			return testToken("access-2", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("refresh after the panic: %v", err)
	}

	waited := time.Since(begin)

	if refreshed.Token.AccessToken != "access-2" {
		t.Errorf("got the access token %q, want %q",
			refreshed.Token.AccessToken, "access-2")
	}

	// It has to have waited: taking the lease straight over would mean
	// the lease was released by the dying refresher, and a refresher that
	// dies between the exchange and the write-back must not have released
	// anything.
	if waited < 500*time.Millisecond {
		t.Errorf("the next caller waited %s, expected it to wait the lease out",
			waited)
	}

	t.Logf("the next caller took the lease over after %s",
		waited.Round(10*time.Millisecond))
}

// TestRefreshFailureIsRecorded pins the failure marker: a provider outage
// costs one exchange per session and n fast failures, not n serialised
// exchanges against a token the provider may already have rotated.
func TestRefreshFailureIsRecorded(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	const callers = 8

	var (
		exchanges atomic.Int64
		ready     sync.WaitGroup
		done      sync.WaitGroup
		start     = make(chan struct{})
		errs      = make([]error, callers)
	)

	ready.Add(callers)
	done.Add(callers)

	for i := range callers {
		go func() {
			defer done.Done()

			read, err := store.Get(t.Context(), session.Handle)

			ready.Done()
			<-start

			if err != nil {
				errs[i] = err

				return
			}

			_, errs[i] = store.Refresh(t.Context(), read,
				func(
					context.Context, *oauth2.Token,
				) (*oauth2.Token, error) {
					exchanges.Add(1)

					time.Sleep(100 * time.Millisecond)

					return nil, errors.New("invalid_grant")
				})
		}()
	}

	ready.Wait()
	close(start)
	done.Wait()

	if got := exchanges.Load(); got != 1 {
		t.Errorf("the token endpoint was called %d times for %d callers, want exactly 1",
			got, callers)
	}

	var (
		exchangeFailures int
		waiterFailures   int
	)

	for i := range callers {
		switch {
		case errs[i] == nil:
			t.Errorf("caller %d succeeded, want a failure", i)
		case errors.Is(errs[i], pgstore.ErrRefreshFailed):
			waiterFailures++
		default:
			exchangeFailures++
		}
	}

	if exchangeFailures != 1 {
		t.Errorf("%d callers reported the exchange failure, want 1",
			exchangeFailures)
	}

	if waiterFailures != callers-1 {
		t.Errorf("%d callers reported a concurrent failure, want %d",
			waiterFailures, callers-1)
	}

	// A failure is not a wedge: the next request refreshes the session
	// normally.
	read, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the session after the failure: %v", err)
	}

	refreshed, err := store.Refresh(t.Context(), read,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			return testToken("access-2", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("refresh after the failure: %v", err)
	}

	if refreshed.Token.AccessToken != "access-2" {
		t.Errorf("got the access token %q, want %q",
			refreshed.Token.AccessToken, "access-2")
	}
}

// TestRefreshReadsTheWinnersTokenAfterLosingTheLease covers the failure
// path's half of the fence, and the deadline exemption that makes it worth
// having.
//
// A refresher whose lease expires mid-exchange — a provider slower than its
// budget, or a lease sized too tightly — comes back to a row somebody else
// has already refreshed. Its own exchange very often failed *because* of
// that: with rotation on, the winner rotated away the refresh token this
// attempt was posting, so the provider answered invalid_grant. Reporting
// that failure would clear the cookie of a session that was refreshed a
// millisecond earlier, so the fence on FailRefresh has to be read the same
// way the fence on CommitRefresh is: zero rows means "not mine any more,
// discard it and re-read".
//
// The re-read also has to happen even though the wait has run out, which is
// what the refresh wait here is short enough to prove: the answer is already
// committed, so it is one read away rather than an unknown wait.
func TestRefreshReadsTheWinnersTokenAfterLosingTheLease(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t),
		pgstore.WithRefreshLease(700*time.Millisecond),
		pgstore.WithTokenRequestTimeout(300*time.Millisecond),
		pgstore.WithWriteTimeout(300*time.Millisecond),
		pgstore.WithRefreshWait(300*time.Millisecond))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	read, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the session: %v", err)
	}

	var (
		loser    sync.WaitGroup
		outcome  *howdah.StoredToken
		loserErr error
	)

	loser.Add(1)

	go func() {
		defer loser.Done()

		outcome, loserErr = store.Refresh(t.Context(), read,
			func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
				// A provider slower than the lease, and one that
				// pays no attention to the context it was handed
				// — which is the state of the world this has to
				// survive rather than one it can prevent.
				time.Sleep(1100 * time.Millisecond)

				return nil, errors.New("invalid_grant")
			})
	}()

	// Long enough that the lease has expired, so this caller takes it over
	// while the first is still exchanging.
	time.Sleep(800 * time.Millisecond)

	winner, err := store.Refresh(t.Context(), read,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			// Short-lived on purpose, so that the refresh at the
			// end of the test has something to exchange rather than
			// being answered by the idempotency guard.
			return testToken("access-2", -time.Second), nil
		})
	if err != nil {
		t.Fatalf("the second refresher: %v", err)
	}

	if winner.Token.AccessToken != "access-2" {
		t.Fatalf("the second refresher got %q, want %q",
			winner.Token.AccessToken, "access-2")
	}

	loser.Wait()

	if loserErr != nil {
		t.Fatalf("the refresher that lost its lease reported %v, want the winner's token",
			loserErr)
	}

	if outcome.Token.AccessToken != "access-2" {
		t.Errorf("the refresher that lost its lease came back with %q, want %q",
			outcome.Token.AccessToken, "access-2")
	}

	// And the row was left alone: the discarded failure must not have
	// marked a live session as failed, or the next caller fails fast on
	// somebody else's dead attempt.
	got, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the session afterwards: %v", err)
	}

	if got.Token.AccessToken != "access-2" {
		t.Errorf("the row holds %q, want %q",
			got.Token.AccessToken, "access-2")
	}

	refreshed, err := store.Refresh(t.Context(), got,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			return testToken("access-3", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("refresh the session afterwards: %v", err)
	}

	if refreshed.Token.AccessToken != "access-3" {
		t.Errorf("the later refresh came back with %q, want %q",
			refreshed.Token.AccessToken, "access-3")
	}
}

// TestRefreshUsesATokenSomebodyElseObtained is the idempotency guard: a
// caller that decided to refresh before another caller finished must use
// their result rather than exchange again.
func TestRefreshUsesATokenSomebodyElseObtained(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	// Both callers read the session while its token was dead.
	first, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("the first read: %v", err)
	}

	second, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("the second read: %v", err)
	}

	_, err = store.Refresh(t.Context(), first,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			return testToken("access-2", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("the first refresh: %v", err)
	}

	refreshed, err := store.Refresh(t.Context(), second,
		func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			t.Error("the second caller called the token endpoint")

			return testToken("access-3", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("the second refresh: %v", err)
	}

	if refreshed.Token.AccessToken != "access-2" {
		t.Errorf("got the access token %q, want the one the first caller obtained",
			refreshed.Token.AccessToken)
	}
}

// TestRefreshSurvivesTheRequestGoingAway pins the detached exchange. A
// client that disconnects mid-refresh must not cancel a call the provider
// has already acted on: with rotation on, the token that comes back is the
// only one that works, and losing it kills the session. The commit is
// detached for the same reason, and more strongly — the provider has acted
// by then whatever the client did.
func TestRefreshSurvivesTheRequestGoingAway(t *testing.T) {
	pool := testDB(t)
	store := testStore(t, pool, testKeyring(t))

	session, err := store.Create(t.Context(), howdah.NewSession{
		Subject: "user-1",
		Token:   testToken("access-1", -time.Second),
	})
	if err != nil {
		t.Fatalf("create the session: %v", err)
	}

	request, disconnect := context.WithCancel(t.Context())
	defer disconnect()

	read, err := store.Get(request, session.Handle)
	if err != nil {
		t.Fatalf("get the session: %v", err)
	}

	refreshed, err := store.Refresh(request, read,
		func(ctx context.Context, _ *oauth2.Token) (*oauth2.Token, error) {
			// The client goes away in the middle of the round trip.
			disconnect()

			time.Sleep(20 * time.Millisecond)

			err := ctx.Err()
			if err != nil {
				return nil, fmt.Errorf(
					"the exchange was cancelled with the request: %w",
					err)
			}

			return testToken("access-2", time.Hour), nil
		})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if refreshed.Token.AccessToken != "access-2" {
		t.Errorf("got the access token %q, want %q",
			refreshed.Token.AccessToken, "access-2")
	}

	// And it was written, which is the half that matters: an exchange
	// whose result is not persisted is a session that is dead everywhere.
	got, err := store.Get(t.Context(), session.Handle)
	if err != nil {
		t.Fatalf("get the refreshed session: %v", err)
	}

	if got.Token.AccessToken != "access-2" {
		t.Errorf("the row holds the access token %q, want %q",
			got.Token.AccessToken, "access-2")
	}
}
