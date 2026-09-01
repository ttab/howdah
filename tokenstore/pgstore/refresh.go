package pgstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ttab/howdah"
	"github.com/ttab/howdah/tokenstore/pgstore/postgres"
	"golang.org/x/oauth2"
)

// errLeaseLost is internal: it says this refresher no longer owns the
// refresh, so whatever it came back with — a token or a failure — has to be
// discarded and the row re-read. It never reaches a caller, because the
// reason the fence rejected the write is that somebody else's write landed.
var errLeaseLost = errors.New("the refresh lease was lost")

// maxLostWriteReads caps how many times one call may read past its own
// deadline on the strength of a lost write-back. Each of those reads is
// justified — the result it is looking for is committed already — but the
// cap is what guarantees the loop ends whatever the traffic does.
const maxLostWriteReads = 2

// Refresh exchanges the session's refresh token for a new one, and does it
// exactly once per session across the whole fleet however many requests ask
// for it at the same time.
//
// How, and why in this order:
//
//  1. **Read the row.** If the token in it has more than the refresh margin
//     left, somebody refreshed between the caller's read and this call:
//     return their token and make no provider call at all.
//  2. **Take the lease.** A conditional UPDATE, guarded on the lease being
//     free and on refreshed_at not having moved since the read. No
//     transaction is held, which is the whole point: SELECT ... FOR UPDATE
//     and pg_advisory_xact_lock both hold a pooled connection open across
//     the round trip to the identity provider, so a hung provider drains the
//     pool and takes the application down rather than just its logins.
//  3. **The winner exchanges**, on a context detached from the request, and
//     writes the result back fenced on its lease nonce. A write that comes
//     back with no rows means the lease was lost and somebody fresher won;
//     the result is discarded rather than committed over theirs, and the row
//     is re-read even if the wait has run out, because the answer is
//     committed already. **The same fence, read the same way, guards the
//     failure write-back** — a refresher that has lost its lease must not
//     report its own exchange failure, which under rotation is most likely
//     the answer to a token the new owner has already rotated away.
//  4. **The losers wait**, on a bounded backoff, and return as soon as
//     refreshed_at has moved. They make no provider call. If the refresh
//     they were waiting for failed, they see that and fail immediately
//     rather than each attempting an exchange of their own against a token
//     the provider may already have rotated.
//  5. **A refresher that died** holds its lease until it expires, and then
//     the next caller takes it over. That costs one slow request, not a
//     wedged session. The lease covers the round trip and the write-back
//     together, so a refresher that is merely slow does not lose it — an
//     expired lease that a live refresher still thinks it holds is what lets
//     two callers post the same refresh token.
//
// The one window that cannot be closed: if the exchange succeeds and the
// write-back then fails — the database was unreachable for the two seconds
// it mattered — the rotated refresh token exists only in this process's
// memory, and in store mode the cookie is only a handle, so there is no
// recovery path and the user logs in again. It is inherent to rotation plus
// external storage, and it is an argument for a generous refresh margin, so
// that there is room to try again before the access token actually dies.
func (s *Store) Refresh(
	ctx context.Context, t *howdah.StoredToken,
	exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
) (*howdah.StoredToken, error) {
	if t == nil {
		return nil, errors.New("a session is required")
	}

	id, _, err := s.rowID(t.Handle)
	if err != nil {
		return nil, err
	}

	var (
		seenRefreshedAt pgtype.Timestamptz
		seenFailedAt    pgtype.Timestamptz
		backoff         = refreshPollMin
		deadline        = time.Now().Add(s.conf.refreshWait)
		lostWriteReads  int
	)

	for pass := 0; ; pass++ {
		// Every path back to the top of this loop is a wait for
		// somebody else's refresh — the lease was held, or our own
		// write-back was fenced out by a fresher one — so the whole
		// call is bounded here rather than in each of them. A refresh
		// that cannot be resolved inside the budget is a failed
		// request, not an unbounded loop.
		//
		// The one exception is the pass that follows a lost write-back,
		// and it is an exception because that pass is not a wait at
		// all. A write is fenced out only when somebody else's write
		// landed, so the answer is already in the row and one read
		// away: giving up on the budget here would return
		// ErrRefreshTimeout — and cost the caller its session — over a
		// token that is sitting there. The reads are counted so that a
		// pathological run of lost leases still ends.
		if pass > 0 && lostWriteReads == 0 && !time.Now().Before(deadline) {
			return nil, ErrRefreshTimeout
		}

		if lostWriteReads > 0 {
			lostWriteReads--
		}

		row, err := s.q.GetSession(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: unknown session handle",
				howdah.ErrNoSession)
		} else if err != nil {
			return nil, fmt.Errorf("read the session row: %w", err)
		}

		if !row.ExpiresAt.Time.After(row.DbNow.Time) {
			return nil, fmt.Errorf(
				"%w: the session expired %s ago", howdah.ErrNoSession,
				row.DbNow.Time.Sub(row.ExpiresAt.Time).Round(time.Second))
		}

		payload, err := s.openPayload(id, row.Payload)
		if err != nil {
			return nil, err
		}

		switch {
		case pass == 0:
			seenRefreshedAt = row.RefreshedAt
			seenFailedAt = row.RefreshFailedAt

			// The idempotency guard. A caller reads the session,
			// decides the access token is nearly dead, and calls
			// here — and in between, another request refreshed it.
			// Redoing the exchange would post a refresh token the
			// provider may already have rotated away.
			if time.Until(payload.Token.Expiry) > s.conf.refreshMargin {
				return s.session(t, row, payload), nil
			}
		case row.RefreshedAt.Time.After(seenRefreshedAt.Time):
			// Somebody refreshed. Their token is the one everybody
			// uses, whatever its remaining life — checking the
			// margin here instead would leave a caller polling
			// forever behind a provider that hands out very
			// short-lived access tokens.
			return s.session(t, row, payload), nil
		case advanced(row.RefreshFailedAt, seenFailedAt):
			return nil, ErrRefreshFailed
		}

		nonce := make([]byte, leaseNonceLength)

		_, err = rand.Read(nonce)
		if err != nil {
			return nil, fmt.Errorf("generate a lease nonce: %w", err)
		}

		lease, err := s.q.TakeRefreshLease(ctx,
			postgres.TakeRefreshLeaseParams{
				ID:              id,
				Nonce:           nonce,
				Lease:           interval(s.conf.refreshLease),
				SeenRefreshedAt: seenRefreshedAt,
				SeenFailedAt:    seenFailedAt,
			})
		if errors.Is(err, pgx.ErrNoRows) {
			// Somebody else holds the lease, or refreshed while we
			// were asking. Either way we do not call the provider:
			// we wait for their answer.
			err = wait(ctx, backoff)
			if err != nil {
				return nil, err
			}

			backoff = min(2*backoff, refreshPollMax)

			continue
		} else if err != nil {
			return nil, fmt.Errorf("take the refresh lease: %w", err)
		}

		session, err := s.runExchange(ctx, id, nonce, t, lease, exchange)
		if errors.Is(err, errLeaseLost) {
			// The row now holds somebody else's newer tokens, and
			// the next pass through the loop reads them. No wait:
			// their write has already landed, so the read is worth
			// one pass past the deadline.
			lostWriteReads = min(lostWriteReads+1, maxLostWriteReads)

			continue
		}

		return session, err
	}
}

// runExchange is the winner's half: the token endpoint round trip and the
// fenced write-back.
func (s *Store) runExchange(
	ctx context.Context, id, nonce []byte, t *howdah.StoredToken,
	lease postgres.TakeRefreshLeaseRow,
	exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
) (*howdah.StoredToken, error) {
	// The lease returned the payload as the row holds it, which is what
	// the exchange has to be done with. The caller's own copy may be a
	// refresh behind.
	payload, err := s.openPayload(id, lease.Payload)
	if err != nil {
		return nil, err
	}

	// The exchange runs on a context detached from the request, with a
	// timeout of its own. A client that disconnects mid-exchange would
	// otherwise cancel a call the provider has already acted on, and the
	// rotated refresh token would be lost — with several requests
	// collapsed onto one exchange, the client that goes away is not even
	// necessarily the one that started it.
	exchangeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), s.conf.tokenRequestTimeout)
	defer cancel()

	tok, err := exchange(exchangeCtx, payload.Token)
	if err != nil {
		return nil, s.refreshFailed(ctx, id, nonce, err)
	}

	// A token that is not there is a failure rather than something to
	// write: sealing it would leave a row nothing can open, which is a
	// session dead for good rather than one that logs in again.
	if tok == nil {
		return nil, s.refreshFailed(ctx, id, nonce,
			errors.New("the exchange returned no token"))
	}

	refreshed := *payload
	refreshed.Token = tok

	sealed, kid, err := s.sealPayload(id, refreshed)
	if err != nil {
		return nil, err
	}

	// The write-back is detached too, and for a stronger reason than the
	// exchange: the provider has already acted, so a rotated refresh
	// token that is not written is a session that is dead everywhere.
	writeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), s.conf.writeTimeout)
	defer cancel()

	rows, err := s.q.CommitRefresh(writeCtx, postgres.CommitRefreshParams{
		ID:              id,
		Nonce:           nonce,
		KeyID:           kid.Bytes(),
		Payload:         sealed,
		AccessExpiresAt: timestamp(tok.Expiry),
	})
	if err != nil {
		return nil, fmt.Errorf("write the refreshed session: %w", err)
	}

	if rows == 0 {
		return nil, errLeaseLost
	}

	return &howdah.StoredToken{
		// A refresh does not move the handle: the row is the session,
		// and the cookie only names it. That is what lets the caller
		// write a Set-Cookie only when something actually changed.
		Handle:    t.Handle,
		Subject:   refreshed.Subject,
		Token:     tok,
		IDToken:   refreshed.IDToken,
		IssuedAt:  lease.CreatedAt.Time,
		ExpiresAt: lease.ExpiresAt.Time,
		Stale:     t.Stale,
	}, nil
}

// refreshFailed records that this refresher's attempt failed and returns the
// error the caller is handed. A failure that cannot even be recorded is
// reported alongside the one that caused it, because it is what turns a
// provider outage into a stampede.
//
// The marker's own fence is read, not thrown away, and that is the
// difference between one user staying logged in and one being bounced. Zero
// rows means the nonce is gone, so this refresher no longer owns the
// refresh: somebody else committed a token, failed the refresh, or took the
// lease over. Its own exchange error then says nothing about the session —
// most often it *is* invalid_grant, because the winner rotated the token
// this attempt was posting — so it goes the same way a fenced-out success
// goes: discarded, with the row re-read. Reporting it instead would clear
// the cookie of a session that was refreshed a millisecond earlier.
func (s *Store) refreshFailed(
	ctx context.Context, id, nonce []byte, cause error,
) error {
	err := fmt.Errorf("exchange the refresh token: %w", cause)

	rows, markErr := s.markRefreshFailed(ctx, id, nonce)

	switch {
	case markErr != nil:
		return errors.Join(err, fmt.Errorf(
			"record the failed refresh: %w", markErr))
	case rows == 0:
		return errLeaseLost
	}

	return err
}

// markRefreshFailed records that the attempt failed and releases the lease,
// fenced on the nonce so that a refresher which has already lost its lease
// cannot mark a fresher one's attempt as failed. It returns how many rows
// the fence let through, which is what tells the caller whether the failure
// it is recording is still its own to report.
//
// It runs on a detached context because the failure it is recording may be
// the request's own cancellation, and the callers waiting on the lease need
// the answer either way.
func (s *Store) markRefreshFailed(
	ctx context.Context, id, nonce []byte,
) (int64, error) {
	writeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), s.conf.writeTimeout)
	defer cancel()

	rows, err := s.q.FailRefresh(writeCtx, postgres.FailRefreshParams{
		ID:    id,
		Nonce: nonce,
	})
	if err != nil {
		return 0, fmt.Errorf("mark the refresh as failed: %w", err)
	}

	return rows, nil
}

// session builds the token a read hands back. The handle is the caller's own
// cookie value, unchanged: this store's handles are stable, and a rollover
// moves them through Reseal rather than through a read.
func (s *Store) session(
	t *howdah.StoredToken, row postgres.GetSessionRow,
	payload *sessionPayload,
) *howdah.StoredToken {
	return &howdah.StoredToken{
		Handle:    t.Handle,
		Subject:   payload.Subject,
		Token:     payload.Token,
		IDToken:   payload.IDToken,
		IssuedAt:  row.CreatedAt.Time,
		ExpiresAt: row.ExpiresAt.Time,
		Stale:     t.Stale,
	}
}

// advanced reports whether a nullable timestamp has moved since it was last
// seen. A marker that was already set when we started belongs to an earlier
// attempt and says nothing about this one.
func advanced(now, seen pgtype.Timestamptz) bool {
	if !now.Valid {
		return false
	}

	if !seen.Valid {
		return true
	}

	return now.Time.After(seen.Time)
}

// wait sleeps, or gives up early if the request goes away.
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for a concurrent refresh: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}
