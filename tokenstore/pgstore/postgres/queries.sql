-- name: CreateSession :one
INSERT INTO howdah_session(
  id, subject, key_id, payload, access_expires_at,
  refreshed_at, created_at, expires_at
) VALUES (
  @id, @subject, @key_id, @payload, @access_expires_at,
  now(), now(), now() + @max_session_age::interval
)
RETURNING created_at, expires_at;

-- name: GetSession :one
SELECT subject, key_id, payload, access_expires_at, refresh_lease_until,
       refresh_lease_nonce, refresh_failed_at, refreshed_at, created_at,
       expires_at, now()::timestamptz AS db_now
FROM howdah_session
WHERE id = @id;

-- name: UpdateSession :execrows
UPDATE howdah_session
SET    key_id = @key_id,
       payload = @payload,
       access_expires_at = @access_expires_at,
       refreshed_at = now(),
       refresh_lease_until = NULL,
       refresh_lease_nonce = NULL,
       refresh_failed_at = NULL
WHERE  id = @id;

-- name: DeleteSession :execrows
DELETE FROM howdah_session WHERE id = @id;

-- name: DeleteSubjectSessions :execrows
DELETE FROM howdah_session WHERE subject = @subject;

-- Deletes at most batch sessions that are past their absolute expiry. The
-- subselect is what bounds the delete: an unbounded one takes a lock on
-- every dead row in the table at once.
--
-- FOR UPDATE SKIP LOCKED and the ORDER BY are what make two replicas
-- sweeping at the same time behave. Without them the second sweeper's
-- statement snapshot selects the very rows the first is deleting, blocks on
-- its locks, and then finds every one of them gone — so it reports 0 with
-- rows still in the table and stops short. And a LIMIT with no ORDER BY
-- leaves the lock order to the plan, so two deletes that take their rows in
-- opposite orders deadlock and abort the sweep outright. Skipping the locked
-- rows instead gives each sweeper a disjoint batch.
-- name: DeleteExpiredSessions :execrows
DELETE FROM howdah_session
WHERE id IN (
  SELECT id FROM howdah_session
  WHERE expires_at <= now()
  ORDER BY expires_at, id
  LIMIT @batch
  FOR UPDATE SKIP LOCKED
);

-- Takes the refresh lease. It is a conditional UPDATE rather than a
-- SELECT ... FOR UPDATE or an advisory lock, because either of those holds a
-- pooled connection open across an HTTP round trip to the identity provider:
-- a hung provider then drains the pool and takes down the whole application
-- rather than just its logins. The lease holds no transaction — take it,
-- commit, do the round trip, commit the result.
--
-- The refreshed_at clause is the idempotency guard. If somebody refreshed
-- between the caller's read and this attempt, refreshed_at has moved past
-- what the caller saw, no row comes back, and the caller re-reads instead of
-- refreshing a token that is already fresh.
--
-- The refresh_failed_at clause closes the same window on the failure side.
-- A refresher that fails releases the lease and sets the marker in one
-- statement, so a caller that read the row before that and asks for the
-- lease after it would otherwise find the lease free and exchange the same
-- refresh token again — which is exactly the n-attempts-per-outage the
-- marker exists to prevent.
-- name: TakeRefreshLease :one
UPDATE howdah_session
SET    refresh_lease_until = now() + @lease::interval,
       refresh_lease_nonce = @nonce
WHERE  id = @id
  AND  (refresh_lease_until IS NULL OR refresh_lease_until < now())
  AND  refreshed_at <= @seen_refreshed_at
  AND  refresh_failed_at IS NOT DISTINCT FROM @seen_failed_at
  AND  expires_at > now()
RETURNING subject, key_id, payload, refreshed_at, created_at, expires_at;

-- Writes the result of a refresh back, fenced on the lease nonce. Without
-- the fence a refresher whose exchange finished but whose write stalled past
-- its lease could land on top of a fresher winner's tokens, leaving a
-- rotated-away refresh token in the row and the session dead fleet-wide.
-- Zero rows means the lease was lost: discard the result and re-read.
-- name: CommitRefresh :execrows
UPDATE howdah_session
SET    payload = @payload,
       key_id = @key_id,
       access_expires_at = @access_expires_at,
       refreshed_at = now(),
       refresh_lease_until = NULL,
       refresh_lease_nonce = NULL,
       refresh_failed_at = NULL
WHERE  id = @id AND refresh_lease_nonce = @nonce;

-- Records that a refresh attempt failed and releases the lease, so that the
-- callers waiting on it fail fast rather than polling a refreshed_at that
-- will never move, burning their whole backoff and then each attempting an
-- exchange of their own. Fenced on the nonce for the same reason the commit
-- is.
-- name: FailRefresh :execrows
UPDATE howdah_session
SET    refresh_failed_at = now(),
       refresh_lease_until = NULL,
       refresh_lease_nonce = NULL
WHERE  id = @id AND refresh_lease_nonce = @nonce;

-- Finds the live sessions sealed under some other key than the one we seal
-- with now, through the key_id index rather than by opening every row.
-- name: ListRekeySessions :many
SELECT id, key_id, payload, refreshed_at
FROM   howdah_session
WHERE  key_id <> @key_id AND expires_at > now()
ORDER BY id
LIMIT  @batch;

-- Re-seals one row's payload, fenced on both the key id and the refreshed_at
-- the sweep read. Without both, a sweep that interleaves with a refresh
-- commits a re-sealed copy of the old payload over the new one — which, with
-- refresh token rotation on, resurrects a token the provider has revoked and
-- kills the session.
-- name: ResealSession :execrows
UPDATE howdah_session
SET    key_id = @key_id,
       payload = @payload
WHERE  id = @id
  AND  key_id = @seen_key_id
  AND  refreshed_at = @seen_refreshed_at;
