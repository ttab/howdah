-- One row per session. The id is sha256 of the session handle rather than
-- the handle itself, so a database dump, a backup on a laptop or a read
-- through an injection yields nothing anybody can log in with.
CREATE TABLE IF NOT EXISTS howdah_session(
  -- sha256 of the session handle.
  id bytea PRIMARY KEY,
  -- The OIDC sub claim, so that logging one person out everywhere is a
  -- single delete.
  subject text NOT NULL,
  -- The id of the cookie key the payload is sealed under. It is a column as
  -- well as a field inside the sealed payload so that a rollover sweep can
  -- find the rows under a retiring key through an index instead of opening
  -- every row to discover which key it used.
  key_id bytea NOT NULL,
  -- The sealed token set, bound to this row's id by the additional
  -- authenticated data.
  payload bytea NOT NULL,
  -- When the access token in the payload expires. Nothing coordinates on
  -- it; it is what an operator queries.
  access_expires_at timestamptz NOT NULL,
  -- Held by whichever caller is doing the token endpoint round trip. No
  -- transaction is held across that round trip, so a hung identity provider
  -- costs one slow request rather than a drained connection pool.
  refresh_lease_until timestamptz,
  -- Fences the write-back: a refresher whose exchange finished but whose
  -- write stalled past its lease commits nothing, so it cannot land a
  -- rotated-away refresh token on top of a fresher one.
  refresh_lease_nonce bytea,
  -- Set when a refresh attempt failed, so that the callers waiting for it
  -- fail fast instead of polling a refreshed_at that will never move and
  -- then each attempting an exchange of their own.
  refresh_failed_at timestamptz,
  -- Moves on every write of the token set, and is both the idempotency
  -- guard on taking the lease and what a waiting caller polls.
  refreshed_at timestamptz NOT NULL,
  -- When the session began. It is never moved, so refreshing does not
  -- extend the session.
  created_at timestamptz NOT NULL,
  -- The absolute session expiry, which is the one the server enforces.
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS howdah_session_expires_at_idx
  ON howdah_session(expires_at);

CREATE INDEX IF NOT EXISTS howdah_session_subject_idx
  ON howdah_session(subject);

-- key_id is read by no query. It records which cookie key a row's payload is
-- sealed under, and the index serves the question an operator asks during a
-- rollover: how many live sessions are still on the old key, and is it safe
-- to drop it yet. That is an ad hoc count, deliberately not a sweep -- see
-- the comment on Reseal in pgstore.go for why there is no sweep.
CREATE INDEX IF NOT EXISTS howdah_session_key_id_idx
  ON howdah_session(key_id);

---- create above / drop below ----

DROP TABLE IF EXISTS howdah_session;
