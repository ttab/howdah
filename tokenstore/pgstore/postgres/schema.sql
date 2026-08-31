-- The schema sqlc compiles the queries against. It is the result of applying
-- everything in ../schema, and the store's tests apply those migrations to a
-- real Postgres and then run every query, so the two cannot drift far
-- without a test failing.

CREATE TABLE howdah_session(
  id bytea PRIMARY KEY,
  subject text NOT NULL,
  key_id bytea NOT NULL,
  payload bytea NOT NULL,
  access_expires_at timestamptz NOT NULL,
  refresh_lease_until timestamptz,
  refresh_lease_nonce bytea,
  refresh_failed_at timestamptz,
  refreshed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX howdah_session_expires_at_idx ON howdah_session(expires_at);

CREATE INDEX howdah_session_subject_idx ON howdah_session(subject);

CREATE INDEX howdah_session_key_id_idx ON howdah_session(key_id);
