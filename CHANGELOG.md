# Changelog

Everything from v0.1.0 forward is documented here; the releases before it are
in the git history only. Entries are derived from the release tags, and the
linked PRs hold the detail.

## [v0.4.0] - Unreleased

**Behaviour change (cross-site writes are refused):** a `POST`, `PUT`,
`PATCH` or `DELETE` that reaches a route registered on a `PageMux` is now
answered with a 403 error page unless the browser says the request came from
this application — `Sec-Fetch-Site: same-origin` or `none`, or, for a client
that sends no `Sec-Fetch-Site`, an `Origin` whose host is the host the request
was addressed to. A request carrying neither header is not a browser request
and is let through, so command-line clients and health checks are unaffected.
This closes the same-site CSRF that `SameSite=Lax` leaves open: same-site is
the registrable domain, so every application on our own domain can post at
every other one with the session cookie attached. What a consumer has to do:
add a `CrossSiteRequestBlocked` message to the locale files, and check any
route of their own that is posted to by something other than one of their own
pages — a webhook receiver or a form on another host belongs on the
`http.ServeMux` rather than on the `PageMux`.

**Behaviour change (UI pages refuse to be framed):** every response a
`PageMux` route produces now carries `Content-Security-Policy:
frame-ancestors 'none'`. An application that is deliberately embedded in an
iframe has to set the header itself in the handler, which overwrites this one.
Nothing mounted directly on the underlying `http.ServeMux` is touched, so an
embeddable widget or an API endpoint served next to the UI keeps the headers
it had.

Changes:

- The site check and the framing policy are the whole of the release; both are
  `PageMux` behaviour and neither has an option, because a framework that lets
  a page opt out of them is a framework where the opt-out is the thing that
  gets copied. `docs/architecture.md` records the reasoning under "The request
  pipeline" and the README lists both under "PageMux and PageHandlers".

## [v0.3.0] - 2026-09-01

**No code to change for an existing consumer.** Sessions now go through a
`howdah.TokenStore`, and the store an application gets without asking is
`howdah.CookieTokenStore` — v0.2.0's session exactly, sealed into the cookie
and byte-compatible with it, so nobody is logged out by the upgrade and no
call has to change. Two things are still worth doing: add a
`SessionUnavailable` message to the locale files, and read the behaviour
change below if a frontend polls `Keepalive`.

**New (keeping sessions somewhere):** `howdah.WithTokenStore` hands `OIDCAuth`
a store of your own. The store owns the session: it seals the handle that goes
in the cookie, enforces the absolute session expiry, and decides how far the
deduplication of a concurrent refresh reaches — per process for the
cookie-backed store, and callers must not assume the token exchange runs
exactly once. Implement `Create`, `Get`, `Update`, `Reseal`, `Delete`,
`Refresh` and `DeleteExpired`. `howdah.ErrNoSession` is what a store returns for a handle it cannot
resolve. howdah starts no goroutines, so sweeping expired sessions is a
`DeleteExpired` call on a schedule of the application's own.

**New (sessions in Postgres):** `howdah/tokenstore/pgstore` keeps sessions in
a `howdah_session` table, and the cookie holds a sealed handle of about ninety
bytes instead of the token set. Logout becomes a revocation, `DeleteSubject`
logs one person out of every browser at once, the absolute expiry is a column
the server checks, and a refresh is serialised across the fleet — the several
requests of a page load collapse onto one token endpoint round trip however
many replicas they land on, which is what makes it safe to turn refresh token
rotation on at the provider. `pgstore.New(pool, keyring, cookieName)`, then
`howdah.WithTokenStore`; the session lifetime, the refresh lease and the four
timeouts around it are `pgstore.Option`s, and `pgstore.New` refuses a lease
that does not outlast the token request timeout and the write timeout
together. It reads and writes through a `pgstore.DB`, which a `*pgxpool.Pool`
satisfies, and holds no connection across anything slower than one statement:
the lease is what keeps a transaction from being open while the identity
provider is being called, so a hung provider costs one slow request rather
than the connection pool.

**New (sealing from outside the package):** `howdah.SessionSealer` and
`howdah.KeyID`, so a store in another package can seal the handle it puts in
the cookie and the payload it puts in its own storage. The domains a value is
sealed under stay behind the constructor, because a hand-written one is the
cross-cookie replay the domain exists to prevent.

**Behaviour change (a session that cannot be resolved):** only a session that
really is over clears the session cookie now. A session unknown to the store,
past its absolute expiry, sealed under a key that is gone, or holding a
refresh token the provider refused is unchanged: the cookie is cleared and the
user logs in again. But a store that could not *answer* — the database was
unreachable, the wait for another caller's refresh ran out — leaves the cookie
alone and fails the request instead: `RequireAuth` returns a 503
`howdah.HTTPError` (message id `SessionUnavailable`) rather than redirecting to
login, and `Keepalive` answers 503 rather than 401. v0.2.0 cleared the cookie
for both, which was harmless when the cookie *was* the session and is not once
it is a handle to a row: a two-second failover would otherwise log out every
user whose access token happened to be inside the refresh margin and leave
their rows unreachable until the sweep. A frontend polling `Keepalive` should
read 401 as "log in again" and 503 as "try again shortly", and an application
with a locale file wants a `SessionUnavailable` message in it.
`howdah.ErrRefreshRejected` is the sentinel that marks the failures which do
end a session, and a store that answers a caller waiting on somebody else's
refused refresh should wrap it — `pgstore.ErrRefreshFailed` does.

**Behaviour change (`WithMaxSessionAge`):** it configures the store howdah
builds for itself, so passing it together with `WithTokenStore` is now a
startup error rather than an option that quietly does nothing. A store brings
its own session lifetime.

**Migrations (`pgstore` only):** the table comes from tern migrations howdah
carries, applied against a version table of howdah's own —
`pgstore.SchemaVersionTable`, `howdah_session_version` — so howdah's numbering
cannot collide with the numbering of the migrations the application already
has in the same database. **A service on tern should vendor the migration into
its own `./schema` instead**, with `mage sql:vendor` from `github.com/ttab/mage`
v0.11.2 or later: `mage sql:migrate` and elephant-platform's
`setup db migrate` apply exactly those files and neither looks inside a
dependency, so a migration applied only from here never runs in a hosted deploy
— the API serves normally and every login fails on a missing `howdah_session`.
`pgstore.Migrate(ctx, pool)`, `pgstore.MigrateConn` and `pgstore.Migrations`
remain for an application that migrates some other way. **Whichever route,
apply them from a deliberate step and never from the service's startup path.**

- `001_session.sql` — creates the `howdah_session` table and its `expires_at`,
  `subject` and `key_id` indexes. **Run it before the deploy that turns
  `pgstore` on**, since the store's first read needs it. It touches nothing
  that already exists, so it takes no lock worth planning around and needs no
  maintenance window. Rolling it back drops the table, and every session in
  it.

**Also to schedule, because howdah starts no goroutines:** `DeleteExpired`
sweeps sessions past their expiry. Call it until it returns 0.

Retiring a cookie key takes the same wait with a store as without — the
maximum session age. There is deliberately no sweep that re-seals rows under
the new key: it could not reach the cookies, so it would not shorten that
wait, and a sweep racing a refresh is how a token the provider has revoked
gets written back over a live one.

**Build:** the minimum Go version is now 1.26.5, raised by the
`github.com/ttab/mage` targets howdah's magefiles import, so a consumer on Go
1.25 upgrades its toolchain before it upgrades howdah. Four new direct
dependencies land in every consumer's module graph whether or not it imports
`pgstore`: `github.com/jackc/pgx/v5` and `github.com/jackc/tern/v2` for the
store and its migrations, `github.com/ttab/mage` for the magefiles, and
`github.com/ttab/eltest` for the store's tests. Nothing links unless it is
imported — `pgstore` is a package in the main module rather than a nested one,
which keeps a release one tag at the price of that graph noise.

Changes:

- Logging out asks the store to forget the session before clearing the
  cookie, which is what makes logout a revocation for a store that keeps
  something. The cookie-backed store has nothing to forget, so an application
  on the default sees no change.
- A session's sealed payload now carries the OIDC `sub` claim, which costs a
  few dozen bytes of the cookie's budget. The raw `id_token` is carried by
  `howdah.NewSession` and `howdah.StoredToken`, for the `id_token_hint` that
  RP-initiated logout will need, but the cookie-backed store drops it: another
  JWT does not fit in the roughly 1.5 KB a store-less session has left.
- howdah has a `magefiles` directory for the first time, for `sql:generate`
  and `docs:links`, and an `sqlc.yaml` — every query pgstore runs is compiled
  by sqlc from `tokenstore/pgstore/postgres/queries.sql`. The store's tests
  run against a real Postgres in Docker through `github.com/ttab/eltest`.
- Documentation: the README has "Where sessions live", with a table for
  choosing between the two stores, and "Keeping sessions in Postgres".
  `docs/architecture.md` describes the read and refresh path through a store —
  why the session cookie is rewritten when the handle changed *or* when the
  value came in under a retired key, and how the refresh lease serialises an
  exchange without holding a transaction across the round trip to the
  provider. `docs/cookies.md` says what is in a session cookie in each mode,
  and its rollover runbook now covers both halves of a rollover: the cookie
  the request path re-seals and the row only a sweep reaches.

## [v0.2.0] - 2026-08-31

**Breaking (NewOIDCAuth):** the constructor now takes a `*CookieKeyring` as
its fourth argument and returns `(*OIDCAuth, error)`. Build the keyring with
`howdah.CookieKeyringFromEnv()` and pass it through; a nil keyring is an
error. There is no fallback to unencrypted cookies, so this is a change every
consumer has to make.

**Breaking (session cookies):** session cookies are now encrypted, and the
unencrypted cookies written by v0.1.0 are not readable. Everyone with a
session is logged out once on upgrade and has to log in again. Cookies sealed
under a key that is no longer configured are unset the same way.

**Required configuration:** the application will not start without at least
one currently usable cookie key. Provision `COOKIE_KEY_1` before the deploy,
in the form `<RFC 3339 use-after>_<base64 of 32 random bytes>` — for example
`2026-08-01T00:00:00Z_…`. `howdah.GenerateCookieKey` produces a value, and
`COOKIE_KEY_2`, `COOKIE_KEY_3` and so on hold the keys of a rollover in
progress. The README carries the rotation runbook.

**Behaviour change (cookie attributes):** every cookie howdah sets now
carries `Secure` unconditionally and `SameSite=Lax`. A deployment served over
plain HTTP — local development, in practice — must pass
`WithInsecureCookies()` or browsers will refuse to send the session back.
Applications that were adding these attributes with a response wrapper of
their own can drop it.

**Behaviour change (failed logins):** a login that does not complete now
redirects to the login page with `?login_failed=1` instead of rendering an
error page at the callback URL. That URL still carries the authorization code,
so an error page there was one a reload re-submitted, and the provider's reply
to a redeemed code — `invalid_grant "Code not valid"` — replaced the real
reason and made a recoverable failure look permanent. The login page's
`Page.Contents` is now a `howdah.LoginPage` whose `Failed` field says the last
attempt did not complete, so a template can show a notice; one that ignores
`Contents` renders as before. A provider that denies the login outright still
gets its own error page, since no code was issued and its description is
actionable.

Changes:

- A session cookie too large for a browser to store is refused rather than
  written. A browser drops an oversized cookie silently, so this previously
  presented as a login that reported success and returned the user to the
  login page with nothing logged anywhere. The refusal names the size and the
  limit. A measured session cookie is around 2.5 KB against the 4096 bytes a
  browser guarantees, so this is a guard rather than a limit most deployments
  will meet.
- Fixed an open redirect in the `/set-language` endpoint: the `redirect` query
  parameter went into the `Location` header unvalidated, so a crafted link
  made the application's own origin hand visitors to another site. The value
  is now refused unless it is a path within the application, and it resolves
  against the base path — previously it also dropped the mount prefix for a
  prefix-mounted application.
- Session cookies and the `auth_redir` cookie are sealed with AES-256-GCM
  under a keyring that supports rotation and format evolution. The `state` and
  `nonce` cookies stay in plaintext, because they are compared against values
  the provider echoes back.
- Sessions now have an enforced maximum age, carried as an issue time inside
  the sealed cookie and preserved across refreshes, rather than lasting as
  long as the refresh token survives. It defaults to
  `DefaultMaxSessionAge` (12 hours) and is set with `WithMaxSessionAge`.
- Concurrent requests that all find the access token expired now perform a
  single token exchange per process and share its result, instead of each
  posting the same refresh token to the provider.
- Applications mounted behind `http.StripPrefix` can complete the OIDC flow:
  the new `BasePath` component carries the mount point, `WithBasePath` applies
  it to the login and logout redirects and the auth cookie paths, and
  `WithSessionCookieName` gives co-hosted applications distinct session
  cookies. The callback also rejects `auth_redir` values that a browser would
  resolve against another host. (#1)
- The `lang` cookie is set with `Path`, `HttpOnly`, `SameSite` and `Secure`,
  none of which it carried before.
- `Keepalive` clears the session cookie when a refresh fails, so a browser
  stops re-sending a session that can no longer be renewed.
- `CookieKeyringFromEnv` takes option funcs, so the call with no arguments
  reads `COOKIE_KEY_*` — `DefaultCookieKeyPrefix` — in every application.
  `WithCookieKeyPrefix` overrides the prefix and `WithCookieKeyLogger` directs
  the startup line naming the sealing key.
- Added `golang.org/x/sync` v0.22.0 as a dependency, for the refresh
  deduplication.
- Reorganised the documentation: `docs/cookies.md` is now the authority on
  cookies and sessions, `docs/architecture.md` on howdah's internals and the
  OIDC flow, and the README is orientation and the working reference. The
  cookie material was about a third of the README.

## [v0.1.0] - 2026-05-25

Changes:

- Added `howdah.Token`, which returns the user's OAuth2 token from the auth
  context. Use it rather than re-reading the request cookie when forwarding an
  access token onwards: `RequireAuth` puts the post-refresh token in the
  context, while the request cookie still holds the pre-refresh value.
