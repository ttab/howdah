# Changelog

Everything from v0.1.0 forward is documented here; the releases before it are
in the git history only. Entries are derived from the release tags, and the
linked PRs hold the detail.

## [v0.2.0] - Unreleased

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
