# Cookies and sessions

Howdah keeps a user's session in a cookie, encrypted under a keyring that can
be rotated without logging anyone out. This document is the authority on that:
what is in each cookie, how a value is sealed, how keys are configured and
rolled over, and every way a session ends.

| Document | What it settles |
|---|---|
| [README](../README.md) | Orientation and the working reference: what the package holds, how to wire an application up, and every option it takes. |
| [architecture.md](architecture.md) | How howdah is built: the component model, the page pipeline, and the OIDC flow. |
| **cookies.md** (this document) | The cookie and session contract. |

It does not cover how to wire `OIDCAuth` up — that is the README — or the
shape of the login flow, which is [architecture.md](architecture.md#the-oidc-flow).
Sections here are numbered because the code cites them.

## 1. What is in a cookie

The session cookie and the post-login redirect cookie (`auth_redir`) are
sealed with AES-256-GCM under a keyring. `state` and `nonce` are left in the
clear on purpose: they are random values whose only job is to be compared
against what the provider echoes back, so rewriting either one makes the
comparison fail, and sealing them would buy nothing.

All three belong to a single login attempt. The callback clears them as it
reads them, and a login started without a redirect target clears any target
an abandoned attempt left behind — otherwise a login from the login page
lands the user wherever they were headed an hour ago.

A sealed value is bound to the cookie it lives in, not merely to the kind of
value it is, so two applications sharing a host and a keyring cannot open
each other's sessions — see [`WithSessionCookieName`](../README.md#mounting-under-a-path-prefix).
The cookie name is part of that binding, which is why it has to be an HTTP
token: no separators, and no colon in particular.

## 2. Cookie attributes

Every cookie howdah sets — the session cookie, `state`, `nonce`,
`auth_redir` and the `lang` cookie the application's own language switch
writes — carries the same attributes, and nothing configures them per
cookie:

* `HttpOnly`.
* `SameSite=Lax`, and deliberately not `Strict`. The OIDC callback is a
  cross-site top-level navigation from the provider, so `Strict` would have
  the browser withhold `state` and `nonce` on exactly the request that
  compares them, breaking every login.
* `Secure`, unconditionally. It is not derived from the connection, which is
  plain http behind a TLS-terminating ingress, and not from
  `X-Forwarded-Proto`, which the client sets.
* A `Path` inside the application's mount point, and no `Domain` at all —
  every cookie is host-only.

A plain-http local development run is the one case `Secure` gets in the way,
since the browser accepts such a cookie and then never sends it back.
`howdah.WithInsecureCookies()` is the opt-out, and the only one: never set
it on anything a browser reaches over a network. The application picks the
posture up from `OIDCAuth` when it is registered as a component, so the
language cookie follows it rather than a development run handing out one
insecure cookie and one `Secure` one.

```go
auth, err := howdah.NewOIDCAuth(provider, verifier, oauth2Config, keyring,
    howdah.WithInsecureCookies(), // http://localhost only
)
```

The `__Host-` cookie name prefix would have the browser enforce the same
posture — `Secure`, host-only, and a path of `/` — and was considered for
exactly that reason. It is not used because it *requires* `Path=/`, which is
incompatible with `WithBasePath`: an application mounted at `/admin` would
have to write its session cookie for the whole host, which is the opposite
of what mounting it under a prefix is for. It also rules out plain-http
local development entirely. Host-only is asserted by a test instead. This is
a settled decision, not an oversight — please don't reopen it every six
months.

## 3. The sealed envelope

A sealed value is one binary envelope, base64url-encoded into the cookie:

```
 1 B   1 B     8 B            12 B                    n B              16 B
┌─────┬─────┬──────────┬──────────────────┬────────────────────────┬──────────┐
│ ver │kind │   kid    │      nonce       │       ciphertext       │   tag    │
└─────┴─────┴──────────┴──────────────────┴────────────────────────┴──────────┘
└────────────────────┘
          ↑ authenticated but not encrypted, together with the domain
```

Version 1 is AES-256-GCM from the standard library, with a nonce from
`crypto/rand` per seal. A later format takes a new version byte: readers
dispatch on it, writers only ever emit the current one, so the format can
evolve on the same rails as the keys. `kid` is the first 8 bytes of a hash of
the secret, which is why reusing a variable name for a new secret is safe —
identity comes from the key, not from where it was written down.

`kind` says whether the ciphertext holds a whole session payload or a handle
to one stored elsewhere. Nothing writes handles yet; the byte exists now
because retrofitting it later would mean a release where the two shapes are
indistinguishable, and the mismatch would surface as
`ErrAuthentication` — tampering — rather than as the benign
`ErrWrongSessionKind`.

**The additional authenticated data carries the cookie name, not just the kind
of value.** AES-GCM authenticates the AAD without encrypting it, so opening
succeeds only if the reader supplies byte-for-byte what the writer sealed
with. Ours is `version ‖ kind ‖ kid ‖ domain`, where the domain is
`"cookie:" + the session cookie name`. The header fields are in the envelope
already, so authenticating them stops anyone editing it; the domain is never
transmitted at all, so it acts as a label the ciphertext has to match.

That last part is load-bearing rather than belt-and-braces. `NewOIDCAuth`
builds its access-token verifier with `SkipClientIDCheck: true`, so a token
minted for one application verifies in another. Two applications sharing a
host and a keyring but *not* the cookie name in the domain would therefore be
a privilege escalation: copy the low-privilege application's cookie into the
high-privilege one's and the session opens. The cookie name is what closes
it, which is also why it has to be an HTTP token — no separators, and no
colon in particular, or `"cookie:" + "a:b"` and `"cookie:a" + ":b"` would
collide.

## 4. What fits in a cookie

A browser guarantees 4096 bytes per cookie, counting the name, the value and
the attributes, and the store-less session carries the user's whole token set.
**A browser drops an oversized cookie silently** — nothing comes back to the
server and nothing appears in the response — so the failure used to present as
a login that reported success and landed the user back on the login page, with
no signal anywhere. `setTokenCookie` now refuses instead, naming the size and
the limit, so the login fails once and says why.

Measured, rather than estimated: imagereporting's sealed session cookie
against the tt realm on stage is **2453 bytes**, leaving about 1550 to spare.
The design document that preceded this work extrapolated 3527 from a guessed
token size and concluded the cookie was nearly full; it was not. The ceiling
is real all the same — a realm with a much fatter `roles` or `groups` claim
would close that gap — and a later release that keeps sessions server-side
would remove the question by putting a handle in the cookie instead.

## 5. The keyring environment format

`howdah.CookieKeyringFromEnv` reads one key per environment variable:

```
COOKIE_KEY_1=2026-08-01T00:00:00Z_TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IA==
COOKIE_KEY_2=2026-09-15T00:00:00Z_aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXIgcGE=
```

The value is an RFC 3339 timestamp and the standard base64 of exactly 32
bytes, separated by an underscore. It is split on the *first* underscore,
which is unambiguous whatever the secret looks like: RFC 3339 has no
underscore in it. The timestamp is the `use after` — when the key starts
being used for sealing.

Anything malformed is a startup error rather than a runtime surprise: a
missing separator, an unparseable timestamp, a secret that is not valid
base64, and a secret that is not exactly 32 bytes long.

The number is just a name. Keys are read in sorted variable-name order so
that every replica builds the same keyring, but a key's identity comes from
a hash of its secret, so reusing `COOKIE_KEY_1` for a new secret is fine and
no numbering discipline is required of whoever edits the environment.

`COOKIE_KEY_` (`howdah.DefaultCookieKeyPrefix`) is the prefix in every
application, so the fleet has one secret naming convention, one
externalsecrets shape and one runbook. `howdah.WithCookieKeyPrefix` reads a
different prefix, and is only for an application hosting two independent
keyrings. `howdah.WithCookieKeyLogger` sends the startup line below to the
application's own logger instead of `slog.Default()`; it is worth passing,
since a constructor called early in `main` can easily run before the
application has installed its handler.

`howdah.NewCookieKeyring` takes `[]howdah.CookieKey` directly, for an
application that gets its secrets from somewhere other than the
environment. The rules below are the same either way.

## 6. Generating a key

`howdah.GenerateCookieKey` returns the base64 of a fresh 32-byte secret:

```go
secret, err := howdah.GenerateCookieKey()
if err != nil {
    return fmt.Errorf("generate cookie key: %w", err)
}

fmt.Printf("COOKIE_KEY_2=%s_%s\n",
    time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339), secret)
```

`openssl rand -base64 32` produces an equally good secret if you would
rather not write a program. Either way the timestamp is yours to pick, and
picking it is the whole trick — see the rollover below.

## 7. Which key seals, which keys open

* **One key seals:** of the keys whose `use after` has passed, the one with
  the latest `use after`. The choice is made per request rather than frozen
  at startup, so a running replica starts sealing with the new key the
  moment its timestamp passes.
* **Every configured key opens, including future-dated ones.** This is not
  laxity, it is required. Replicas do not cross a `use after` boundary
  simultaneously — clock skew alone guarantees that — so a replica still
  sealing with the old key will be handed cookies sealed with the new one by
  a sibling whose clock ran ahead. If future keys did not open, every
  rollover would log out a slice of users for the width of the skew.
* **Two keys sharing a `use after` is a startup error**, checked across
  every key rather than only the eligible ones, because otherwise two
  future-dated keys pass the deploy that introduces them and become a coin
  flip weeks later. So are two variables holding the same secret.
* **No keys at all is a startup error, and so is no *eligible* key.** A
  fresh environment handed the fleet's rollover-dated key fails at startup
  rather than booting cleanly and failing on the first login.

The sealing key is logged once at startup, as `selected cookie sealing key`
with the key id, its `use after`, the size of the keyring and — if there is
one — the key due to take over next. The mistake it exists to catch is a new
key accidentally dated in the *past*: that key starts sealing on the first
replica to restart while its siblings cannot open the result, which presents
as mystery logouts. Nothing in code can prevent it, but one log line makes
it visible. `keyring.SealingKey()` returns the same two values for an
application that would rather log them itself, or check them from a handler.

## 8. When a cookie cannot be opened

Every one of these ends the same way — the cookie is cleared with
`Max-Age=-1` and the user is sent to the login page — but they mean
different things, and only one is worth alerting on.

| Error | Cause | Logged | Normal when |
|---|---|---|---|
| `howdah.ErrNotSealed` | Does not parse as an envelope at all | Info | Rolling out the release that starts sealing, while browsers still hold plaintext cookies |
| `howdah.ErrUnknownVersion` | An envelope from a newer howdah | Info | Rolling back |
| `howdah.ErrUnknownKey` | The key id is not in the keyring | Info | After dropping a retired key |
| `howdah.ErrWrongSessionKind` | The envelope holds a payload where a handle was expected, or the reverse | Info | Reserved for a later release: nothing writes handles yet |
| `howdah.ErrAuthentication` | The key was known, but decryption failed | **Warn** | Rare. Tampering, two environments crossed, or a cookie an intermediary truncated |

A session whose sealed `issued_at` is older than the maximum session age is
cleared the same way, as is one whose payload does not parse.

Plaintext cookies from before sealing are **not** migrated. They come back
as `ErrNotSealed`, get unset, and the user logs in again — which is a
one-off cost during one rollout, against carrying a reader for unencrypted
session cookies indefinitely.

## 9. What ends a session

A session ends, and the user logs in again, when any of these is true:

| Cause | Signal |
|---|---|
| The cookie cannot be opened | The taxonomy in §8 |
| The sealed `issued_at` is older than the maximum session age | `unusable session cookie` with the age and the cap |
| The refresh token is rejected by the provider | `refresh the access token` at error level |
| The user logs out | Nothing; the cookie is cleared |

**The maximum session age is counted against an `issued_at` sealed into the
cookie, not against the cookie's `Expires`,** which is only ever a request to
the browser and means nothing to somebody holding a copied value. Refreshing
the access token does not extend it, and the `issued_at` is carried forward
unchanged across every re-seal — restarting it would slide the cap forward
every few minutes and enforce nothing. `DefaultMaxSessionAge` is 12 hours;
`WithMaxSessionAge` changes it.

The age cap is enforced wherever a session enters the process, not only in
`RequireAuth`. `Keepalive` would otherwise keep refreshing a session past the
cap that `RequireAuth` refuses, leaving a user whose session works everywhere
except on the pages they wanted.

### Keepalive

`OIDCAuth.Keepalive` is an `http.HandlerFunc` for a periodic XHR from the
frontend, so a session does not lapse while somebody reads a long page that
never calls `RequireAuth`. It refreshes the access token when it is near
expiry, answers 204 on success and 401 when there is no usable session, and
clears the cookie when a refresh fails so the browser stops sending one that
can no longer be renewed. Register it on the mux the application uses for its
API endpoints rather than on the `PageMux`:

```go
mux.HandleFunc("GET /auth/keepalive", auth.Keepalive)
```

### Concurrent refreshes

Access tokens are refreshed as they near expiry, and the concurrent refreshes
of one session collapse onto a single round trip to the provider, so the
several requests of one page load do not each post the same refresh token.
With refresh token rotation enabled at the provider they otherwise would: the
first exchange invalidates the token and the rest come back `invalid_grant`,
bouncing the user to login intermittently and under load.

**The deduplication is per process and does not reach across replicas.** The
tokens live in the cookie, so there is nothing for two replicas to coordinate
through. Two replicas serving the same session inside the refresh margin can
still both refresh, which is the remaining exposure if rotation is turned on
fleet-wide.

Two fields RFC 6749 leaves optional are decided where a token enters the
session rather than in the request path. A refresh response without a
`refresh_token` means "keep using the one you have", so the session's own is
carried forward; one without an `expires_in` leaves the access token's
lifetime unknown, so it is assumed to be five minutes and a warning says so.
Keycloak sends both, so that warning appearing means the provider changed.

## 10. When a login fails

Every failure in the callback from the state check onwards logs its reason at
warn level and redirects to the login page with `?login_failed=1`. It does
**not** render an error page.

**That is deliberate, and it is the fix for a real trap.** The callback URL
still carries the authorization code in its query string, so an error page
rendered there is one that a reload re-submits — and a provider's answer to a
code it has already redeemed is `invalid_grant "Code not valid"`. The real
reason for the failure is replaced by a misleading one, and a perfectly
recoverable attempt looks permanent. This cost a debugging session before it
was fixed: a service with a stale `CALLBACK_URL` after a port change reported
only the spent-code error, which pointed nowhere near the cause. Redirecting
takes the code out of the address bar, so trying again actually tries again.

The one exception is a provider that denies the login outright, returning
`error` rather than a code. No code was issued, so reloading that page is
harmless, and the provider's own description is the one thing on it a visitor
can act on — that keeps its error page.

The login page's `Page.Contents` is a `LoginPage`, whose `Failed` field
reports that the last attempt did not complete, so a template can say so:

```html
{{if .Contents.Failed}}
  <p class="error">{{t "LoginFailed" "That login did not complete. Please try again."}}</p>
{{end}}
```

A template that ignores `Contents` renders exactly as before. The *reason*
stays in the log: there is nothing a visitor can do with the detail, and some
of it should not be shown to them.

## 11. Rolling a key over

1. **Add the new key, dated ahead.** Generate a secret and add
   `COOKIE_KEY_2=<future timestamp>_<secret>` alongside `COOKIE_KEY_1`, then
   deploy. Nothing changes yet — every replica now *accepts* both keys and
   still seals with key 1. Set the timestamp far enough ahead that the
   rollout finishes first: no replica may seal with a key another replica
   has not got.
2. **The timestamp passes.** Each replica starts sealing with key 2 as it
   crosses. Values sealed under key 1 keep opening, and each one is re-sealed
   under key 2 on the next request that touches its session. Nobody is
   logged out. `selected cookie sealing key` in a restarted replica's log,
   or `SealingKey()`, confirms which key is in use.
3. **Wait out the maximum session age** (`howdah.DefaultMaxSessionAge`,
   or whatever `WithMaxSessionAge` was given). Re-sealing only happens on a
   request, so an idle session keeps its key 1 cookie until its user comes
   back or it ages out; there is no way to sweep outstanding cookies. A
   later release that keeps sessions server-side will replace this wait with
   a re-key pass.
4. **Drop the old key.** Remove `COOKIE_KEY_1` and deploy. Renumber the rest
   if you like — the numbers carry no meaning. Any straggler still holding a
   value sealed under key 1 comes back as `ErrUnknownKey`, has its cookie
   unset, and lands on the login page.

**Emergency revocation is step 4 done immediately.** Delete the compromised
key and deploy, and everyone holding a value sealed under it is logged out.
Note what that costs: every session sealed under that key dies, not only the
ones you are worried about.
