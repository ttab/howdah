# Sealed sessions and a token store

Encrypt howdah's session cookie under a rotatable keyring, move the tokens
behind a `TokenStore` so refreshes have a single winner, and upstream the
cookie hardening imagereporting is currently carrying downstream.

> **This is a working document, not documentation.** Everything it proposes
> has now been built, and where it disagrees with the documentation set the
> set wins — some figures in here were estimates that a real measurement has
> since corrected, and the implementation settled several details this
> document only sketched. It is kept because open decision 5 is still open,
> and because the reasoning behind the refresh lease is worth having in one
> place. Delete it when logout revokes at the provider.

| | |
|---|---|
| Status | v0.2.0 and v0.3.0 shipped; §1–10 are built |
| Shipped | all of §1–10, including §5's interface, the cookie-backed store, §6's refresh lease, §7's schema and migrations, and §10's store tests |
| Still live | [§11's open decisions 4 and 5](#11-open-decisions). The build followed 4's recommendation — one module, pgx in every consumer's `go.sum` — and 5 is untouched: nothing talks to the provider on logout. |
| Documented properly in | [cookies.md](cookies.md), [architecture.md](architecture.md), [README](../README.md#where-sessions-live) |
| Superseded figures | §5's cookie sizes — measured at 2453 B, not the 3527 first estimated |

### What the implementation of §6 and §7 added

The lease, the schema and the sweep are built as described, plus five things
this document does not mention and each of which is load-bearing:

| Addition | Why |
|---|---|
| `refresh_failed_at` is in the lease's own predicate, not only read by the losers | A loser that read the row before the winner failed and asked for the lease after it would otherwise find the lease free and exchange the same refresh token again, which is the *n* attempts per outage the column exists to prevent. |
| The write-back runs on a detached context too, not just the exchange | The provider has already acted by then, so a client that disconnects between the two takes the rotated token with it. |
| The whole of `Refresh` is bounded by one deadline | Every path back to the top of its loop is a wait for somebody else, including a lost write-back, so the budget belongs to the call rather than to each branch. |
| `Rekey` deletes a payload that will not open | It is a session nobody can use, and skipping it would leave it in the set the sweep selects, so "call until it returns 0" would never terminate. |
| `SessionSealer` in the root package | §5 settled that stores seal, but the unexported `seal`/`open` pair cannot be reached from a subpackage; the sealer exports both halves with the domains behind a constructor, so a hand-written domain is still impossible. |

### What §5 settled, and how

The two questions §5 left open before the interface could be written are
answered, and the answers are in the code rather than here:

| Question | Answer |
|---|---|
| Who seals? | The stores do, and each takes the keyring. `TokenStore`'s doc comment carries the reasoning: sealing in `OIDCAuth` would make it choose the envelope's kind byte and know which kind to expect back, which is the type switch the interface exists to remove. |
| Is "Set-Cookie when the handle changed" enough? | No, and the code says so. The condition is "changed **or** the value came in under a key we no longer seal with", because a stored session's handle survives a refresh and the first half alone would never migrate one. |

Three things the implementation added that this document does not describe:
`StoredToken.Stale`, which is how a store reports the second condition;
`Reseal`, which is how a caller acts on it without writing tokens it only
read; and the cookie-backed store's refusal to keep the raw `id_token`, since
another JWT does not fit in the 1.5 KB a store-less session has left.

### What shipped, and where it is documented now

| Section here | Now the authority |
|---|---|
| §2 the envelope, §3 the keyring | [cookies.md §3, §5–7](cookies.md#3-the-sealed-envelope) |
| §4 failure taxonomy | [cookies.md §8](cookies.md#8-when-a-cookie-cannot-be-opened) |
| §8 cookie hardening | [cookies.md §2](cookies.md#2-cookie-attributes) |
| §9 rollover runbook | [cookies.md §11](cookies.md#11-rolling-a-key-over) |

Two things were added after this document was written and are not described in
it at all: the refusal to write a session cookie a browser would drop, and the
redirect to the login page when a callback fails. Both are in
[cookies.md](cookies.md) (§4 and §10).

## Contents

1. [What's true today](#1-whats-true-today)
2. [The envelope](#2-the-envelope)
3. [The keyring](#3-the-keyring)
4. [Failure taxonomy](#4-failure-taxonomy)
5. [The token store](#5-the-token-store)
6. [Serialising refresh](#6-serialising-refresh)
7. [Schema and migrations](#7-schema-and-migrations)
8. [Cookie hardening, upstreamed](#8-cookie-hardening-upstreamed)
9. [Rollover runbook](#9-rollover-runbook)
10. [Tests](#10-tests)
11. [Open decisions](#11-open-decisions)
12. [Sequencing](#12-sequencing)

---

## 1. What's true today

Three questions started this, and all three have been checked against the
code rather than assumed.

### The cookie is host-only

`Domain` is never set on any cookie howdah writes — `grep Domain` across the
package returns nothing — and a `Set-Cookie` without `Domain` is host-only by
definition. That is the right default, and it should stop being an accident:
pin it with a test.

### The cookie is not encrypted

`setTokenCookie` is `base64.RawURLEncoding(json.Marshal(token))`. The access
token *and the refresh token* are readable by anyone holding the cookie value
— a browser profile on disk, a proxy log, a support screenshot pasted into a
ticket. `HttpOnly` keeps scripts out; it does nothing about any of that.

### imagereporting's claims hold up

Serialising the cookie howdah actually emits gives:

```
token=v; Path=/; Expires=Sun, 06 Sep 2026 05:06:19 GMT; HttpOnly
```

No `SameSite`, and `Secure` is `r.TLS != nil`, which is false behind a
TLS-terminating ingress. So `internal/web/cookies.go` is accurate, including
its "This belongs upstream in howdah" comment. [Section 8](#8-cookie-hardening-upstreamed)
upstreams it.

### Not asked about, but worse

**There is no server-side session expiry at all.** A cookie's `Expires` is an
instruction to the browser, not a check the server makes. Someone holding a
copied cookie value keeps a live session until the *refresh token* dies,
because `checkTokenExpiry` will happily keep refreshing. Logout clears the
cookie in one browser and revokes nothing. Both are fixed below, and the
cheaper half doesn't need a database.

---

## 2. The envelope

One binary envelope, base64url-encoded into the cookie value.

```
 1 B   1 B     8 B            12 B                    n B              16 B
┌─────┬─────┬──────────┬──────────────────┬────────────────────────┬──────────┐
│ ver │kind │   kid    │      nonce       │       ciphertext       │   tag    │
└─────┴─────┴──────────┴──────────────────┴────────────────────────┴──────────┘
└────────────────────┘
          ↑ authenticated but not encrypted, together with the domain string
```

Version `1` is AES-256-GCM from `crypto/aes` and `crypto/cipher` — no new
dependency — with a random 12-byte nonce. A later format takes a new version
byte; readers dispatch on it, writers only ever emit the current one. That is
the format-evolution half of the ask, running on the same rails as key
rotation.

`kind` says what the ciphertext wraps: a whole token payload, or a handle to
one in a store. It sits in the header rather than the plaintext so a reader
can reject a value from the other mode without holding the right key at all,
and it is covered by the AAD so it cannot be edited. See
[the two modes](#the-two-modes) for why one byte here saves a migration later.

### Additional authenticated data binds the envelope to its purpose

AES-GCM is an AEAD — authenticated encryption with associated data — which
means that besides the plaintext it takes a second input, the **additional
authenticated data** (AAD). The AAD is not encrypted, but it is mixed into
the authentication tag, so opening the envelope succeeds only if the reader
supplies byte-for-byte the same AAD the writer sealed with. It is how you say
"this ciphertext is valid in this context and nowhere else".

Ours is `version ‖ kind ‖ kid ‖ domain`:

* `version`, `kind` and `kid` are already in the envelope in the clear.
  Authenticating them stops anyone editing the header — claiming a different
  key, a different format, or a payload where a handle belongs — without
  invalidating the tag.
* `domain` is never transmitted at all. The reader supplies it from the call
  site, so it acts as a label the ciphertext must match. Only the last field
  is variable-length, so the concatenation is unambiguous.

The domain must carry **cookie identity, not just value kind**:
`"cookie:" + a.cookieName`, `"cookie:auth_redir:" + a.cookieName`,
`"store:" + a.cookieName`. A domain of merely `"cookie:token"` would not do
the job the next paragraph claims for it.

Two things fall out. A sealed value cannot be moved between cookies — which
matters precisely because `WithSessionCookieName` exists so co-hosted
applications can share a host, and they will share a keyring. And a payload
sealed for a database row cannot be replayed as a cookie.

> **Why cookie identity, specifically.** `NewOIDCAuth` builds its access
> verifier with `SkipClientIDCheck: true` (`application_auth.go:84-86`), so a
> token minted for application A verifies in application B. Two co-hosted
> applications sharing a keyring and a domain of `"cookie:token"` therefore
> have a privilege escalation: copy the value of `token_a` into `token_b` and
> the low-privilege session opens as a high-privilege one, end to end. The
> cookie name in the domain is what closes it.

```go
func (k *CookieKeyring) Seal(domain string, plaintext []byte) (string, error)
func (k *CookieKeyring) Open(domain, value string) (plaintext []byte, current bool, err error)
```

`current` reports whether the value was sealed under the key we would seal
with now. `false` is the migration trigger — re-seal it on the way out.

### The key id is derived, not the variable's number

`kid` is the first 8 bytes of `SHA-256("howdah-cookie-key-v1" ‖ secret)`.

This matters more than it looks. If `kid` were the `1` or `2` from the
environment variable name, then reusing `COOKIE_KEY_1` for a new secret would
make every outstanding cookie fail *authentication* rather than come back as
*unknown key*. A signal you want to stay loud — someone is tampering, or two
environments have been crossed — would be buried under routine rotation
noise. Deriving the id from the secret means retiring a key produces exactly
the "unknown kid, unset the cookie, send them to login" path, and no
numbering discipline is required of whoever edits the environment.

---

## 3. The keyring

```
COOKIE_KEY_1=2026-08-01T00:00:00Z_TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IA==
COOKIE_KEY_2=2026-09-15T00:00:00Z_aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXIgcGE=
```

Split on the **first** `_`. RFC 3339 contains no underscore, so this is
unambiguous whatever the secret's alphabet. The secret is standard base64 of
exactly 32 bytes; anything else is a startup error, not a runtime surprise.

```go
// DefaultCookieKeyPrefix is the environment variable prefix cookie keys are
// read from unless an application says otherwise.
const DefaultCookieKeyPrefix = "COOKIE_KEY_"

type CookieKey struct {
	UseAfter time.Time
	Secret   []byte // 32 bytes
}

// CookieKeyringOption configures CookieKeyringFromEnv.
type CookieKeyringOption func(*cookieKeyringEnv)

// WithCookieKeyPrefix reads the keys from a different environment variable
// prefix. An application only needs this if it hosts two independent
// keyrings; everything else stays on DefaultCookieKeyPrefix.
func WithCookieKeyPrefix(prefix string) CookieKeyringOption

func NewCookieKeyring(keys []CookieKey) (*CookieKeyring, error)
func CookieKeyringFromEnv(opts ...CookieKeyringOption) (*CookieKeyring, error)
func GenerateCookieKey() (string, error) // for ops
```

The prefix is an option rather than an argument so that the zero-effort call
is the uniform one. `CookieKeyringFromEnv()` reads `COOKIE_KEY_*` in every
application, which means one secret naming convention across the fleet, one
externalsecrets shape, and one rollover runbook that names the actual
variables rather than saying "whatever this service calls them". Overriding
the prefix stays possible and reads as the deliberate exception it is.

### Selection rules

* **Sealing key:** among the keys whose `UseAfter` is in the past, the latest
  `UseAfter` wins. A tie is a configuration error at startup, not a coin flip.
* **Every configured key opens, including future-dated ones.**
* **Zero keys is an error**, and so is **zero *eligible* keys.** A fresh
  environment handed the fleet's rollover-dated key must fail at startup, not
  boot cleanly and then fail on the first login.
* **Log the sealing key's `kid` and `UseAfter` at startup.** The opposite
  operator error — a new key dated in the past by accident — starts sealing on
  the first restarted replica while its siblings cannot open the result, which
  is exactly the mystery-logout scenario the callout below warns about. There
  is no way to prevent it in code; there is a way to make it visible in one
  log line.
* Parse, validate and build one `cipher.AEAD` per key at startup. Nothing in
  the request path reads an environment variable or derives a key.

> **The rule that is easy to get wrong.** Future-dated keys *must* decrypt.
> Replicas do not cross the `use after` boundary simultaneously — clock skew
> alone guarantees it — so a replica still sealing with key 1 will be handed
> cookies sealed with key 2 by a replica whose clock ran ahead. If future keys
> don't open, every rollover logs out a slice of users for the width of the
> skew, and it will look like a mystery.

```
                key 2          its use-after        key 1
                deployed       passes               dropped
                    │              │                   │
COOKIE_KEY_1  ══════╪══════════════╪═══════════════════╡
              seals + opens   │ opens only        │ removed
                              │                   │
COOKIE_KEY_2  ┈┈┈┈┈┈┼──────────────┼═══════════════════════════════
              absent │ opens only  │ seals + opens
```

The "opens only" band on key 2 is the deploy window; the one on key 1 is the
drain. Both have to be wider than they feel like they need to be — see the
[runbook](#9-rollover-runbook).

---

## 4. Failure taxonomy

Every one of these ends the same way: unset the cookie, redirect to login.
They differ in what they *mean*, and therefore in how loudly they should be
logged. Collapsing them into today's single `errors.New("invalid token
cookie")` throws away the one row worth alerting on.

| Sentinel | Cause | Level | When it's normal |
|---|---|---|---|
| `ErrNotSealed` | Does not parse as an envelope at all | Info | During the rollout |
| `ErrUnknownVersion` | Envelope from a newer howdah | Info | During a rollback |
| `ErrUnknownKey` | `kid` not in the keyring | Info | After retiring a key |
| `ErrWrongSessionKind` | `kind` is a payload where a handle was expected, or the reverse | Info | After switching a service between store-less and store mode |
| `ErrAuthentication` | Key known, GCM open failed | **Warn** | Rare. Tampering, crossed environments — or a truncated cookie |

> **`ErrNotSealed` needs an explicit check, not version dispatch.** A legacy
> cookie base64-decodes to JSON, whose first byte is `{` — `0x7B`. A reader
> that simply switches on the version byte reports every legacy cookie as
> `ErrUnknownVersion`, polluting the one code that is supposed to mean "we
> rolled back". Validate the envelope's shape first — plausible version, total
> length consistent with header plus tag — and only then dispatch.
>
> The same logic is why `ErrAuthentication` is "rare" rather than "never". A
> 3.6 KB store-less cookie is close enough to intermediary header limits that
> benign truncation happens, and a truncated-but-parseable envelope fails GCM
> open. A Warn bucket that promises zero noise and then carries some is a
> bucket that gets muted.

Unsealed cookies are not migrated. You asked for them to be unset and the user
sent to login, and that is right: the fleet is small, the alternative is
carrying a plaintext reader forever, and "we still accept unencrypted session
cookies" is a sentence nobody wants to write in a year's time.

---

## 5. The token store

### Why: the cookie is not as full as first estimated

The first version of this section extrapolated from a guessed
1.4 KB access + 1.1 KB refresh token and concluded the cookie was at 87% of
its limit. **A real measurement says otherwise.** imagereporting's sealed
store-less session cookie, against the tt realm on stage, is **2 453 bytes** —
comfortably inside the 4 096 a browser guarantees.

| | Cookie value | Headroom to 4096 | Source |
|---|---:|---:|---|
| Sealed payload — store-less mode | 2 453 B | ~1 550 B | measured, imagereporting on stage |
| Sealed payload — the earlier estimate | 3 527 B | 489 B | synthetic, too pessimistic |
| Sealed handle — store mode | 94 B | ~3 922 B | arithmetic, exact |

So **size is the weakest of the arguments for the store**, not the strongest,
and store-less mode has more room than this document originally claimed. It is
still a real ceiling rather than a theoretical one — a realm with a much fatter
`roles` or `groups` claim than tt's would close that 1.5 KB — and the way it
used to present was a login loop nobody could reproduce, because a browser
drops an oversized cookie in silence. That is now a hard failure at write time
naming the byte count, so the ceiling announces itself rather than having to be
inferred.

Read the store's case on the two things below instead, which no amount of
headroom provides.

**And two things size doesn't buy:**

* **Real revocation.** Logout deletes the row, so a copied cookie value dies
  with it. Today logout clears one browser's cookie and revokes nothing.
* **Enforceable session lifetime.** A row has an `expires_at` the server
  checks. A cookie has an `Expires` the browser obeys and an attacker ignores.

### The interface

```go
// TokenStore holds a session's OAuth2 tokens. Implementations must be
// safe for concurrent use by multiple goroutines and processes.
type TokenStore interface {
	// Create stores a new session and returns it. The Handle is what
	// goes in the session cookie.
	Create(ctx context.Context, sub string, tok *oauth2.Token) (*StoredToken, error)

	// Get resolves a cookie handle. It returns ErrNoSession for a handle
	// that is unknown, past its absolute expiry, or sealed under a key
	// that is no longer configured.
	Get(ctx context.Context, handle string) (*StoredToken, error)

	// Update replaces the tokens for an existing session.
	Update(ctx context.Context, handle string, tok *oauth2.Token) (*StoredToken, error)

	// Delete removes a session: logout, and the unset-and-redirect path.
	Delete(ctx context.Context, handle string) error

	// Refresh obtains a new token, deduplicating concurrent refreshes of
	// the same session as far as the implementation is able. exchange
	// performs the token endpoint round trip; callers that lose the race
	// wait for the winner's result rather than repeating it.
	//
	// How far "as far as it is able" reaches is the main thing that
	// separates the implementations, and each one documents it: pgstore
	// is fleet-wide, cookiestore is per-process. Callers must not assume
	// exchange runs exactly once.
	Refresh(ctx context.Context, t *StoredToken,
		exchange func(context.Context, *oauth2.Token) (*oauth2.Token, error),
	) (*StoredToken, error)

	// DeleteExpired removes sessions past their absolute expiry, at most
	// batch at a time. Call until it returns 0.
	DeleteExpired(ctx context.Context, batch int) (int64, error)
}

type StoredToken struct {
	Handle    string        // opaque; the session cookie's plaintext
	Subject   string        // the OIDC sub, for revoke-all-for-user
	Token     *oauth2.Token
	IssuedAt  time.Time
	ExpiresAt time.Time     // absolute session expiry
}
```

The trick that keeps `OIDCAuth` ignorant of which implementation it has:
`Refresh` and `Update` return a `*StoredToken` whose `Handle` *may* differ
from the one that went in. The caller compares, and writes a `Set-Cookie` only
when it changed. For the Postgres store the handle is stable across a refresh,
so nothing is written. For a cookie-backed store the handle *is* the sealed
token, so it changes on every refresh and the cookie is rewritten. Same code
path, no type switch.

Two things this framing does not yet settle, and they need settling before the
interface is written:

* **Who seals?** If `Handle` is the cookie's plaintext then `OIDCAuth` seals
  it — but then `OIDCAuth` must choose the `kind` byte and know which kind to
  *expect* on read, which is the type switch this was supposed to remove.
  Either `TokenStore` grows a method that reports its kind, or the stores own
  sealing and each takes the keyring. The second is probably right, and it
  means `cookiestore` and `pgstore` both take a `*CookieKeyring`.
* **"Set-Cookie only when the handle changed" is stated too absolutely.** In
  store mode the handle is stable across a refresh, but a handle that `Open`
  reported as `current == false` still has to be re-sealed and written, or key
  migration never happens for store-mode sessions. The condition is "changed
  **or** not sealed under the current key".

### One optional extra

```go
// Rekeyer is implemented by stores that can re-seal their payloads
// under the current key without waiting for sessions to expire.
type Rekeyer interface {
	Rekey(ctx context.Context, batch int) (int64, error)
}
```

A table can be swept; outstanding cookies cannot. That collapses the
key-retirement window from "longer than the maximum session lifetime" to
"however long the sweep takes", which is the difference between a week and a
minute.

**The sweep has to be fenced too.** A naive read-payload, re-seal, write-back
that interleaves with a refresh commits a re-sealed copy of the *old* payload
over the new one — which, with rotation on, resurrects a revoked refresh token
and kills the session. Guard the write with
`WHERE key_id = @old_kid AND refreshed_at = @seen_refreshed_at`; both columns
already exist, so this costs nothing but has to be remembered.

### Where the pgx code lives

Subpackage `howdah/tokenstore/pgstore`, depending on `pgx/v5` directly rather
than on `elephantine` — elephantine's `pg` package has the right helpers, but
taking it as a dependency drags Vault, Prometheus and Twirp into the module
graph of every howdah consumer. Follow its layout conventions (`schema.sql`,
`queries.sql`, generated code in `postgres/`) without importing it.

### The two modes

Sessions work with or without a store. `pgstore` keeps the tokens in a row and
puts a sealed handle in the cookie; `cookiestore` seals the whole payload into
the cookie and keeps nothing. Both go through `TokenStore`, so `OIDCAuth` has
one code path and no type switch.

This is not a concession to imagereporting — though that application does
force the issue, having no pgx in its `go.mod` and an egress policy of DNS
plus 443 to `login.stage.tt.se`, deliberately, as the positive statement that
the tool cannot reach our other services. It is that a small backoffice tool
should not need a database to have a login, and an interface with one
implementation is an interface nobody has tested the shape of.

What store-less mode gives up, and what it doesn't:

| | `cookiestore` | `pgstore` |
|---|---|---|
| Cookie size | ~3.6 KB, 489 B of headroom | ~174 B |
| Absolute session expiry | Yes — sealed `issued_at` | Yes — `expires_at` column |
| Refresh deduplication | Per process | Fleet-wide |
| Revocation on logout | No | Yes |
| Revoke all of one subject | No | Yes |
| Key retirement wait | Max session age | A `Rekey` sweep |

Only two rows are hard noes, and both are inherent: you cannot revoke what you
do not store. The rest degrade rather than fail. Note that the sealed
`issued_at` from [section 8](#8-cookie-hardening-upstreamed) is what makes the
last row tractable — without a bounded session age, store-less key retirement
has no defined end.

> **The one real caveat.** Store-less mode is only safe while the realm does
> **not** rotate refresh tokens. With rotation on, two replicas refreshing the
> same session concurrently means one gets `invalid_grant` and bounces the user
> to login. Per-process deduplication (below) shrinks that window a lot but
> cannot close it. Turning on refresh token rotation fleet-wide is therefore a
> decision to move every application onto a store — worth knowing now rather
> than discovering it as intermittent logouts.

---

## 6. Serialising refresh

### The race, concretely

`checkTokenExpiry` refreshes when the access token has under ten seconds left.
A page load that fires several XHRs, plus the keepalive, means several
requests hit that branch at once, each posting the *same* refresh token to the
token endpoint. Right now that is merely wasteful and the last writer wins the
cookie — possibly with an older token than one of its siblings just obtained.

It stops being merely wasteful the moment the realm turns on refresh token
rotation: the first exchange invalidates the refresh token, the rest come back
`invalid_grant`, and every one of those requests redirects to login. The user
is bounced mid-session for no visible reason, intermittently, under load. This
is worth fixing before it is switched on rather than after.

### A lease column, not `SELECT … FOR UPDATE`

> **The tempting wrong answer.** `SELECT … FOR UPDATE` serialises correctly
> and needs no lease tuning, but it holds a transaction — and a pooled
> connection — open across an HTTP round trip to the identity provider. A slow
> or hung IdP then pins one connection per concurrent request and drains the
> pool. The failure mode is the whole application, not just logins.
> `pg_advisory_xact_lock` has the same shape. The lease holds no transaction:
> take it, commit, do the round trip, commit the result.

```sql
-- name: TakeRefreshLease :one
UPDATE howdah_session
SET    refresh_lease_until = now() + @lease::interval,
       refresh_lease_nonce = @nonce
WHERE  id = @id
  AND  (refresh_lease_until IS NULL OR refresh_lease_until < now())
  AND  refreshed_at <= @seen_refreshed_at
RETURNING key_id, payload, refreshed_at;

-- name: CommitRefresh :execrows
UPDATE howdah_session
SET    payload = @payload, key_id = @key_id,
       access_expires_at = @access_expires_at,
       refreshed_at = now(),
       refresh_lease_until = NULL, refresh_lease_nonce = NULL
WHERE  id = @id AND refresh_lease_nonce = @nonce;
```

**The nonce is not optional.** Without it the write-back is unfenced: a winner
whose exchange finished at 9.9 s but whose write stalls past the 15 s lease
loses the lease, a second caller exchanges the *same* refresh token, and then
the stale winner's write lands on top of the fresh one. The row now holds a
refresh token the provider has rotated away, and the session is dead for every
replica. `CommitRefresh` returning 0 rows means "I lost the lease, discard my
result and re-read" — which is safe, because the other refresher succeeded.

The `refreshed_at <= @seen_refreshed_at` clause is the idempotency guard: if
somebody else refreshed between our read and our attempt, `refreshed_at` has
moved past what we saw, we get no row, and we re-read instead of refreshing a
token that is already fresh.

1. **Every caller** — read the session. If the access token still has more
   than the refresh margin left, use it. No lock, no write, no contention on
   the common path.
2. **Every caller** — otherwise attempt the lease above.
3. **Winner** — got a row. Do the token endpoint round trip, then
   `CommitRefresh`. The exchange runs on a context **detached from the
   request** with its own timeout — today's code uses `r.Context()`
   (`application_auth.go:257`), so a client that disconnects mid-exchange
   cancels a call the provider has already acted on. See the lost-token note
   below.
4. **Losers** — got no row. Re-read on a short backoff (25 ms, 50 ms, 100 ms,
   capped around two seconds) and return as soon as `refreshed_at` has
   advanced. No provider call is made.
5. **Winner failed** — it must record that, not just release the lease, or the
   losers poll a `refreshed_at` that never moves, burn the full cap, and then
   each attempt their own exchange against a token the provider may already
   have rotated. An IdP outage otherwise becomes *n* serialised attempts per
   session. A `refresh_failed_at` column the losers can read turns that into
   one attempt and *n* fast failures.
6. **Winner vanished** — process killed. The lease expires (set it above the
   token request timeout, say 15 s against 10 s) and the next caller takes it.
   A dead refresher costs one slow request, not a wedged session.

> **The unavoidable window.** If the exchange succeeds and `CommitRefresh`
> then fails — the database is down for the two seconds it mattered — the
> rotated refresh token exists only in that process's memory. In store mode
> the cookie is just a handle, so there is *no* recovery path: that session is
> gone and the user re-logs in. This is inherent to rotation plus external
> storage, not a flaw in the protocol, but it should be a known and monitored
> event rather than a surprise. It is also an argument for keeping the refresh
> margin generous, so there is room to retry the commit before the access
> token actually expires.

### Store-less deduplication

`cookiestore` has no shared state, so it cannot coordinate across replicas —
but it can stop a single replica from stampeding, which is where most of the
damage comes from. A page load firing five XHRs is five requests in one
process, not five processes.

Key an in-process `singleflight.Group` on the cookie handle. Concurrent
requests carrying the same cookie collapse to one exchange, and all of them
get the same new token — which also fixes the "last writer wins, possibly with
an older token than its sibling just obtained" problem in store-less mode.
`golang.org/x/sync/singleflight` is the whole implementation.

What remains is the cross-replica race, and it is much rarer: it needs two
replicas to handle requests for the same session inside the refresh margin.
Real, but not the common case, and [the caveat above](#the-two-modes) says
when it stops being acceptable.

### Two smaller things this fixes

* **Rotated refresh tokens get persisted.** Keycloak hands back a new refresh
  token; the winner writes it, the losers read it, and nobody is left holding
  a revoked one.
* **`Keepalive` must clear the cookie when a *refresh* fails.** A malformed
  cookie is already cleared by `readTokenCookie`
  (`application_auth.go:471-486`); it is the refresh-failure path that returns
  401 and leaves the dead cookie in place, so the browser re-sends it on every
  subsequent keepalive. Under key rotation that turns a one-off into a standing
  401 loop.

---

## 7. Schema and migrations

```sql
CREATE TABLE howdah_session (
    id                  bytea       PRIMARY KEY,  -- sha256 of the handle
    subject             text        NOT NULL,
    key_id              bytea       NOT NULL,     -- the kid payload is sealed under
    payload             bytea       NOT NULL,     -- sealed oauth2.Token
    access_expires_at   timestamptz NOT NULL,
    refresh_lease_until timestamptz,
    refresh_lease_nonce bytea,                    -- fences the write-back
    refresh_failed_at   timestamptz,              -- so losers stop polling
    refreshed_at        timestamptz NOT NULL,
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL      -- absolute session lifetime
);

CREATE INDEX howdah_session_expires_at_idx ON howdah_session (expires_at);
CREATE INDEX howdah_session_subject_idx    ON howdah_session (subject);
CREATE INDEX howdah_session_key_id_idx     ON howdah_session (key_id);
```

### Why each of the less obvious columns

* `id` is `sha256(handle)`, not the handle. A database dump, a backup on a
  laptop, or a read through an injection then yields no usable session. Cheap,
  and a different threat from sealing the cookie.
* `key_id` is a column as well as a field inside the sealed blob, so `Rekey`
  can find rows under a retiring key through an index instead of opening every
  row to discover which key it used.
* `subject` makes "log this person out everywhere" a one-line delete, which is
  the thing you want at 3 a.m. and cannot do at all today.
* `refresh_lease_nonce` is what makes the write-back safe; see
  [section 6](#6-serialising-refresh).

Consider putting the row `id` in the AAD of the `payload` as well, so a writer
with database access cannot transplant one session's sealed payload into
another session's row.

### Migrations

Tern, in `pgstore/schema/`, embedded so the tooling can reach them, run with
`--version-table howdah_session_version` so howdah's numbering never collides
with the host application's own migrations. Exposed as a documented step the
application calls deliberately — **never from the service's startup path**,
per the house rule: a migration turns every restart, scale-up and rollback
into a schema change.

Queries go through sqlc, following elephantine's layout. This is the first
database code in howdah, so it brings a `magefiles` directory, an `sqlc.yaml`,
and `eltest`-backed tests with it. That's real setup cost and it should be
counted before starting, not discovered.

### Garbage collection

`DeleteExpired` is exposed; the application schedules it. The library does not
start goroutines on its own. An application that already depends on
elephantine can wrap it in `pg.RunInJobLock` so only one replica sweeps; one
that doesn't can run it on a ticker and accept the occasional duplicate
delete, which is harmless.

---

## 8. Cookie hardening, upstreamed

These land with part one. They are what `imagereporting/internal/web/cookies.go`
is doing from the outside, plus three things it can't reach.

| Change | Where | Note |
|---|---|---|
| `SameSite=Lax` on every cookie howdah sets | `token`, `state`, `nonce`, `auth_redir`, `lang` | Lax and *not* Strict — write down why. The OIDC callback is a cross-site top-level navigation from the provider, and Strict drops `state` and `nonce` on exactly that request, breaking every login. |
| `Secure` unconditionally, with `WithInsecureCookies()` for plain-http dev | `application_auth.go` | Rather than adopting the `X-Forwarded-Proto` sniff. See [decisions](#11-open-decisions). |
| Give the `lang` cookie `Path`, `HttpOnly`, `SameSite` and `Secure` | `application.go:130-140` | It is set only by `GET /set-language` (`application.go:84`), so RFC 6265's default path already resolves to `/` — an explicit `Path` is tidiness, not a fix. The missing attributes are the real gap. |
| ~~Validate the `redirect` parameter in `setLanguage`~~ — **done** | `application.go` | Was an open redirect: `redirect` went from the query string straight into the `Location` header. Now resolved through `languageRedirect`, which refuses anything a browser would resolve against another origin and applies the base path — the raw value also dropped the mount prefix, since `page_url` hands templates the post-`StripPrefix` URL. Covered by `TestLanguageRedirect`. |
| `MaxAge: -1` when clearing | `clearTokenCookie` | Keep the past `Expires` too; `MaxAge` is what current browsers act on. |
| Seal an `issued_at` into the envelope and cap session age | keyring + `RequireAuth` | A weaker `expires_at` that needs no database, so the "sessions never actually expire" finding closes in part one rather than waiting for part two. **`issued_at` must be carried forward unchanged across every refresh re-seal** — reset it and the cap slides forward every five minutes and enforces nothing. |
| Assert host-only in a test | new attribute test | No `Domain`, ever. |

### `__Host-` prefix: not now

It would have the browser enforce `Secure` + host-only + `Path=/`, which is
otherwise exactly the posture being built. But it *requires* `Path=/` and so
is incompatible with `WithBasePath`, and it rules out plain-http local
development. Host-only stays an invariant asserted by a test rather than
enforced by the browser. Worth a README note so the question isn't re-opened
every six months.

### What imagereporting does after the release

* Delete `internal/web/cookies.go` and `cookies_test.go`; drop the wrapper at
  `cmd/imagereporting/run.go:189`.
* Update the Security bullet at `docs/ops.md:213`.
* Update the `checkFetchSite` comment at `internal/web/upload.go:356`, which
  justifies itself with "the cookie howdah sets carries no SameSite
  attribute". The check still earns its keep as belt-and-braces; only its
  reasoning changes.

---

## 9. Rollover runbook

1. **Add the key, dated ahead.** Generate a secret. Add
   `COOKIE_KEY_2=<future timestamp>_<secret>` alongside `COOKIE_KEY_1` and
   deploy. Nothing changes yet; every replica now *accepts* both. Set the
   timestamp far enough ahead that the rollout finishes first — no replica may
   seal with a key another replica hasn't got.
2. **The timestamp passes.** Each replica starts sealing with key 2 as it
   crosses. Values sealed under key 1 keep opening and are re-sealed on the
   next request. Nobody is logged out.
3. **Sweep, if there's a store.** Run `Rekey` until it returns 0. Every row is
   now under key 2 and step 4 can happen today rather than next week. Without
   a store, wait out the maximum session lifetime instead.
4. **Drop the old key.** Remove `COOKIE_KEY_1` and renumber. Stragglers come
   back as `ErrUnknownKey`, get their cookie unset, and land on the login page.

**Emergency revocation is step 4 done immediately.** Delete the compromised
key, deploy, and everyone holding a value sealed under it is logged out. With
a store, `DELETE FROM howdah_session` is the bigger hammer and doesn't need a
deploy.

---

## 10. Tests

### Keyring

* Parsing: missing separator, unparseable RFC 3339, wrong secret length, no
  keys at all, tied `UseAfter`.
* Selection: the latest past `UseAfter` seals; a future-dated key opens but
  never seals.

### Envelope

* Round trip. Wrong domain string fails — that's the proof the AAD binding
  works. One flipped byte fails. Unknown `kid` gives `ErrUnknownKey`; legacy
  plaintext gives `ErrNotSealed`.
* A payload-kind envelope handed to a handle-kind reader gives
  `ErrWrongSessionKind` **before** any key is tried, and editing the `kind`
  byte in place gives `ErrAuthentication`.

### Auth flow

* A legacy cookie produces a clearing `Set-Cookie` and a 302 to login.
* A value sealed under a retired-but-still-configured key is opened
  transparently and re-sealed under the new `kid`, with **exactly one**
  `Set-Cookie` on the response. Two would mean `Get` and `Refresh` are both
  writing.

### Attributes

* The golden test: every cookie howdah sets is `HttpOnly`, `SameSite=Lax`,
  `Secure`, has `Path` equal to the base path, and carries no `Domain`. This
  is imagereporting's `TestHardenCookiesInTheApplication` moved to where it
  wanted to live.

### Store, against a real Postgres via eltest

* CRUD round trip; `Get` on an expired row returns `ErrNoSession`; `Delete` is
  idempotent.
* **The one that matters:** fire *n* goroutines at a session whose access
  token has just expired, and assert `exchange` ran **exactly once** and every
  goroutine came back with the same new token.
* A refresher that panics mid-exchange leaves a lease that expires, and the
  next caller succeeds.
* `Rekey` moves every row to the current `kid` and is safe to run concurrently
  with live traffic.

---

## 11. Open decisions

### 1. Does a cookie-backed store ship too? — **decided: yes**

Sessions work with or without a store; see [the two modes](#the-two-modes).
`cookiestore` is close to the code part one already writes, and having a second
implementation from day one is what keeps the interface honest.

Two consequences that follow from the decision rather than being separate
choices: the `kind` byte in the envelope, so a later switch between modes is a
clean re-login instead of a tampering alarm or a format sniff; and the weakened
`Refresh` contract, since a per-process implementation cannot promise what a
fleet-wide one does.

### 2. `Secure` always, or trust `X-Forwarded-Proto`? — **decided: always, shipped**

These are backoffice applications, always behind TLS in every real deployment.

**Recommendation** — `Secure` unconditionally with an explicit opt-out for
local dev. It makes the header-trust question disappear rather than
documenting an answer to it. imagereporting's version is defensible and its
comment argues it well; this one needs no argument.

### 3. Breaking `NewOIDCAuth`? — **decided: take the break, shipped**

The keyring is not optional, so it shouldn't be an `OIDCAuthOption` — an
option every caller must pass is a lie in the API. That means a positional
argument and a constructor that returns an error.

**Recommendation** — take the break. howdah is at v0.1.0 and its own README
calls it unstable. The alternative is a `WithCookieKeyring` that the
constructor errors without, which is the same break dressed as a convenience.

### 4. One module or a nested one? — **still open, v0.3.0**

A `pgstore` package in the main module puts pgx in the `go.sum` of every
howdah consumer, even ones that never import it. Nothing links unless
imported, so the cost is graph noise rather than binary size. A nested
`go.mod` keeps the graph clean at the price of separate tagging.

**Recommendation** — one module. Nested modules make every release a two-step
and the versions drift; graph noise is the cheaper problem.

### 5. Does logout revoke at the provider? — **still open**

Nothing in this proposal talks to the identity provider on the way out.
Deleting the row ends howdah's session but strands a live refresh token at
Keycloak that nobody holds any more, so it cannot be revoked afterwards — and
the emergency `DELETE FROM howdah_session` in [section 9](#9-rollover-runbook)
strands the whole table's worth at once. Doing it properly means an RFC 7009
revocation call in `Delete`, and RP-initiated logout at the end-session
endpoint needs `id_token_hint`, which we do not have: `json.Marshal` on an
`oauth2.Token` drops the `Extra` map, so the `id_token` is absent from today's
cookie and would be absent from the sealed payload and the `payload` column
too.

**Recommendation** — add the raw `id_token` to `StoredToken` in v0.3.0 (it is
free once there is a struct), and treat provider-side revocation as a separate
piece of work rather than smuggling it in here. But say out loud that until it
exists, "revocation" means our session only.

---

## 12. Sequencing

Two releases, and they line up with the two modes. **v0.2.0 is store-less
mode** — sealed payload in the cookie, no database, which is what
imagereporting is waiting for. **v0.3.0 puts that behind `TokenStore`** and
adds `pgstore` beside it, so the interface is extracted from working code
rather than guessed at up front.

### v0.2.0 — sealed cookies

1. **`cookie_crypto.go` and `cookie_keyring.go`.** Envelope, keyring,
   taxonomy, and their tests. Self-contained, no callers yet.
2. **Wire into `OIDCAuth`.** Breaking constructor change. Seal `token` and
   `auth_redir`; leave `state` and `nonce` plain — they're random values
   compared against what the provider echoes back, so their integrity is
   inherent in the comparison, and that reasoning needs a comment so nobody
   "fixes" it later.
3. **Hardening and the attribute golden test.** SameSite, Secure, the `lang`
   cookie's attributes and its open redirect, `MaxAge: -1`, sealed `issued_at`.
4. **Per-process refresh deduplication.** A `singleflight.Group` keyed on the
   cookie value. This needs no interface and no database, and it belongs in the
   release imagereporting actually adopts rather than the one after it.
5. **README and tag.** A "Cookies and session keys" section carrying the env
   format, key generation, and the rollover runbook. Pre-1.0, so no
   `CHANGELOG.md` yet — the breaking change goes in the commit message and the
   README.

> **The plaintext is now a wire contract.** Sealing an `issued_at` means the
> envelope wraps a small struct, not the bare `oauth2.Token` JSON. That struct
> is what v0.3.0's `cookiestore` has to produce byte-compatibly, or every
> store-less user is logged out on upgrade. Version it explicitly and write a
> round-trip test against a v0.2.0-sealed fixture, or accept the logout
> deliberately — but decide now, because discovering it during the v0.3.0
> rollout is the expensive way.

### v0.3.0 — the token store

1. **`TokenStore` and `cookiestore`.** Define the interface against v0.2.0's
   behaviour, so `OIDCAuth` moves onto it with no functional change and the
   refactor is separable from the new implementation, and v0.2.0's
   `singleflight` moves behind `cookiestore` unchanged.
2. **`pgstore`.** Schema, tern migrations, sqlc, the lease. Brings
   `magefiles` and `eltest` into howdah for the first time.
3. **The concurrency test.** Written before the lease, if you have the
   patience — it's the test that says whether any of this worked.
4. **`Rekey` and `DeleteExpired`.** Plus the runbook step 3 that only exists
   once there's a table to sweep.

---

*Proposal against github.com/ttab/howdah @ 97fcb42. Sizes measured against a
1.4 KB access + 1.1 KB refresh token.*
