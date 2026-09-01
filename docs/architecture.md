# Architecture

How howdah is put together, for somebody about to change it. The README is
the reference for using it; this is the design authority for the internals and
the request flows.

| Document | What it settles |
|---|---|
| [README](../README.md) | Orientation and the working reference: what the package holds, how to wire an application up, and every option it takes. |
| **architecture.md** (this document) | The internals: the render pipeline, the hook system, the OIDC flow, and where a session lives. |
| [cookies.md](cookies.md) | The cookie and session contract: sealing, the keyring, rotation, and every way a session ends. |

It does not cover the cookie format or key rotation — those are
[cookies.md](cookies.md) — nor the API surface, which is the README.

## The shape of it

Everything hangs off `NewApplication`, which is deliberately thin: it loads
locales, builds a `PageRenderer`, wraps the caller's `http.ServeMux` in a
`PageMux`, registers the asset server, and calls `RegisterRoutes` on each
component. It owns no request handling of its own beyond `/set-language`.

**The framework has no plugin registry and no lifecycle.** A component is
whatever implements `Component`, and the optional interfaces are discovered by
type assertion at construction time, once. That is why adding a capability to
howdah means adding an interface a component may implement, rather than a
registration call — and why a component that implements an interface howdah
does not know about is silently inert.

```
NewApplication
  │
  ├─ load locale.<lang>.toml from the locales FS ──→ i18n.Bundle
  ├─ NewPageRenderer(templates, bundle, components)
  │     └─ collects template funcs from every TeplateFuncSource
  ├─ NewPageMux(renderer, serveMux)
  ├─ register GET /assets/  (http.FileServerFS, prefix stripped)
  ├─ register GET /set-language
  └─ for each component:
        ├─ RegisterRoutes(pageMux)
        └─ if ComponentObserver: ObserveComponent(every component)
```

`ObserveComponent` is called with every component including the observer
itself, so an observer that cares has to filter itself out.

## The request pipeline

`PageMux` exists so that a handler returns *what to render* rather than
writing bytes. That single decision is what makes error pages, titles, menus
and breadcrumbs uniform without every handler remembering them.

```
http.ServeMux
  │
  ▼
PageMux.Handle
  │
  ├─ handler(ctx, w, r) → (*Page, error)
  │     │
  │     ├─ error is ErrSkipRender  ──→ return, write nothing
  │     │      (the handler already wrote: a redirect, a file download)
  │     │
  │     ├─ other error ──→ AsHTTPError ──→ renderer.ErrorPage
  │     │      (an untyped error becomes 500)
  │     │
  │     └─ *Page ──→ renderer.RenderPage
  │                    ├─ resolve language (cookie, then Accept-Language, then en)
  │                    ├─ collect menu from every MenuHook, then Alter hooks
  │                    ├─ mark the active menu item by matching r.URL.Path
  │                    └─ execute Page.Template with the i18n funcs bound
```

**`PageMux` does not authenticate anything.** There is no route-level auth
hook: a handler that needs a session calls `RequireAuth` itself. That is a
deliberate trade — it means a new route can be added without a session check
and nobody notices — and the way applications close it is to wrap the
`Authenticator` they hand their components, so the check is in one place they
control rather than in howdah. imagereporting's `RoleAuth` is the worked
example: it wraps howdah's authenticator, adds a realm-role requirement, and
components never see the unwrapped one.

## The hook system

`Hooks[D, T]` is two-phase on purpose. Build hooks contribute; alter hooks see
the whole collected list and can rewrite it.

```
Collect()  → every RegisterHook fn, concatenated, sorted by Weight
Alter(...) → every RegisterAlter fn in turn, each handed the full list
```

The split is what lets a component hide or reorder another component's menu
item without knowing which component contributed it — a build hook cannot,
because it only ever returns its own items. Alter hooks receive an
`AlterContext[D]` carrying the request, so the decision can depend on who is
asking.

Menus are the only user of `Hooks` today. The type is generic because the
second user was expected and the shape is the interesting part.

## Language resolution

Three sources, in order: the `lang` cookie, the `Accept-Language` header,
English. The cookie is written only by `GET /set-language`, which is
registered by `NewApplication` rather than by a component, because a language
switch that only works on pages a particular component serves is not a
language switch.

That endpoint takes a `redirect` parameter, and it is client-supplied input
that goes into a `Location` header. It is refused unless it is an absolute
path within the application; anything a browser would resolve against another
origin falls back to the application root. **This was an open redirect until
v0.2.0** — the value went into the header unvalidated — and the fix also
resolves it against the base path, which the raw value did not, so a
prefix-mounted application used to send the visitor to the server root.

## The OIDC flow

```
  GET /any-protected-page
    │  RequireAuth: no usable session
    ▼
  302 → GET /auth/login?redirect=<app-relative path>
    │  renders login.html, Contents = LoginPage{Failed: …}
    ▼
  POST /auth/login
    │  mint state + nonce, seal the redirect target into auth_redir
    │  all three scoped to <base>/auth, single-use
    ▼
  302 → the provider's authorize endpoint
    │
    ▼
  GET /auth/callback?code=…&state=…      (cross-site top-level navigation:
    │                                     which is why SameSite is Lax)
    ├─ read state, nonce, auth_redir, then clear all three
    ├─ compare state
    ├─ exchange the code               ─┐
    ├─ verify the ID token              │ any failure from here on:
    ├─ compare the nonce                │ log at warn, 302 to the login
    ├─ WithOnLogin callback, if any     │ page with ?login_failed=1
    ├─ store.Create then set the cookie ─┘ (never an error page — see
    └─ 302 → the redirect target             cookies.md §10)
```

**The callback cookies are cleared as they are read, before the state
comparison.** Every path below that point ends the attempt, and a value left
behind is one the next callback picks up — an abandoned attempt's redirect
target would otherwise hijack the landing page of a later login started
without one. Clearing before the comparison means a forced navigation to the
callback costs the visitor the login button again, which is the better half of
the trade.

`state` and `nonce` are not sealed. They are random values whose only job is
to be compared against what the provider echoes back, so rewriting either one
makes the comparison fail; sealing them would buy nothing. `auth_redir` is
sealed because it is a value the application acts on. This is settled — see
cookies.md §1.

The session itself is the store's, not the callback's: `store.Create` is
handed the token set, the `sub` and the raw `id_token`, and hands back the
handle that goes in the cookie — see [Where a session
lives](#where-a-session-lives). Refresh, the session age cap and `Keepalive`
are [cookies.md §9](cookies.md#9-what-ends-a-session).

## Mounting under a path prefix

`BasePath` is a component that carries the mount point and contributes the
`{{base_path}}` template function. It is a `string` rather than a struct so
that the zero value is the root mount and costs nothing.

The problem it solves is that `http.StripPrefix` makes the application blind
to its own prefix: `r.URL.Path` is stripped, so anything howdah emits *for the
browser* — redirects, cookie paths, menu hrefs — would point at the server
root. Everything that builds such a URL goes through `BasePath.Path`, and
`WithBasePath` is what tells `OIDCAuth` about it.

**A prefixed application must also be told its own cookie name.** Cookies are
scoped by host and path, and not by port, so two applications on one host —
including two on different ports of `localhost` — share a cookie jar and will
overwrite each other's sessions under the default name. `WithSessionCookieName`
is not optional in that arrangement, and it doubles as the sealing domain, so
two applications can share a keyring without being able to open each other's
sessions.

## Where a session lives

`OIDCAuth` does not hold sessions; a `TokenStore` does, and the default one is
`CookieTokenStore`, which seals the whole session into the cookie and keeps
nothing. The store owns sealing, which is the decision the interface is built
around: if `OIDCAuth` sealed the handle itself it would have to choose the
envelope's kind byte and know which kind to expect on the way back in, and
that is the "which implementation have I got" switch the interface exists to
remove.

```
  a request carrying a session cookie
    │
    ▼
  readTokenCookie ── store.Get(cookie value) ──→ *StoredToken
    │                    ├─ ErrNoSession ──→ clear the cookie, 302 to login
    │                    └─ anything else ──→ keep the cookie, 503
    ▼
  checkTokenExpiry
    ├─ access token has more than the refresh margin left
    │    └─ Stale? ──→ store.Reseal ──→ one Set-Cookie
    └─ otherwise
         └─ store.Refresh(exchange) ──→ Stale? store.Reseal
              ├─ handle changed? ──→ one Set-Cookie
              ├─ ErrRefreshRejected ──→ clear the cookie, 302 to login
              └─ anything else ──→ keep the cookie, 503
```

**Only a session that is over takes the cookie with it.** The two outcomes on
the right of every failure are the same split, and it is `sessionGone` that
makes it: a session unknown to the store, past its absolute expiry, sealed
under a key that is gone, or one the provider has refused to refresh
(`ErrNoSession`, `ErrRefreshRejected`) is over, so the cookie is cleared and
the browser stops sending it. Everything else — the storage could not be read,
the wait for another caller's refresh ran out, the write-back was fenced —
means "I could not find out", and the session is very likely still there.

That distinction did not exist before the tokens moved into a store, because
a store-less session *is* the cookie: there was nothing else to lose, so
clearing it on any failure cost nothing. A stored session is a row, and the
cookie is the only handle anybody has to it. Clearing it over a two-second
database failover logs out every user whose access token happened to be
inside the refresh margin — and leaves their rows unreachable until
`DeleteExpired` sweeps them at the maximum session age. Those requests fail
with a 503 instead, and the next one succeeds against the row that never
went anywhere. `TestSessionSurvivesAStoreThatCannotAnswer` holds the line.

**The cookie is written when the handle changed *or* when the value came in
under a key we no longer seal with,** and both halves are load-bearing. A
store-less handle is the sealed session itself, so it changes on every write;
a handle to a stored session survives a refresh, so "changed" alone would
never fire and a key rollover would never reach a stored session at all.
Every branch resolves to at most one `Set-Cookie`, which is what
`TestSessionCookieReSealedUnderCurrentKey` and
`TestStoredSessionStaleHandleIsResealed` hold the line on.

The token endpoint round trip stays in `OIDCAuth` and is passed to
`Refresh` as a function, on a context detached from the request: a client
that disconnects mid-exchange would otherwise cancel a call the provider has
already acted on, and with several requests collapsed onto one exchange the
client that goes away is not necessarily the one that started it. Which
requests share an exchange, and whether that reach is a process or the fleet,
is the store's business.

**Detached from the cancellation, not from the deadline.**
`context.WithoutCancel` returns a context with no deadline at all, so
detaching by itself throws away whatever budget the caller set — and a store
that bounds the exchange before handing it down sizes its refresh lease
against exactly that budget. `detachedDeadline` therefore keeps the sooner of
the caller's deadline and howdah's own ten seconds, so the number the store
validated against is the number that bounds the round trip. An exchange that
outlives the lease is an exchange a second caller is free to repeat, which
with refresh token rotation on is the failure the lease exists to prevent.

### One refresh per session, fleet-wide

`tokenstore/pgstore` is the store for an application with a database, and
what it adds beyond revocation and a server-checked expiry is that a refresh
happens once per session however many replicas want one. It does that with a
**lease column** rather than a lock:

```
  every caller ── read the row
    ├─ the token in it is still good ──→ use it, no provider call
    └─ otherwise ── conditional UPDATE taking the lease
         ├─ got the row  ──→ exchange (detached ctx) ──→ commit, fenced on the
         │                                              lease nonce
         │                    └─ no rows? the lease was lost: discard, re-read
         └─ got nothing ──→ poll on a bounded backoff until refreshed_at moves
                            (or refresh_failed_at does, and fail fast)
```

**Not `SELECT … FOR UPDATE`, and not `pg_advisory_xact_lock`.** Either would
serialise correctly and need no lease tuning, and either holds a transaction —
and therefore a pooled connection — open across an HTTP round trip to the
identity provider. A hung provider then pins one connection per concurrent
request and drains the pool, so the failure mode is the whole application
rather than just its logins. The lease holds no transaction: take it, commit,
do the round trip, commit the result.

Seven details that are each a bug if left out, and each have a test:

- **The write-back is fenced on a lease nonce.** A refresher whose exchange
  finished but whose write stalled past its lease would otherwise land on top
  of a fresher winner's tokens, leaving a rotated-away refresh token in the
  row and the session dead everywhere.
- **The failure write-back is fenced the same way, and its row count is
  read.** Zero rows means this refresher no longer owns the refresh, and its
  own exchange error then says nothing about the session — most often it *is*
  `invalid_grant`, because the caller that took the lease over rotated the
  token this attempt was posting. Reporting it would end a session that was
  refreshed a millisecond earlier, so it goes the way a fenced-out success
  goes: discarded, and the row re-read.
- **The re-read after a lost write-back is exempt from the wait.** A write is
  fenced out only because somebody else's landed, so the answer is committed
  already and one read away rather than an unknown wait. Giving up on the
  budget there would answer `ErrRefreshTimeout` — and cost the caller its
  session — over a token sitting in the row.
- **The exchange and the write-back run on a context detached from the
  request.** The provider has already acted; a client that disconnects must
  not take the rotated token with it.
- **The lease covers the round trip *and* the write-back.** The refresher
  holds it from `TakeRefreshLease` until `CommitRefresh` lands, so a lease
  sized against the round trip alone expires while the winner is still
  committing — and the duplicate exchange that authorises is the failure the
  lease exists to prevent. `New` refuses a store where the lease does not
  outlast the token request timeout and the write timeout together.
- **A refresher that fails records that.** Without the `refresh_failed_at`
  column the waiting callers poll a `refreshed_at` that never moves, burn
  their whole backoff, and then each attempt an exchange of their own — so a
  provider outage becomes *n* serialised attempts per session instead of one.

`DeleteExpired` takes its batch `FOR UPDATE SKIP LOCKED` in a deterministic
order, which is what makes the sweep on a ticker safe for two replicas at
once: without it one sweeper's statement selects the rows the other is
deleting, waits for its locks and finds them gone — reporting 0 with rows
still in the table — and two deletes taking their rows in opposite orders
deadlock. It does mean that 0 from one sweeper means "nothing here for me
right now" rather than "the table is clean", which is only the same thing
when a job lock leaves one sweeper.

The row id is `sha256` of the handle rather than the handle, so a database
dump yields no usable session, and the row id is in the sealed payload's AAD,
so a writer with database access cannot transplant one session's payload into
another's row.

**A key rollover reaches a stored session in two halves, and only one of them
is a sweep.** The handle in the cookie is re-sealed by the request that
carries it — `Stale`, then `Reseal` — and the payload in the row is re-sealed
when a refresh writes it, which is to say never for a session nobody is using.
**There is deliberately no sweep for that second half.** A sweep could
re-seal the rows, but it could not reach the cookies, so it would not shorten
the wait before a retired key can be dropped — and a sweep racing a refresh
is how a token the provider has revoked gets written back over a live one.
The wait is the maximum session age with a store or without it: a session that
never refreshes is one that expires, and `DeleteExpired` takes the row. [cookies.md §11](cookies.md#11-rolling-a-key-over) is
the runbook that puts the two halves in order.

## Pending work

- **Nothing talks to the provider on logout.** No RFC 7009 revocation and no
  RP-initiated logout, so a session howdah ends leaves a live refresh token at
  the provider. `NewSession` and `StoredToken` carry the raw `id_token` that
  `id_token_hint` needs — `json.Marshal` drops `oauth2.Token`'s `Extra` map,
  so a store that does not take it at creation cannot get it back — but the
  cookie-backed store drops it, having nowhere to put another JWT. `pgstore`
  keeps it, so this is a piece of work rather than a piece of work plus a
  migration. The reasoning, and what it would take, is
  [sealed-sessions.md §11](sealed-sessions.md#11-open-decisions), which is
  kept for exactly that decision.
- **`pgx` is in the module graph of every consumer.** `pgstore` is a package
  in the main module rather than a nested one, so an application with no
  database still resolves `github.com/jackc/pgx/v5` and
  `github.com/jackc/tern/v2` in its `go.sum`. Nothing links unless it is
  imported, and one module keeps a release one tag, so the trade was made
  deliberately — but it is a trade, and a nested module is what to reach for
  if the graph noise starts to cost something.
- **A session that survives a lost write-back.** If a refresh's exchange
  succeeds and the commit then fails, the rotated token exists only in that
  process's memory, and a stored session's cookie is only a handle — so there
  is no recovery path and the user logs in again. Inherent to rotation plus
  external storage, but it should be a monitored event rather than a
  surprise.
