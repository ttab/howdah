# Howdah

<p>
  <img src="https://github.com/ttab/howdah/raw/main/docs/logo.png?raw=true" width="256" alt="Howdah logo">
</p>

Unstable/experimental Go library for creating elephant backoffice web UIs.

Howdah provides a component-based web framework with built-in OIDC
authentication, internationalization (i18n), page rendering, and a menu system.
Components register routes on a `PageMux` that returns structured `*Page`
objects instead of writing HTTP responses directly, and a `PageRenderer`
handles template execution and locale resolution.

```
go get github.com/ttab/howdah
```

| Document | What it settles |
|---|---|
| **README** (this document) | Orientation and the working reference: what the package holds, how to wire an application up, and every option it takes. |
| [docs/architecture.md](docs/architecture.md) | How howdah is built: the render pipeline, the hook system, and the OIDC flow. Read it before changing howdah itself. |
| [docs/cookies.md](docs/cookies.md) | The cookie and session contract: sealing, the keyring, key rotation, and every way a session ends. |

## Quick start

```go
package main

import (
	"embed"
	"log/slog"
	"net/http"

	"github.com/ttab/howdah"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed locales
var locales embed.FS

//go:embed assets
var assets embed.FS

func main() {
	logger := slog.Default()
	mux := http.NewServeMux()

	app, err := howdah.NewApplication(
		logger,
		mux,
		templates,
		locales,
		assets,
		[]howdah.Component{
			// your components here
		},
	)
	if err != nil {
		panic(err)
	}
	defer app.Cleanup()

	http.ListenAndServe(":8080", mux)
}
```

## Concepts

### Application

`NewApplication` is the entry point. It takes a logger, an `http.ServeMux`,
three `fs.FS` values (templates, locales, assets), and a slice of components.
It wires everything together: loads locale files, creates the `PageRenderer`,
sets up the `PageMux`, registers an asset file server at `/assets/`, and calls
`RegisterRoutes` on each component.

### Components

A component is anything that implements the `Component` interface:

```go
type Component interface {
    RegisterRoutes(mux *PageMux)
}
```

Components register route handlers on the `PageMux`. They can optionally
implement additional interfaces to hook into other parts of the framework:

| Interface | Purpose |
|---|---|
| `MenuHook` | Contribute items to the navigation menu |
| `ComponentObserver` | Observe other registered components |
| `TeplateFuncSource` | Provide custom template functions |

### PageMux and PageHandlers

`PageMux` wraps `http.ServeMux` but expects handlers that return a `*Page`
instead of writing a response:

```go
type PageHandlerFunc func(
    ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error)
```

The mux takes care of rendering the page or handling errors. If a handler
returns an error, it is rendered as an error page. Return `ErrSkipRender`
to signal that the handler already wrote its own response (e.g. a redirect).

### Page

A `Page` describes what to render:

```go
type Page struct {
    Status     int        // HTTP status code (defaults to 200)
    Template   string     // name of the Go template to execute
    Title      TextLabel  // page title (translatable)
    Menu       []MenuItem // additional menu items for this page
    Breadcrumb []Link     // breadcrumb trail
    Contents   any        // arbitrary data passed to the template
}
```

### Menu system

The menu is built from contributions by all components that implement
`MenuHook`. Items are sorted by `Weight` (lower values appear first). Menu
hooks support two phases:

- **Build hooks** (`RegisterHook`) — return menu items to include.
- **Alter hooks** (`RegisterAlter`) — modify the collected menu list after all
  build hooks have run. This lets components hide, reorder, or annotate items
  based on request context.

The active menu item is determined automatically by matching the current
request path against each item's `HREF`.

```go
func (c *MyComponent) MenuHook(hooks *howdah.MenuHooks) {
    hooks.RegisterHook(func() []howdah.MenuItem {
        return []howdah.MenuItem{
            {Title: howdah.TL("Dashboard", "Dashboard"), HREF: "/", Weight: 0},
        }
    })
}
```

## Internationalization

Locale strings are loaded from TOML files in the locales filesystem. Files must
be named `locale.<lang>.toml` (e.g. `locale.en.toml`, `locale.sv.toml`). The
format follows [go-i18n](https://github.com/nicksnyder/go-i18n):

```toml
[Dashboard]
other = "Dashboard"

[Greeting]
other = "Hello, {{.Name}}"
```

The user's language is resolved from a `lang` cookie, falling back to the
`Accept-Language` header, with English as the final default. A built-in
`/set-language` endpoint sets the cookie, and gives it the same attributes as
every other cookie howdah sets (see
[docs/cookies.md §2](docs/cookies.md#2-cookie-attributes)). Its optional `redirect` parameter must be
an application-relative path — the URL `page_url` hands templates, with the
mount prefix already stripped — and anything a browser would resolve against
another origin is ignored in favour of the application root.

### Template functions

The following functions are available in all templates:

| Function | Signature | Description |
|---|---|---|
| `t` | `t "MessageID" ["fallback"]` | Translate a message by ID |
| `tl` | `tl .Label` | Translate a `TextLabel` value |
| `td` | `td "ID" "fallback" .Data` | Translate with template data |
| `lang` | `lang` | Returns the current language code |
| `ctx` | `ctx` | Returns the request context |
| `page_url` | `page_url` | Returns the current request URL |
| `pathescape` | `pathescape "value"` | URL path-escapes a string |
| `renderBlock` | `renderBlock "name" .Data` | Renders a named template block |

### TextLabel

`TextLabel` is used throughout the API for translatable strings. Create them
with the helper functions:

```go
howdah.TL("MessageID", "Fallback text")       // i18n message
howdah.TMsg(i18n.Message{ID: "X", Other: "Y"}) // from an i18n.Message
howdah.TLiteral("Not translated")              // literal string, no lookup
```

## Authentication

`OIDCAuth` implements the full OpenID Connect authorization code flow. It
registers routes for login, callback, logout, and handles token refresh
automatically.

The keyring is not optional: the session cookie carries the user's access
*and refresh* token, so howdah has no mode in which it writes them to the
browser in the clear. That is why it is a positional argument rather than an
option, and why the constructor returns an error.

```go
keyring, err := howdah.CookieKeyringFromEnv(
    howdah.WithCookieKeyLogger(logger))
if err != nil {
    return fmt.Errorf("read cookie keyring: %w", err)
}

auth, err := howdah.NewOIDCAuth(provider, verifier, oauth2Config, keyring)
if err != nil {
    return fmt.Errorf("set up authentication: %w", err)
}
```

[Cookies and session keys](#cookies-and-session-keys) has the `COOKIE_KEY_*`
format, how to generate a key, and how to roll one over.

A session lives for `howdah.DefaultMaxSessionAge` (12 hours) and refreshing
the access token does not extend it. Concurrent refreshes of one session
collapse onto a single round trip to the provider, per process. What ends a
session, what `Keepalive` is for, and how refresh behaves are
[docs/cookies.md §9](docs/cookies.md#9-what-ends-a-session).

### Where sessions live

A session is held by a `howdah.TokenStore`, and unless an application says
otherwise that store is a `howdah.CookieTokenStore`: the whole session is
sealed into the cookie and howdah keeps nothing. That is what howdah has
always done, and it is the right answer for a small backoffice tool that
should not need a database to have a login.

It gives up two things that cannot be had without storing something. It
cannot revoke — logging out clears one browser's cookie, and a copied cookie
value keeps working until the session reaches its maximum age — and its
deduplication of concurrent refreshes reaches one process rather than the
fleet, so two replicas serving the same session inside the refresh margin can
still both refresh. That is harmless until the provider rotates refresh
tokens, at which point it is an intermittent mid-session logout.

`WithTokenStore` hands `OIDCAuth` a store of the application's own instead.
The store owns the session: it seals the handle that goes in the cookie,
enforces the absolute expiry, and decides how far a concurrent refresh
deduplicates. `OIDCAuth` cannot tell which one it is holding — it writes the
handle a store hands back, and writes a new cookie only when that handle
changed or when the value came in under a retired key.

The interface is `Create`, `Get`, `Update`, `Reseal`, `Delete`, `Refresh` and
`DeleteExpired`, plus an optional `Rekeyer` for a store that can re-seal what
it holds under a new key without waiting for sessions to expire. howdah
starts no goroutines of its own, so an application that wants expired
sessions swept calls `DeleteExpired` on a schedule of its own.

### Keeping sessions in Postgres

`howdah/tokenstore/pgstore` is the store for an application that has a
database. The cookie then holds a sealed handle of about ninety bytes, the
tokens live in a row sealed under the same keyring, and the row id is
`sha256` of the handle — so a database dump yields nothing anybody can log in
with, and a sealed payload cannot be moved from one session's row to
another's.

```go
store, err := pgstore.New(pool, keyring, "token")
if err != nil {
    return fmt.Errorf("create the session store: %w", err)
}

auth, err := howdah.NewOIDCAuth(provider, verifier, oauth2Conf, keyring,
    howdah.WithSessionCookieName("token"), // the same name the store took
    howdah.WithTokenStore(store),
)
```

What the row buys: logout is a revocation rather than a cleared cookie,
`DeleteSubject` logs one person out of every browser at once, the absolute
expiry is a column the server checks, and a refresh is **serialised across
the fleet** — the several requests of a page load collapse onto one token
endpoint round trip however many replicas they land on, which is what makes
it safe to turn refresh token rotation on at the provider.

| Option | Effect |
|---|---|
| `WithMaxSessionAge` | The absolute session lifetime. Defaults to `DefaultMaxSessionAge`. |
| `WithRefreshLease` | How long a refresher holds the right to call the token endpoint. Must be longer than the token request timeout, and is what the next caller waits out if a refresher dies mid-exchange. |
| `WithTokenRequestTimeout` | Bounds the token endpoint round trip, which runs detached from the request. |
| `WithRefreshMargin` | How little life an access token may have left for a concurrent refresh's result to be used as-is. |
| `WithRefreshWait` | How long a caller waits for another caller's refresh before failing with `ErrRefreshTimeout`. |
| `WithWriteTimeout` | Bounds the writes that must happen even though the request is gone: recording a refresh, and recording that one failed. |

**The migrations are the application's to run, never the service's to run at
startup** — a migration at startup turns every restart, scale-up and rollback
into a schema change. `pgstore.Migrate(ctx, pool)` applies them from
wherever the application already migrates, and it tracks its version in
`howdah_session_version` so howdah's numbering cannot collide with the
application's own. `pgstore.Migrations` is the embedded `fs.FS` for tooling
that would rather do it itself.

Two jobs the application schedules, because howdah starts no goroutines:
`DeleteExpired(ctx, batch)` sweeps sessions past their expiry, and
`Rekey(ctx, batch)` re-seals the table under the current key during a key
rollover — which is step 3 of the [rollover
runbook](docs/cookies.md#11-rolling-a-key-over), and the difference between
retiring a key today and retiring it after the longest possible session. Call
either until it returns 0.

### Options

| Option | Effect |
|---|---|
| `WithBasePath` | Resolve redirects and cookie paths against a mount prefix. See [Mounting under a path prefix](#mounting-under-a-path-prefix). |
| `WithSessionCookieName` | Name the session cookie. Required when applications share a host, and it is also the sealing domain. |
| `WithMaxSessionAge` | Change the maximum session age from `DefaultMaxSessionAge`. Configures the store howdah builds for itself, so it cannot be combined with `WithTokenStore`. |
| `WithTokenStore` | Keep sessions in a store of your own rather than in the cookie. See [Where sessions live](#where-sessions-live). |
| `WithInsecureCookies` | Drop `Secure`. For a plain-http local run, and nothing else. |
| `WithOnLogin` | A callback after a successful login, before the session cookie is set. Provision users here rather than on every request. |

### Routes registered

| Route | Purpose |
|---|---|
| `GET /auth/login` | Renders the login page |
| `POST /auth/login` | Redirects to the OIDC provider |
| `GET /auth/callback` | Handles the OIDC callback |
| `GET /auth/logout` | Clears the session and redirects to the application root |

`OIDCAuth.Keepalive` is an `http.HandlerFunc` rather than a registered route,
for a periodic XHR that keeps a session alive while somebody reads a page that
never calls `RequireAuth`. Register it on whichever mux serves the
application's API endpoints — see
[docs/cookies.md §9](docs/cookies.md#keepalive).

A failed login redirects back to `GET /auth/login` with `?login_failed=1`
rather than rendering an error page, and the login page's `Page.Contents` is a
`howdah.LoginPage` whose `Failed` field says so. Templates can show a notice;
one that ignores `Contents` is unaffected. The reasoning, which is not
cosmetic, is [docs/cookies.md §10](docs/cookies.md#10-when-a-login-fails).

### Protecting routes

Use `OIDCAuth` as an `Authenticator`. Call `RequireAuth` at the start of a
handler to ensure the user is logged in:

```go
func (c *MyComponent) handlePage(
    ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
    ctx, err := c.auth.RequireAuth(ctx, w, r)
    if err != nil {
        return nil, err
    }

    // ctx now carries the OAuth2 token and verified access token
    accessToken, ok := howdah.AccessToken(ctx)
    // ...
}
```

`RequireAuth` redirects unauthenticated users to the login page and
refreshes expired tokens automatically. A session cookie it cannot use —
unsealed, sealed under a key that is gone, tampered with, or past the
maximum session age — is cleared on the way out, so the browser stops
sending it. On success it adds an
`Authorization: Bearer` header to the context (for forwarding to backend
services via Twirp) and stores the verified access token, retrievable with
`howdah.AccessToken(ctx)`.

## Cookies and session keys

The session cookie and the post-login redirect cookie (`auth_redir`) are
sealed with AES-256-GCM under a keyring that can be rotated without logging
anyone out. `state` and `nonce` are left in the clear on purpose.

Every cookie howdah sets carries the same attributes and nothing configures
them per cookie: `HttpOnly`, `SameSite=Lax` (not `Strict` — that would break
every login), `Secure` unconditionally, a `Path` inside the mount point, and
no `Domain`, so every cookie is host-only. `howdah.WithInsecureCookies()` is
the one opt-out, for a plain-http local run:

```go
auth, err := howdah.NewOIDCAuth(provider, verifier, oauth2Config, keyring,
    howdah.WithInsecureCookies(), // http://localhost only
)
```

Keys come from the environment, one per variable:

```
COOKIE_KEY_1=2026-08-01T00:00:00Z_TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IA==
COOKIE_KEY_2=2026-09-15T00:00:00Z_aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXIgcGE=
```

The value is an RFC 3339 `use after` and the standard base64 of exactly 32
bytes. Of the keys whose `use after` has passed, the one with the latest seals;
every configured key opens. `howdah.GenerateCookieKey` produces a secret, and
elephant-deploy's `tools cookie-keys` manages the hosted ones.

**[docs/cookies.md](docs/cookies.md) is the authority on all of this** — the
envelope format and why the AAD carries the cookie name, what fits in a
cookie, the key selection rules and the startup errors that enforce them, what
every failure to open a cookie means and which one is worth alerting on, what
ends a session, what happens when a login fails, and the rollover runbook.

## Mounting under a path prefix

An application can be mounted under a path prefix on a shared server mux
with `http.StripPrefix`. Since the application only ever sees stripped
paths, anything that emits URLs for the browser (redirects, cookie paths,
menu items, template links) needs to know the prefix. `BasePath` carries
it:

```go
base := howdah.NewBasePath("/admin")

auth, err := howdah.NewOIDCAuth(provider, verifier, oauth2Config, keyring,
    howdah.WithBasePath(base),
    // Required when multiple applications share a host, otherwise
    // their sessions overwrite each other — and the cookie name is what
    // binds a sealed value to this application, so two applications can
    // share a keyring without being able to open each other's sessions.
    howdah.WithSessionCookieName("admin_token"),
)
if err != nil {
    return fmt.Errorf("set up authentication: %w", err)
}

appMux := http.NewServeMux()
serverMux.Handle("/admin/", http.StripPrefix("/admin", appMux))

app, err := howdah.NewApplication(logger, appMux, templates, locales, assets,
    []howdah.Component{
        base, // exposes {{base_path}} to templates
        auth,
        // ...
    },
)
```

With `WithBasePath` set, the OIDC login/logout redirects, the callback
cookies, and the logout menu item all resolve against the mount point.
Remember that the OAuth2 config's redirect URL must point at the prefixed
callback (`https://example.com/admin/auth/callback`), and that the
provider must allow it.

In templates, prefix any absolute link or asset URL with `{{base_path}}`:

```html
<link rel="stylesheet" href="{{base_path}}/assets/css/style.css" />
<a href="{{base_path}}/things/">Things</a>
```

In component code, build links with `BasePath.Path`:

```go
hooks.RegisterHook(func() []howdah.MenuItem {
    return []howdah.MenuItem{
        {Title: howdah.TL("Things"), HREF: base.Path("/things/"), Weight: 10},
    }
})
```

Applications mounted at the server root use the zero value `BasePath("")`,
which leaves all paths unchanged — registering it keeps templates portable
between prefixed and root-mounted applications.

## Error handling

Handlers return errors that get rendered as error pages. Use `HTTPError` types
to control the HTTP status code and user-facing message:

```go
// Wrap an error with a status code and translatable message
howdah.NewHTTPError(http.StatusNotFound, "NotFound", "Page not found", err)

// Format-style with a TextLabel message
howdah.HTTPErrorf(http.StatusBadRequest, howdah.TL("InvalidInput", "Invalid input"),
    "parse form: %w", err)

// Use the raw error message as the user-facing text
howdah.LiteralHTTPError(http.StatusForbidden, err)

// Shorthand for 500 Internal Server Error
howdah.InternalHTTPError(err)
```

Untyped errors are automatically wrapped as 500 Internal Server Error.

## Document forms (`docform` subpackage)

The `docform` package provides a framework for building forms that read from
and write to `newsdoc.Document` structures. It is useful when building UIs
that edit structured document metadata.

A `docform.Component` handles a specific block type:

```go
type Component interface {
    Name() string
    TemplateName() string
    Target() BlockTarget           // TargetMeta or TargetLinks
    Matcher() newsdoc.BlockMatcher
    Extract(blocks []newsdoc.Block) any
    Validate(values url.Values) []FieldError
    Apply(original []newsdoc.Block, values url.Values) []newsdoc.Block
}
```

Compose components into a `Form`:

```go
form := docform.New(titleComponent, authorComponent)

// Extract template data from a document
blocks := form.ExtractAll(doc)

// Validate submitted form values
if errs := form.ValidateAll(formValues); errs != nil {
    // handle validation errors
}

// Apply form values back to the document
doc = form.ApplyAll(doc, formValues)
```

Form fields are namespaced by component name. A field `title.value` in the
HTML form maps to `value` in the title component's `Validate` and `Apply`
methods. `ParseValues` handles the prefix stripping.

## Status

This library is **unstable and experimental**. The API may change without
notice.
