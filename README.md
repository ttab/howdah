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
every other cookie howdah sets (see [Cookie
attributes](#cookie-attributes)). Its optional `redirect` parameter must be
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

A session lives for `howdah.DefaultMaxSessionAge` from the login, counted
against an `issued_at` sealed into the cookie rather than against the
cookie's `Expires`, which is only ever a request to the browser. Refreshing
the access token does not extend it — a session ends and the user logs in
again. Use `howdah.WithMaxSessionAge` to change it, bearing in mind that the
maximum session age is also how long a copied cookie value keeps working and
how long a retired cookie key has to stay in the keyring.

Access tokens are refreshed as they near expiry, and the concurrent
refreshes of one session collapse onto a single round trip to the provider,
so the several requests of one page load do not each post the same refresh
token. The deduplication is per process and does not reach across replicas —
the tokens live in the cookie, so there is nothing for two replicas to
coordinate through.

Two fields RFC 6749 leaves optional are decided where a token enters the
session rather than in the request path. A refresh response without a
`refresh_token` means "keep using the one you have", so the session's own is
carried forward; one without an `expires_in` leaves the access token's
lifetime unknown, so it is assumed to be five minutes and a warning says so.
Keycloak sends both, so the warning showing up in the log means the provider
changed.

### Routes registered

| Route | Purpose |
|---|---|
| `GET /auth/login` | Renders the login page |
| `POST /auth/login` | Redirects to the OIDC provider |
| `GET /auth/callback` | Handles the OIDC callback |
| `GET /auth/logout` | Clears the session and redirects to the application root |

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
each other's sessions — see [`WithSessionCookieName`](#mounting-under-a-path-prefix).
The cookie name is part of that binding, which is why it has to be an HTTP
token: no separators, and no colon in particular.

### Cookie attributes

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

### The keyring environment format

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

### Generating a key

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

### Which key seals, which keys open

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

### When a cookie cannot be opened

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

### Rolling a key over

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
