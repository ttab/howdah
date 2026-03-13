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
`/set-language` endpoint sets the cookie.

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

```go
auth := howdah.NewOIDCAuth(provider, verifier, oauth2Config)
```

### Routes registered

| Route | Purpose |
|---|---|
| `GET /auth/login` | Renders the login page |
| `POST /auth/login` | Redirects to the OIDC provider |
| `GET /auth/callback` | Handles the OIDC callback |
| `GET /auth/logout` | Clears the session and redirects to `/` |

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
refreshes expired tokens automatically. On success it adds an
`Authorization: Bearer` header to the context (for forwarding to backend
services via Twirp) and stores the verified access token, retrievable with
`howdah.AccessToken(ctx)`.

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
