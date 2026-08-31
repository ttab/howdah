package howdah

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

type MenuHook interface {
	MenuHook(hooks *MenuHooks)
}

type Component interface {
	RegisterRoutes(mux *PageMux)
}

type ComponentObserver interface {
	ObserveComponent(c Component)
}

type TeplateFuncSource interface {
	GetTemplateFuncs() template.FuncMap
}

type Authenticator interface {
	RequireAuth(
		ctx context.Context, w http.ResponseWriter, r *http.Request,
	) (context.Context, error)
}

func NewApplication(
	logger *slog.Logger,
	httpMux *http.ServeMux,
	templates fs.FS,
	locales fs.FS,
	assets fs.FS,
	components []Component,
) (*Application, error) {
	bundle := i18n.NewBundle(language.English)

	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	ld, err := fs.ReadDir(locales, ".")
	if err != nil {
		return nil, fmt.Errorf("list locales: %w", err)
	}

	for _, f := range ld {
		name := f.Name()

		if f.IsDir() || !strings.HasPrefix(name, "locale.") {
			continue
		}

		_, err := bundle.LoadMessageFileFS(locales, name)
		if err != nil {
			return nil, fmt.Errorf("load locale %q: %w", name, err)
		}
	}

	renderer, err := NewPageRenderer(logger, templates, bundle, components)
	if err != nil {
		return nil, fmt.Errorf("create page renderer: %w", err)
	}

	a := Application{
		log:        logger,
		render:     renderer,
		mux:        httpMux,
		components: components,
	}

	// The set-language redirect has to resolve against the application's
	// mount point, and page_url gives templates the request URL as the
	// handler sees it, which http.StripPrefix has already trimmed.
	//
	// The cookie security posture is picked up the same way, from
	// whichever component carries one — OIDCAuth, in practice — so the
	// language cookie is written with the same attributes as the session
	// cookie. Without a component saying otherwise the cookies are
	// Secure, which is the answer for every deployment that is not a
	// plain-http development run.
	for _, c := range components {
		if bp, ok := c.(BasePath); ok {
			a.basePath = bp
		}

		if cs, ok := c.(cookieSecurity); ok {
			a.insecureCookies = cs.insecureCookies()
		}
	}

	mux := NewPageMux(renderer, httpMux)

	mux.HandleFunc("GET /set-language", a.setLanguage)

	fs := http.FileServerFS(assets)

	httpMux.Handle("GET /assets/", http.StripPrefix("/assets/", fs))

	for _, c := range components {
		c.RegisterRoutes(mux)

		o, ok := c.(ComponentObserver)
		if !ok {
			continue
		}

		for _, oc := range components {
			o.ObserveComponent(oc)
		}
	}

	return &a, nil
}

type Application struct {
	log             *slog.Logger
	render          *PageRenderer
	mux             *http.ServeMux
	components      []Component
	basePath        BasePath
	insecureCookies bool
}

func (a *Application) Cleanup() {}

func (a *Application) GetMenu() []MenuItem {
	return []MenuItem{}
}

func (a *Application) setLanguage(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	query := r.URL.Query()

	lang := query.Get("lang")

	// The language cookie goes out through setCookie like every other
	// cookie howdah sets, which is where it gets the HttpOnly, SameSite
	// and Secure attributes it used to be missing entirely. The explicit
	// Path is tidiness rather than a fix: this endpoint is only reached at
	// the application root, so RFC 6265's default path already resolves to
	// the mount point.
	c := http.Cookie{
		Name:    "lang",
		Value:   lang,
		Expires: time.Now().AddDate(1, 0, 0),
		Path:    a.basePath.Path("/"),
	}

	if lang == "" {
		// No language asked for means going back to the default, which
		// is done by handing the browser a cookie that has already
		// expired.
		c.Value = "en"
		c.Expires = time.Now().AddDate(-1, 0, 0)
	}

	setCookie(w, &c, a.insecureCookies)

	http.Redirect(w, r,
		resolveRedirect(a.basePath, query.Get("redirect")),
		http.StatusTemporaryRedirect)

	return nil, ErrSkipRender
}

// resolveRedirect resolves a client-supplied redirect target against the
// application's mount point. Both places howdah redirects somewhere it was
// told to go through here — the set-language endpoint and the post-login
// callback — so that tightening the rule reaches both.
//
// The target goes straight into a Location header, so anything a browser
// would resolve against another origin has to be refused: without the check
// "/set-language?lang=sv&redirect=https://evil.example" makes our own origin
// hand visitors to someone else's. A rejected value falls back to the
// application root rather than failing the request — the visitor asked to
// change language or to log in, not to navigate, and there is nothing useful
// to tell them about a link they did not write.
func resolveRedirect(bp BasePath, target string) string {
	if !safeRedirectPath(target) {
		return bp.Path("/")
	}

	return bp.Path(target)
}
