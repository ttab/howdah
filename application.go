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
	for _, c := range components {
		if bp, ok := c.(BasePath); ok {
			a.basePath = bp
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
	log        *slog.Logger
	render     *PageRenderer
	mux        *http.ServeMux
	components []Component
	basePath   BasePath
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

	if lang == "" {
		http.SetCookie(w, &http.Cookie{
			Name:    "lang",
			Value:   "en",
			Expires: time.Now().AddDate(-1, 0, 0),
		})
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:    "lang",
			Value:   lang,
			Expires: time.Now().AddDate(1, 0, 0),
		})
	}

	http.Redirect(w, r,
		languageRedirect(a.basePath, query.Get("redirect")),
		http.StatusTemporaryRedirect)

	return nil, ErrSkipRender
}

// languageRedirect resolves the redirect parameter of the set-language
// endpoint against the application's mount point.
//
// The parameter is client-supplied and goes straight into a Location header,
// so anything a browser would resolve against another origin has to be
// refused: without the check
// "/set-language?lang=sv&redirect=https://evil.example" makes our own origin
// hand visitors to someone else's. A rejected value falls back to the
// application root rather than failing the request — the visitor asked to
// change language, not to navigate, and there is nothing useful to tell them
// about a link they did not write.
func languageRedirect(bp BasePath, target string) string {
	if !safeRedirectPath(target) {
		return bp.Path("/")
	}

	return bp.Path(target)
}
