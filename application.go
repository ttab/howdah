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
}

func (a *Application) Cleanup() {}

func (a *Application) GetMenu() []MenuItem {
	return []MenuItem{}
}

func (a *Application) setLanguage(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	query := r.URL.Query()

	var (
		lang     = query.Get("lang")
		redirect = query.Get("redirect")
	)

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

	w.Header().Add("Location", redirect)
	w.WriteHeader(http.StatusTemporaryRedirect)

	return nil, ErrSkipRender
}
