package howdah

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type MenuItem struct {
	Title  TextLabel
	Active bool
	HREF   string
	Weight int
}

type Page struct {
	Status     int
	Template   string
	Title      TextLabel
	Menu       []MenuItem
	Breadcrumb []Link
	Contents   any
}

type PageRenderer struct {
	log           *slog.Logger
	translations  *i18n.Bundle
	templateFuncs template.FuncMap
	tpl           *template.Template
	components    []Component

	menu      []MenuItem
	menuHooks *MenuHooks
}

func NewPageRenderer(
	logger *slog.Logger,
	tplFs fs.FS, translations *i18n.Bundle,
	components []Component,
) (*PageRenderer, error) {
	defaultLoc := i18n.NewLocalizer(translations, "en")

	funcs := template.FuncMap{
		"t":  tFunc(defaultLoc),
		"td": tdFunc(defaultLoc),
		"tl": tlFunc(defaultLoc),
		"lang": func() string {
			return "en"
		},
		"ctx": context.Background,
		"page_url": func() *url.URL {
			return nil
		},
	}

	for _, c := range components {
		s, ok := c.(TeplateFuncSource)
		if !ok {
			continue
		}

		maps.Copy(funcs, s.GetTemplateFuncs())
	}

	var menuHooks MenuHooks

	for _, c := range components {
		h, ok := c.(MenuHook)
		if !ok {
			continue
		}

		h.MenuHook(&menuHooks)
	}

	pr := PageRenderer{
		log:           logger,
		translations:  translations,
		templateFuncs: funcs,
		components:    components,
		menuHooks:     &menuHooks,
		menu:          menuHooks.Collect(),
	}

	tpl := template.New("templates")

	tpl.Funcs(pr.templateFuncs)

	tpl, err := tpl.ParseFS(tplFs, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	pr.tpl = tpl

	return &pr, nil
}

func (pr *PageRenderer) Localizer(r *http.Request) (string, *i18n.Localizer) {
	// TODO: Move language resolve to middleware
	accept := r.Header.Get("Accept-Language")
	langSetting := "en"

	lc, err := r.Cookie("lang")
	if err == nil && lc.Value != "" {
		langSetting = lc.Value
	}

	return langSetting, i18n.NewLocalizer(pr.translations, langSetting, accept)
}

func (pr *PageRenderer) localeTemplate(
	ctx context.Context,
	r *http.Request,
) *template.Template {
	lang, localizer := pr.Localizer(r)

	tpl, err := pr.tpl.Clone()
	if err != nil {
		panic(fmt.Errorf("clone base templates: %w", err))
	}

	tfn := maps.Clone(pr.templateFuncs)

	tfn["ctx"] = func() context.Context {
		return ctx
	}

	tfn["t"] = tFunc(localizer)
	tfn["tl"] = tlFunc(localizer)
	tfn["td"] = tdFunc(localizer)
	tfn["lang"] = func() string {
		return lang
	}
	tfn["page_url"] = func() *url.URL {
		return r.URL
	}

	tpl.Funcs(tfn)

	return tpl
}

type ErrorInfo struct {
	Code    int
	Message TextLabel
	Error   error
}

func (pr *PageRenderer) ErrorPage(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	info ErrorInfo,
) {
	tpl := pr.localeTemplate(ctx, r)

	code := info.Code
	if code == 0 {
		code = http.StatusInternalServerError
	}

	w.WriteHeader(code)

	p := Page{
		Title: TMsg(i18n.Message{
			ID:    "ErrorEncountered",
			Other: "Encountered an error",
		}),
		Contents: info,
	}

	err := tpl.ExecuteTemplate(w, "error.html", p)
	if err != nil {
		pr.log.ErrorContext(ctx, "execute error page template",
			"err", err,
			"original_error", info.Error.Error(),
		)

		return
	}
}

func PT(loc *i18n.Localizer, msg *i18n.Message) string {
	txt, err := loc.LocalizeMessage(msg)
	if err != nil {
		return fmt.Sprintf("[%s]", msg.ID)
	}

	return txt
}

func (pr *PageRenderer) RenderPage(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	p *Page,
) {
	tpl := pr.localeTemplate(ctx, r)

	menu := slices.Clone(pr.menu)

	menu = append(menu, p.Menu...)

	SortMenuItems(menu)

	menu = pr.menuHooks.Alter(ctx, AlterContext[Page]{
		Request: r,
		Data:    *p,
	}, menu)

	check := []string{r.URL.Path}

	if len(p.Breadcrumb) > 0 {
		check = append(check, p.Breadcrumb[0].HREF)
	}

	// Set menu active status
	for i := range menu {
		menu[i].Active = slices.Contains(check, menu[i].HREF)
	}

	p.Menu = menu

	var buf bytes.Buffer

	err := tpl.ExecuteTemplate(&buf, p.Template, p)
	if err != nil {
		pr.log.ErrorContext(ctx, "execute page template",
			"err", err,
		)

		pr.ErrorPage(ctx, w, r, ErrorInfo{
			Error:   err,
			Message: TL("PageRenderFailed", "Failed to render page template"),
		})

		return
	}

	status := p.Status
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(status)

	_, _ = w.Write(buf.Bytes())
}

func tFunc(loc *i18n.Localizer) func(str string, forms ...string) string {
	return func(str string, forms ...string) string {
		msg := i18n.Message{
			ID: str,
		}

		switch len(forms) {
		case 0:
			msg.Other = str
		case 1:
			msg.Other = forms[0]
		}

		txt, err := loc.LocalizeMessage(&msg)
		if err != nil {
			return fmt.Sprintf("[%s]", msg.ID)
		}

		return txt
	}
}

func tlFunc(loc *i18n.Localizer) func(lbl TextLabel) string {
	return func(lbl TextLabel) string {
		if lbl.Message == nil {
			return lbl.Literal
		}

		conf := i18n.LocalizeConfig{
			DefaultMessage: lbl.Message,
			TemplateData:   lbl.Values,
		}

		if lbl.PluralCount != nil {
			conf.PluralCount = *lbl.PluralCount
		}

		txt, err := loc.Localize(&conf)
		if err != nil {
			return fmt.Sprintf("[%s]", lbl.Message.ID)
		}

		return txt
	}
}

func tdFunc(loc *i18n.Localizer) func(id string, text string, data any) string {
	return func(id string, text string, data any) string {
		msg := i18n.Message{
			ID:    id,
			Other: text,
		}

		conf := i18n.LocalizeConfig{
			DefaultMessage: &msg,
			TemplateData:   data,
		}

		txt, err := loc.Localize(&conf)
		if err != nil {
			return fmt.Sprintf("[%s]", msg.ID)
		}

		return txt
	}
}
