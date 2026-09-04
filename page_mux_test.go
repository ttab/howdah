package howdah

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// pageMuxTestComponent registers the routes the PageMux tests drive: a page
// that renders, a page that writes its own response, and both on more than
// one method so the method rule can be exercised.
type pageMuxTestComponent struct{}

func (pageMuxTestComponent) RegisterRoutes(mux *PageMux) {
	page := func(
		_ context.Context, _ http.ResponseWriter, _ *http.Request,
	) (*Page, error) {
		return &Page{Template: "page.html"}, nil
	}

	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch,
	} {
		mux.HandleFunc(method+" /thing", page)
	}

	mux.HandleFunc("POST /redirect", func(
		_ context.Context, w http.ResponseWriter, r *http.Request,
	) (*Page, error) {
		http.Redirect(w, r, "/thing", http.StatusFound)

		return nil, ErrSkipRender
	})
}

// newPageMuxTestApplication builds a real application, so the tests go
// through NewApplication, the PageMux and a renderer rather than around
// them. The mux also carries a handler mounted directly on it, which is
// what a consumer does with an embeddable widget or an API endpoint.
func newPageMuxTestApplication(t *testing.T) http.Handler {
	t.Helper()

	mux := http.NewServeMux()

	_, err := NewApplication(
		slog.New(slog.DiscardHandler),
		mux,
		fstest.MapFS{
			"page.html": &fstest.MapFile{
				Data: []byte("page"),
			},
			"error.html": &fstest.MapFile{
				Data: []byte("error {{.Contents.Code}}"),
			},
		},
		fstest.MapFS{},
		fstest.MapFS{},
		[]Component{pageMuxTestComponent{}},
	)
	if err != nil {
		t.Fatalf("create application: %v", err)
	}

	mux.HandleFunc("POST /direct", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("direct"))
	})

	return mux
}

// TestPageMuxRefusesCrossSiteWrites holds the line on the same-site CSRF
// that SameSite=Lax leaves open: a sibling application on our own
// registrable domain is same-site, so the browser attaches the session
// cookie to a form it posts at us.
func TestPageMuxRefusesCrossSiteWrites(t *testing.T) {
	cases := []struct {
		name   string
		method string
		fetch  string
		origin string
		want   int
	}{
		{
			name: "our own page posting to us", method: http.MethodPost,
			fetch: "same-origin", want: http.StatusOK,
		},
		{
			name: "the visitor themselves", method: http.MethodPost,
			fetch: "none", want: http.StatusOK,
		},
		{
			name: "a sibling application", method: http.MethodPost,
			fetch: "same-site", want: http.StatusForbidden,
		},
		{
			name: "another site entirely", method: http.MethodPost,
			fetch: "cross-site", want: http.StatusForbidden,
		},
		{
			name:   "the header wins over a forged Origin",
			method: http.MethodPost, fetch: "cross-site",
			origin: "https://example.com",
			want:   http.StatusForbidden,
		},
		{
			name:   "no headers at all is not a browser",
			method: http.MethodPost, want: http.StatusOK,
		},
		{
			name: "Origin matching the host", method: http.MethodPost,
			origin: "https://example.com", want: http.StatusOK,
		},
		{
			name: "Origin on another host", method: http.MethodPost,
			origin: "https://evil.example", want: http.StatusForbidden,
		},
		{
			name: "an opaque Origin", method: http.MethodPost,
			origin: "null", want: http.StatusForbidden,
		},
		{
			name: "Origin on another port", method: http.MethodPost,
			origin: "https://example.com:8443",
			want:   http.StatusForbidden,
		},
		{
			name: "PUT is guarded too", method: http.MethodPut,
			fetch: "cross-site", want: http.StatusForbidden,
		},
		{
			name: "DELETE is guarded too", method: http.MethodDelete,
			fetch: "cross-site", want: http.StatusForbidden,
		},
		{
			name: "PATCH is guarded too", method: http.MethodPatch,
			fetch: "cross-site", want: http.StatusForbidden,
		},
		{
			name:   "a cross-site GET is a link, not a write",
			method: http.MethodGet, fetch: "cross-site",
			want: http.StatusOK,
		},
		{
			name:   "a cross-site HEAD changes nothing",
			method: http.MethodHead, fetch: "cross-site",
			want: http.StatusOK,
		},
	}

	app := newPageMuxTestApplication(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/thing", nil)

			if c.fetch != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetch)
			}

			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}

			w := httptest.NewRecorder()

			app.ServeHTTP(w, r)

			if w.Code != c.want {
				t.Errorf("got status %d, want %d: %s",
					w.Code, c.want, w.Body.String())
			}
		})
	}
}

// TestPageMuxKeepsTheLoginFlowWorking covers the two routes the site check
// could plausibly break: the login page's own form posts to
// POST /auth/login, and the provider sends the visitor back to
// GET /auth/callback as a cross-site top-level navigation.
func TestPageMuxKeepsTheLoginFlowWorking(t *testing.T) {
	app := newTestApplication(t, newTestAuth(t), "")

	cases := []struct {
		name   string
		method string
		path   string
		fetch  string
		want   int
	}{
		{
			name: "the login form", method: http.MethodPost,
			path: "/auth/login", fetch: "same-origin",
			want: http.StatusFound,
		},
		{
			name: "a bookmarked login", method: http.MethodPost,
			path: "/auth/login", fetch: "none",
			want: http.StatusFound,
		},
		{
			name:   "a sibling application posting a login",
			method: http.MethodPost, path: "/auth/login",
			fetch: "same-site", want: http.StatusForbidden,
		},
		{
			// No state cookie, so the callback gives up and sends
			// the visitor back to the login page. What matters is
			// that it was not refused before it got that far.
			name: "the provider's callback", method: http.MethodGet,
			path:  "/auth/callback?code=x&state=y",
			fetch: "cross-site", want: http.StatusFound,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.path, nil)
			r.Header.Set("Sec-Fetch-Site", c.fetch)

			w := httptest.NewRecorder()

			app.ServeHTTP(w, r)

			if w.Code != c.want {
				t.Errorf("got status %d, want %d",
					w.Code, c.want)
			}
		})
	}
}

// TestPageMuxSetsFrameAncestors checks that every response a PageMux route
// produces refuses to be framed, and that nothing a consumer mounts on the
// underlying http.ServeMux is touched — an embeddable widget served next to
// the UI has to stay embeddable.
func TestPageMuxSetsFrameAncestors(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		fetch  string
		want   string
	}{
		{
			name: "a rendered page", method: http.MethodGet,
			path: "/thing", want: framingPolicy,
		},
		{
			name: "an error page", method: http.MethodPost,
			path: "/thing", fetch: "cross-site", want: framingPolicy,
		},
		{
			name:   "a handler that wrote its own response",
			method: http.MethodPost, path: "/redirect",
			fetch: "same-origin", want: framingPolicy,
		},
		{
			name:   "a handler mounted directly on the mux",
			method: http.MethodPost, path: "/direct", want: "",
		},
		{
			name: "the asset server", method: http.MethodGet,
			path: "/assets/nothing", want: "",
		},
	}

	app := newPageMuxTestApplication(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.path, nil)

			if c.fetch != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetch)
			}

			w := httptest.NewRecorder()

			app.ServeHTTP(w, r)

			got := w.Header().Get("Content-Security-Policy")
			if got != c.want {
				t.Errorf(
					"got Content-Security-Policy %q, want %q",
					got, c.want)
			}
		})
	}
}
