package howdah

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

func NewPageMux(
	r *PageRenderer,
	mux *http.ServeMux,
) *PageMux {
	return &PageMux{
		r:   r,
		mux: mux,
	}
}

type PageMux struct {
	r   *PageRenderer
	mux *http.ServeMux
}

var ErrSkipRender = errors.New("skip render")

// framingPolicy is set on every response a PageMux route produces. A
// backoffice UI is never framed by anything, and saying so is what stops a
// page of ours being loaded invisibly under someone else's cursor.
//
// frame-ancestors is the whole policy on purpose. A content policy that
// constrained scripts or styles would be howdah deciding what the
// application's templates may contain, and the first template that loads a
// font from somewhere would have to fight the framework about it. Framing is
// the one thing no application here wants, so it is the one thing the
// framework asserts.
//
// X-Frame-Options is not set alongside it. frame-ancestors supersedes it in
// every browser that has been current for years, and a second header that
// says the same thing is a second header to keep in agreement.
const framingPolicy = "frame-ancestors 'none'"

func (pm *PageMux) Handle(pattern string, handler PageHandler) {
	pm.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Set before the handler runs, so that a handler which writes
		// its own response and returns ErrSkipRender — a redirect, a
		// file download — carries the policy too, and so a handler
		// that genuinely needs a different one can overwrite the
		// header. Nothing a consumer mounts on the underlying
		// http.ServeMux passes through here, which is the point: an
		// embeddable widget served next to the UI keeps being
		// embeddable.
		w.Header().Set("Content-Security-Policy", framingPolicy)

		err := checkRequestSite(r)
		if err != nil {
			pm.renderError(ctx, w, r, err)

			return
		}

		p, err := handler.ServePage(ctx, w, r)
		if err != nil {
			if errors.Is(err, ErrSkipRender) {
				return
			}

			pm.renderError(ctx, w, r, err)

			return
		}

		if pm.r == nil {
			http.Error(w, "no page renderer", http.StatusInternalServerError)

			return
		}

		pm.r.RenderPage(ctx, w, r, p)
	})
}

func (pm *PageMux) renderError(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	err error,
) {
	herr := AsHTTPError(err)

	if pm.r == nil {
		http.Error(w,
			fmt.Sprintf("no page renderer: %v", err),
			herr.Code)

		return
	}

	pm.r.ErrorPage(ctx, w, r,
		ErrorInfo{
			Code:    herr.Code,
			Error:   err,
			Message: herr.Message,
		})
}

// checkRequestSite refuses a state-changing request that another site made
// on the visitor's behalf.
//
// SameSite=Lax on the session cookie does not close this. Lax is a
// *same-site* rule, and same-site is registrable domain plus scheme: every
// application on our own domain is same-site with every other, so a page
// served by a sibling application — or by anything else that ends up hosted
// there — can POST to this one and the browser attaches the session cookie
// in full. Lax also lets a cross-site top-level GET carry the cookie, which
// is exactly what makes the OIDC callback work and is why Lax cannot be
// tightened to Strict (see cookies.go). This check is the other half: the
// cookie decides what the browser sends, and this decides what we act on.
//
// Sec-Fetch-Site answers the question directly, because the browser sets it
// and script cannot. "same-origin" is our own page submitting to us, and
// "none" is the visitor themselves — a typed URL, a bookmark. "same-site" is
// the sibling-application case and "cross-site" is the classic one; both are
// refused.
//
// A client that sends no Sec-Fetch-Site falls back to comparing Origin
// against the Host the request was addressed to. Only the hosts are
// compared, not the schemes: these applications sit behind a TLS-terminating
// ingress, so the request arrives over plain http and the scheme howdah
// would compare against is not the one the browser used.
//
// A request with neither header is allowed through. It is not a browser
// request — every browser that can be talked into a cross-site POST either
// sets Sec-Fetch-Site or has sent Origin on a cross-origin POST for the best
// part of a decade — and refusing it would break the command-line clients
// and the health checks that legitimately post to an application without
// pretending to be anybody.
func checkRequestSite(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// The safe methods, and OPTIONS, which changes nothing. A
		// handler that mutates state behind a GET has a problem this
		// check cannot fix.
		return nil
	}

	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	case "":
		// No opinion from the browser, so fall through to Origin.
	default:
		return crossSiteError(r)
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}

	// "null" and anything else that is not a parseable origin gives an
	// empty host, which never equals a Host we were reached at.
	u, err := url.Parse(origin)
	if err != nil || u.Host != r.Host {
		return crossSiteError(r)
	}

	return nil
}

func crossSiteError(r *http.Request) error {
	return NewHTTPError(http.StatusForbidden,
		"CrossSiteRequestBlocked",
		"This request did not come from this site, please try again",
		fmt.Errorf(
			"cross-site %s request refused: Sec-Fetch-Site %q, Origin %q",
			r.Method,
			r.Header.Get("Sec-Fetch-Site"),
			r.Header.Get("Origin")))
}

func (pm *PageMux) HandleFunc(pattern string, handler PageHandlerFunc) {
	pm.Handle(pattern, handler)
}

type PageHandler interface {
	ServePage(
		ctx context.Context, w http.ResponseWriter, r *http.Request,
	) (*Page, error)
}

type PageHandlerFunc func(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error)

func (fn PageHandlerFunc) ServePage(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	return fn(ctx, w, r)
}
