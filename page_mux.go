package howdah

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

func (pm *PageMux) Handle(pattern string, handler PageHandler) {
	pm.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		p, err := handler.ServePage(ctx, w, r)
		if err != nil {
			if errors.Is(err, ErrSkipRender) {
				return
			}

			herr := AsHTTPError(err)

			if pm.r == nil {
				http.Error(w,
					fmt.Sprintf("no page renderer: %v", err),
					herr.Code)

				return
			}

			pm.r.ErrorPage(r.Context(), w, r,
				ErrorInfo{
					Code:    herr.Code,
					Error:   err,
					Message: herr.Message,
				})

			return
		}

		if pm.r == nil {
			http.Error(w, "no page renderer", http.StatusInternalServerError)

			return
		}

		pm.r.RenderPage(ctx, w, r, p)
	})
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
