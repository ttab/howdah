package howdah

import (
	"errors"
	"fmt"
	"net/http"
)

func NewHTTPError(code int, msgID string, text string, cause error) error {
	return &HTTPError{
		msg:     cause.Error(),
		cause:   cause,
		Code:    code,
		Message: TL(msgID, text),
	}
}

func InternalHTTPError(cause error) error {
	return NewHTTPError(http.StatusInternalServerError,
		"UnexpectedError", "Encountered an unexpected error", cause)
}

func HTTPErrorf(code int, message TextLabel, format string, a ...any) error {
	we := fmt.Errorf(format, a...)

	return &HTTPError{
		msg:     we.Error(),
		cause:   errors.Unwrap(we),
		Code:    code,
		Message: message,
	}
}

func AsHTTPError(err error) *HTTPError {
	var h *HTTPError

	if errors.As(err, &h) {
		return h
	}

	return InternalHTTPError(err).(*HTTPError) //nolint: errorlint
}

func LiteralHTTPError(code int, err error) error {
	return &HTTPError{
		msg:   err.Error(),
		cause: err,
		Code:  code,
		Message: TextLabel{
			Literal: err.Error(),
		},
	}
}

type HTTPError struct {
	msg   string
	cause error

	Code    int
	Message TextLabel
}

// Error implements error.
func (h *HTTPError) Error() string {
	return h.msg
}

func (h *HTTPError) Unwrap() error {
	return h.cause
}

type HTTPHandlerFuncWithErr func(w http.ResponseWriter, r *http.Request) error

func (fn HTTPHandlerFuncWithErr) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return fn(w, r)
}

type HTTPHandlerWithErr interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request) error
}
