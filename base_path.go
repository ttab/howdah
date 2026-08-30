package howdah

import (
	"html/template"
	"strings"
)

// BasePath represents the mount point of an application that is served
// under a path prefix, e.g. `http.StripPrefix("/admin", appMux)`. It is a
// component that exposes the prefix to templates through a {{base_path}}
// function, and a helper for building prefixed URLs in code.
//
// Register it as a component in the application, and share the same value
// with NewOIDCAuth through WithBasePath so that auth redirects and cookies
// resolve against the mount point. An application mounted at the server
// root uses the empty base path.
type BasePath string

// NewBasePath normalises prefix into a BasePath: a root mount ("" or "/")
// becomes the empty base path, any other prefix gets a leading slash and
// no trailing slash.
func NewBasePath(prefix string) BasePath {
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}

	return BasePath("/" + prefix)
}

// Path resolves an application-relative path (starting with "/") against
// the base path.
func (bp BasePath) Path(rel string) string {
	return string(bp) + rel
}

// RegisterRoutes implements Component. BasePath registers no routes.
func (bp BasePath) RegisterRoutes(_ *PageMux) {
}

// GetTemplateFuncs provides the {{base_path}} template function.
func (bp BasePath) GetTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"base_path": func() string {
			return string(bp)
		},
	}
}
