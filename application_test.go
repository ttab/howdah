package howdah

import "testing"

func TestLanguageRedirect(t *testing.T) {
	cases := []struct {
		name   string
		base   BasePath
		target string
		want   string
	}{
		{"empty falls back to root", "", "", "/"},
		{"relative path is kept", "", "/reports", "/reports"},
		{"query string is kept", "", "/reports?month=2026-08", "/reports?month=2026-08"},
		{"absolute URL is refused", "", "https://evil.example", "/"},
		{"scheme relative URL is refused", "", "//evil.example", "/"},
		{"backslash form is refused", "", "/\\evil.example", "/"},
		{"protocol relative with path is refused", "", "//evil.example/x", "/"},
		{"bare word is refused", "", "evil.example", "/"},

		{"mounted root", "/admin", "", "/admin/"},
		{"mounted path", "/admin", "/reports", "/admin/reports"},
		{"mounted query", "/admin", "/reports?a=b", "/admin/reports?a=b"},
		{"mounted refusal stays in the mount", "/admin", "https://evil.example", "/admin/"},
		{"mounted scheme relative refusal", "/admin", "//evil.example", "/admin/"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := languageRedirect(c.base, c.target)
			if got != c.want {
				t.Errorf("languageRedirect(%q, %q) = %q, want %q",
					c.base, c.target, got, c.want)
			}
		})
	}
}
