package howdah

import "testing"

func TestNewBasePath(t *testing.T) {
	cases := map[string]BasePath{
		"":        "",
		"/":       "",
		"//":      "",
		"admin":   "/admin",
		"/admin":  "/admin",
		"/admin/": "/admin",
		"/a/b/":   "/a/b",
	}

	for prefix, want := range cases {
		got := NewBasePath(prefix)
		if got != want {
			t.Errorf("NewBasePath(%q) = %q, want %q", prefix, got, want)
		}
	}
}

func TestBasePathPath(t *testing.T) {
	root := NewBasePath("")

	if got := root.Path("/things/"); got != "/things/" {
		t.Errorf("root Path(\"/things/\") = %q, want \"/things/\"", got)
	}

	admin := NewBasePath("/admin")

	if got := admin.Path("/"); got != "/admin/" {
		t.Errorf("admin Path(\"/\") = %q, want \"/admin/\"", got)
	}

	if got := admin.Path("/things/?a=b"); got != "/admin/things/?a=b" {
		t.Errorf("admin Path(\"/things/?a=b\") = %q, want \"/admin/things/?a=b\"",
			got)
	}
}

func TestSafeRedirectPath(t *testing.T) {
	safe := []string{"/", "/things/", "/things/?a=b&c=/d"}
	unsafe := []string{
		"",
		"things/",
		"//evil.example.com/",
		"/\\evil.example.com/",
		"https://evil.example.com/",
	}

	for _, p := range safe {
		if !safeRedirectPath(p) {
			t.Errorf("safeRedirectPath(%q) = false, want true", p)
		}
	}

	for _, p := range unsafe {
		if safeRedirectPath(p) {
			t.Errorf("safeRedirectPath(%q) = true, want false", p)
		}
	}
}
