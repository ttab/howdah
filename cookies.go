package howdah

import "net/http"

// setCookie writes a cookie with the attributes every cookie howdah sets
// carries. A caller decides a cookie's name, value, path and lifetime and
// nothing else, so that a cookie added later cannot quietly arrive without
// them, and so the golden test in cookies_test.go has one place to hold the
// line.
//
// SameSite is Lax, and deliberately not Strict. The OIDC callback is a
// cross-site top-level navigation from the identity provider, so Strict
// would have the browser withhold the state and nonce cookies on exactly
// the request that has to compare them against what the provider echoed
// back — which is to say it would break every login. Lax still covers what
// SameSite is here for: a request another site makes for a resource of
// ours. Please don't "tighten" this.
//
// Secure is unconditional, and in particular is not derived from the
// connection the request arrived on. These applications sit behind a
// TLS-terminating ingress, where the connection howdah sees is plain http,
// so a Secure flag taken from r.TLS is off in exactly the deployment that
// needs it on — and the session cookie is then sent in the clear to any
// http:// URL on our own host name. WithInsecureCookies is the opt-out, for
// a plain-http local development run. Trusting X-Forwarded-Proto instead
// would work, but it answers a question that does not need asking.
//
// Domain is never set, which makes every cookie host-only. That has always
// been true of howdah; it is now pinned by a test rather than left an
// accident.
func setCookie(w http.ResponseWriter, c *http.Cookie, insecure bool) {
	c.HttpOnly = true
	c.SameSite = http.SameSiteLaxMode
	c.Secure = !insecure

	http.SetCookie(w, c)
}

// cookieSecurity is implemented by components that carry a cookie security
// posture, which in practice means OIDCAuth: WithInsecureCookies is the one
// place it is configured. The application picks it up from its components
// so that its own language cookie agrees with the session cookie — a
// development run that hands out one Secure cookie and one insecure one is
// more confusing than either.
type cookieSecurity interface {
	insecureCookies() bool
}
