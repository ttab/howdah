package howdah

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/twitchtv/twirp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

type OIDCUserInfoSource interface {
	OIDCUserInfo(ctx context.Context) (*oidc.UserInfo, error)
}

// LoginCallback is called after a successful OIDC callback and token
// verification, before the session cookie is set. The IDToken is the verified
// ID token from the provider — use Claims() to extract custom claims. Return
// an error to abort the login.
type LoginCallback func(ctx context.Context, idToken *oidc.IDToken) error

// DefaultMaxSessionAge is how long a session lives before the user has to
// log in again. It is counted from the login and not from the last request,
// so refreshing the access token does not extend it: a working day, and
// then a new login.
const DefaultMaxSessionAge = 12 * time.Hour

const (
	// tokenRefreshMargin is how little life an access token may have left
	// before a request refreshes it.
	tokenRefreshMargin = 10 * time.Second

	// tokenRefreshTimeout bounds the token endpoint round trip. The
	// exchange runs detached from the request, so this is the only thing
	// that stops it.
	tokenRefreshTimeout = 10 * time.Second

	// assumedAccessTokenLifetime is how long an access token is taken to
	// last when the provider does not say. RFC 6749 §5.1 makes expires_in
	// optional, and an oauth2.Token that arrives without one carries the
	// zero Expiry — which the arithmetic in checkTokenExpiry reads as an
	// access token that expired an eternity ago, so every single request
	// would refresh and rewrite the session cookie. Reading it as "never
	// expires" instead, the way oauth2.Token's own Valid does, is no
	// better: the access token does expire, and we would keep handing the
	// dead one to upstream services until the session age cap ran out.
	// So it is guessed, conservatively, and only where a token enters the
	// session — see assumeTokenExpiry.
	assumedAccessTokenLifetime = 5 * time.Minute
)

// authRedirCookieName holds the path to send the user to once the login
// completes. Its value is sealed: unlike state and nonce it is a path the
// application acts on, and nothing in the flow would notice it being
// rewritten.
const authRedirCookieName = "auth_redir"

// OIDCAuthOption configures an OIDCAuth instance.
type OIDCAuthOption func(*OIDCAuth)

// WithOnLogin registers a callback that is invoked after a successful OIDC
// login. This is the right place to provision users, resolve organisations,
// or perform other one-time setup that should happen at login rather than on
// every authenticated request.
func WithOnLogin(fn LoginCallback) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.onLogin = fn
	}
}

// WithBasePath configures the auth component for an application that is
// mounted under a path prefix (see BasePath). The base path is applied to
// the login/logout redirects, the logout menu item, and the auth cookie
// paths, so the flow stays within the mounted application.
func WithBasePath(bp BasePath) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.basePath = bp
	}
}

// WithSessionCookieName overrides the name of the session token cookie
// (default "token"). Applications served on the same host must use
// distinct session cookie names, otherwise logging in to one application
// invalidates the session of the other.
//
// The name must be an HTTP token, as RFC 6265 requires: no separators, and
// the colon in particular. It is not merely a cookie-syntax matter — the
// name goes into the domain a sealed cookie value is bound to, and a colon
// in it makes two purposes produce the same label. See cookieDomain, which
// is where howdah builds those labels and where the name is checked.
func WithSessionCookieName(name string) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.cookieName = name
	}
}

// WithMaxSessionAge sets how long a session may live before the user has to
// log in again (default DefaultMaxSessionAge). The age is measured against
// an issued_at sealed into the session cookie, so it is a limit the server
// enforces rather than an instruction the browser is asked to follow — and
// it survives a refresh, because the refresh re-seals the same issued_at.
//
// Raising it is not free. A store-less session cannot be revoked, so the
// maximum session age is also how long a copied cookie value keeps working,
// and how long a retired cookie key has to stay in the keyring before it
// can be dropped.
func WithMaxSessionAge(d time.Duration) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.maxSessionAge = d
	}
}

// WithInsecureCookies drops the Secure attribute from the cookies the
// application sets. It is there for plain-http local development, where a
// Secure cookie is one the browser accepts and then never sends back, and
// it is the only way to turn Secure off: howdah does not take the answer
// from the connection or from a forwarded-protocol header. See setCookie.
//
// The language cookie follows this too, so an application registering
// OIDCAuth as a component gets one posture rather than two.
//
// Never set it on anything a browser reaches over a network.
func WithInsecureCookies() OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.insecure = true
	}
}

type OIDCAuth struct {
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	accessVerifier *oidc.IDTokenVerifier
	conf           oauth2.Config
	keyring        *CookieKeyring
	onLogin        LoginCallback
	basePath       BasePath
	cookieName     string
	maxSessionAge  time.Duration
	insecure       bool

	// sessionDomain and redirDomain are the domain strings the session
	// and auth_redir cookie values are sealed under. They are built once,
	// at construction, so that a cookie name a value cannot be bound to
	// is a startup error rather than a failure on the first login.
	sessionDomain string
	redirDomain   string

	// refresh collapses the concurrent refreshes of one session onto a
	// single token endpoint round trip. See refreshToken.
	refresh singleflight.Group
}

// NewOIDCAuth builds the auth component. The keyring seals the session
// cookie and the post-login redirect cookie, and is required: howdah has no
// mode in which it writes an OAuth2 refresh token to the browser in the
// clear. Build it with CookieKeyringFromEnv.
func NewOIDCAuth(
	provider *oidc.Provider,
	verifier *oidc.IDTokenVerifier,
	conf oauth2.Config,
	keyring *CookieKeyring,
	opts ...OIDCAuthOption,
) (*OIDCAuth, error) {
	if keyring == nil {
		return nil, errors.New("a cookie keyring is required")
	}

	a := &OIDCAuth{
		provider: provider,
		verifier: verifier,
		accessVerifier: provider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		}),
		conf:          conf,
		keyring:       keyring,
		cookieName:    "token",
		maxSessionAge: DefaultMaxSessionAge,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.maxSessionAge <= 0 {
		return nil, fmt.Errorf(
			"the maximum session age must be positive, got %s",
			a.maxSessionAge)
	}

	var err error

	a.sessionDomain, err = cookieDomain(cookieDomainSession, a.cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie: %w", err)
	}

	a.redirDomain, err = cookieDomain(
		cookieDomainAuthRedirect, a.cookieName)
	if err != nil {
		return nil, fmt.Errorf("auth redirect cookie: %w", err)
	}

	return a, nil
}

func (a *OIDCAuth) RegisterRoutes(mux *PageMux) {
	mux.HandleFunc("GET /auth/login", a.authLogin)
	mux.HandleFunc("POST /auth/login", a.authRedirect)
	mux.HandleFunc("GET /auth/logout", a.authLogout)
	mux.HandleFunc("GET /auth/callback", a.authCallback)
}

// Keepalive is an http.HandlerFunc that reads the OIDC token cookie and
// refreshes the access token when it's near expiry, writing the new token
// back to the cookie. It responds 204 No Content on success and 401
// Unauthorized when there is no cookie or the refresh fails.
//
// Useful for periodic keepalive XHRs from the frontend so a user's session
// doesn't drop while they're browsing pages that don't otherwise call
// RequireAuth. Register on whichever http.ServeMux the application uses
// for its API endpoints, e.g.
//
//	mux.HandleFunc("GET /auth/keepalive", auth.Keepalive)
func (a *OIDCAuth) Keepalive(w http.ResponseWriter, r *http.Request) {
	session, err := a.readTokenCookie(w, r)
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)

		return
	}

	if _, ok := a.checkTokenExpiry(w, r, session); !ok {
		// The session is dead, but the browser has no way of knowing
		// that and re-sends the cookie on every subsequent keepalive.
		// A cookie that cannot be opened is already cleared by
		// readTokenCookie; this is the refresh failure path, which
		// otherwise turns a one-off into a standing 401 loop.
		a.clearTokenCookie(w)

		http.Error(w, "refresh failed", http.StatusUnauthorized)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *OIDCAuth) MenuHook(hooks *MenuHooks) {
	hooks.RegisterHook(func() []MenuItem {
		return []MenuItem{
			{
				Title:  TL("LogOut", "Log out"),
				HREF:   a.basePath.Path("/auth/logout"),
				Weight: 999,
			},
		}
	})
}

var (
	tokenCtxKey       int
	accessTokenCtxKey int
)

// AccessToken returns the verified access token from the context. Use the
// Claims method on the returned IDToken to extract the token's claims into a
// struct of your choosing.
func AccessToken(ctx context.Context) (*oidc.IDToken, bool) {
	token, ok := ctx.Value(&accessTokenCtxKey).(*oidc.IDToken)
	return token, ok
}

// Token returns the user's OAuth2 token (access + refresh + expiry)
// from the auth context. RequireAuth places the post-refresh token
// here, so callers that need to forward the access token to another
// service or to the page should use this rather than re-reading the
// request cookie — the request cookie is what the browser sent,
// which is the pre-refresh value if RequireAuth just refreshed.
func Token(ctx context.Context) (*oauth2.Token, bool) {
	token, ok := ctx.Value(&tokenCtxKey).(*oauth2.Token)
	return token, ok
}

func (a *OIDCAuth) OIDCUserInfo(ctx context.Context) (*oidc.UserInfo, error) {
	token, ok := ctx.Value(&tokenCtxKey).(*oauth2.Token)
	if !ok {
		return nil, errors.New("no token in context")
	}

	info, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("get user info: %w", err)
	}

	return info, nil
}

func (a *OIDCAuth) RequireAuth(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (context.Context, error) {
	// readTokenCookie has already logged whatever the failure was worth,
	// at the level the failure taxonomy calls for, and cleared the cookie
	// if it was unusable.
	session, err := a.readTokenCookie(w, r)
	if err != nil {
		http.Redirect(w, r, a.loginURL(r), http.StatusFound)

		return ctx, ErrSkipRender
	}

	token, ok := a.checkTokenExpiry(w, r, session)
	if !ok {
		// As in Keepalive: the refresh failed, so the cookie is dead
		// and stays dead until the user logs in again. Clearing it
		// keeps the browser from sending it along to every page on the
		// way there.
		a.clearTokenCookie(w)

		http.Redirect(w, r, a.loginURL(r), http.StatusFound)

		return ctx, ErrSkipRender
	}

	// We're making a pretty big assumption here, and that is that the
	// access token actually is a JWT, it holds true for our environment,
	// but YMMV.
	accessToken, err := a.accessVerifier.Verify(ctx, token.AccessToken)
	if err != nil {
		slog.ErrorContext(ctx, "verify access token", "err", err)

		http.Redirect(w, r, a.loginURL(r), http.StatusFound)

		return ctx, ErrSkipRender
	}

	authCtx, err := twirp.WithHTTPRequestHeaders(ctx, http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", token.AccessToken)},
	})
	if err != nil {
		return ctx, NewHTTPError(http.StatusInternalServerError,
			"FailedToSetUpSession", "Failed to set up session", err)
	}

	authCtx = context.WithValue(authCtx, &tokenCtxKey, token)
	authCtx = context.WithValue(authCtx, &accessTokenCtxKey, accessToken)

	return authCtx, nil
}

// checkTokenExpiry refreshes the access token if it is close to expiry, and
// is the one place the session cookie is written on an authenticated
// request. The two reasons to write it — the token changed, or the value
// was sealed under a key we no longer seal with — are mutually exclusive
// branches here, so a response carries exactly one Set-Cookie for the
// session whichever path the request takes.
func (a *OIDCAuth) checkTokenExpiry(
	w http.ResponseWriter, r *http.Request, session *authSession,
) (*oauth2.Token, bool) {
	if time.Until(session.token.Expiry) > tokenRefreshMargin {
		if session.stale {
			// The value opened under a key that is on its way out, so
			// it is re-sealed under the current one. This is what
			// drains the old key during a rollover; without it a
			// retired key can only be dropped once every outstanding
			// session has aged out.
			err := a.setTokenCookie(
				w, session.token, session.issuedAt)
			if err != nil {
				// The session is fine — a failed re-seal is not a
				// reason to log anybody out. The value stays under
				// the old key and the next request tries again.
				slog.ErrorContext(r.Context(),
					"re-seal session cookie", "err", err)
			}
		}

		return session.token, true
	}

	newToken, err := a.refreshToken(r.Context(), session)
	if err != nil {
		slog.ErrorContext(r.Context(), "refresh token", "err", err)

		return nil, false
	}

	// The issued_at is carried forward unchanged. Restarting it on a
	// refresh would slide the session age cap forward every few minutes,
	// which is to say it would enforce nothing at all.
	err = a.setTokenCookie(w, newToken, session.issuedAt)
	if err != nil {
		slog.ErrorContext(r.Context(), "set token cookie", "err", err)

		return nil, false
	}

	return newToken, true
}

// refreshToken exchanges the session's refresh token for a new one,
// collapsing the concurrent refreshes of a single session onto one round
// trip to the provider. A page load that fires several XHRs, plus the
// keepalive, otherwise posts the same refresh token several times over:
// wasteful today, and a mid-session logout for every loser the day the
// realm turns on refresh token rotation. Collapsing them also settles which
// token wins the cookie, since every caller gets the same one.
//
// The deduplication is per process and does not reach across replicas. That
// is the bargain of keeping the tokens in the cookie rather than in a
// store, and it covers the common case: the several requests of one page
// load are handled by one process.
func (a *OIDCAuth) refreshToken(
	ctx context.Context, session *authSession,
) (*oauth2.Token, error) {
	// Keyed on the cookie value, so only requests carrying the same
	// session share an exchange.
	res, err, _ := a.refresh.Do(session.value, func() (any, error) {
		return a.exchangeRefreshToken(ctx, session.token.RefreshToken)
	})
	if err != nil {
		return nil, fmt.Errorf("exchange refresh token: %w", err)
	}

	token, ok := res.(*oauth2.Token)
	if !ok {
		return nil, fmt.Errorf("unexpected refresh result of type %T", res)
	}

	return token, nil
}

func (a *OIDCAuth) exchangeRefreshToken(
	ctx context.Context, refreshToken string,
) (*oauth2.Token, error) {
	// The exchange runs on a context detached from the request, with a
	// timeout of its own. A client that disconnects mid-exchange would
	// otherwise cancel a call the provider has already acted on — and
	// with several requests collapsed onto one exchange, the client that
	// goes away is not necessarily the one that started it.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), tokenRefreshTimeout)
	defer cancel()

	values := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {a.conf.ClientID},
		"client_secret": {a.conf.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.provider.Endpoint().TokenURL,
		strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	token, err := doTokenRoundTrip(ctx, http.DefaultClient, req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint round trip: %w", err)
	}

	// RFC 6749 §6 makes refresh_token optional in the response to a
	// refresh_token grant: a provider that leaves it out is saying "keep
	// using the one you have". x/oauth2 guards this in RetrieveToken, which
	// is one level above the doTokenRoundTrip token.go copied, so the guard
	// has to be repeated here. Without it the session is re-sealed with an
	// empty refresh token, the next refresh posts nothing, comes back
	// invalid_grant, and every user is bounced to login one access token
	// lifetime after logging in — with a log line that reads as a provider
	// problem.
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}

	assumeTokenExpiry(ctx, token)

	return token, nil
}

// assumeTokenExpiry gives a token that arrived without an expiry the
// conservative one from assumedAccessTokenLifetime, so that the zero Expiry
// is interpreted once, where the token enters the session, rather than by
// every reader of the sealed payload. Callers are the two places a token
// comes back from the provider: the login exchange and the refresh.
func assumeTokenExpiry(ctx context.Context, token *oauth2.Token) {
	if !token.Expiry.IsZero() {
		return
	}

	slog.WarnContext(ctx,
		"the token endpoint returned no expires_in, assuming a short access token lifetime",
		"assumed_lifetime", assumedAccessTokenLifetime)

	token.Expiry = time.Now().Add(assumedAccessTokenLifetime)
}

func (a *OIDCAuth) authLogin(
	_ context.Context, _ http.ResponseWriter, _ *http.Request,
) (*Page, error) {
	return &Page{
		Template: "login.html",
		Title:    TL("LogIn", "Log In"),
	}, nil
}

func (a *OIDCAuth) authRedirect(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	state, err := randString(16)
	if err != nil {
		return nil, fmt.Errorf("generate random state: %w", err)
	}

	nonce, err := randString(16)
	if err != nil {
		return nil, fmt.Errorf("generate random nonce: %w", err)
	}

	// state and nonce are deliberately left in the clear. They are random
	// values whose only purpose is to be compared against what the
	// provider echoes back — the state query parameter and the ID token's
	// nonce claim — so their integrity is inherent in that comparison:
	// rewrite either one and it no longer matches. Sealing them would
	// bind them to this cookie name, which is worth having for auth_redir
	// below because that is a path the application acts on, and buys
	// nothing at all here. This is not an oversight, so please don't
	// "fix" it.
	a.setCallbackCookie(w, "state", state)
	a.setCallbackCookie(w, "nonce", nonce)

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		// Cleared rather than left alone. A login started from the login
		// page carries no target of its own, so a target from an earlier
		// attempt the user abandoned would still be in the browser, and
		// the callback of this login would land them wherever that one
		// was headed — for as long as the cookie lives.
		a.clearCallbackCookie(w, authRedirCookieName)
	} else {
		err = a.setAuthRedirCookie(w, r, redirect)
		if err != nil {
			return nil, fmt.Errorf("set auth redirect cookie: %w", err)
		}
	}

	http.Redirect(
		w, r,
		a.conf.AuthCodeURL(state, oidc.Nonce(nonce)),
		http.StatusFound)

	return nil, ErrSkipRender
}

func (a *OIDCAuth) authLogout(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	a.clearTokenCookie(w)

	http.Redirect(w, r, a.basePath.Path("/"), http.StatusFound)

	return nil, ErrSkipRender
}

func (a *OIDCAuth) authCallback(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	failMsg := TL("FailedToHandleLogin",
		"Failed to handle login, please try again")

	if oidcErr := r.URL.Query().Get("error"); oidcErr != "" {
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = oidcErr
		}

		return nil, LiteralHTTPError(http.StatusForbidden,
			fmt.Errorf("login denied by provider: %s", desc))
	}

	state, err := r.Cookie("state")
	if err != nil {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"state not found")
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"nonce not found")
	}

	// The bool is not needed: a request that carries no redirect cookie, or
	// one whose cookie did not open, gives the empty string, which
	// resolveRedirect refuses like any other value that is not an absolute
	// path within the application.
	target, _ := a.readAuthRedirCookie(r)

	// The callback cookies belong to this one login attempt and have all
	// been read by now, so they are cleared here rather than on the way
	// out: every path below ends the attempt, and a value left behind is a
	// value the next callback picks up. The redirect target is the one that
	// misbehaves visibly — it hijacks the landing page of a later login
	// started without a target of its own — but state and nonce have no
	// business outliving the attempt either.
	//
	// Clearing them before the state is compared rather than after means a
	// forced navigation to the callback costs the user the login button
	// again. That is the better half of the trade: the attempt is cheap to
	// restart, and a target that outlives it is not something the next
	// login can tell from its own.
	a.clearCallbackCookie(w, "state")
	a.clearCallbackCookie(w, "nonce")
	a.clearCallbackCookie(w, authRedirCookieName)

	if r.URL.Query().Get("state") != state.Value {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"state did not match")
	}

	oauth2Token, err := a.conf.Exchange(
		ctx, r.URL.Query().Get("code"))
	if err != nil {
		return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
			"failed to exchange token: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
			"no id_token field in oauth2 token: %w", err)
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
			"failed to verify ID Token: %w", err)
	}

	if idToken.Nonce != nonce.Value {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"nonce did not match")
	}

	if a.onLogin != nil {
		err = a.onLogin(ctx, idToken)
		if err != nil {
			return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
				"login callback: %w", err)
		}
	}

	// The provider's own exchange leaves Expiry at the zero time when the
	// response carries no expires_in, exactly as the refresh does.
	assumeTokenExpiry(ctx, oauth2Token)

	// This is the one place a session's issued_at is set. Everything
	// downstream carries it forward, so the age cap is measured from the
	// login and from nothing else.
	err = a.setTokenCookie(w, oauth2Token, time.Now())
	if err != nil {
		return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
			"set token cookie: %w", err)
	}

	http.Redirect(w, r, resolveRedirect(a.basePath, target),
		http.StatusFound)

	return nil, ErrSkipRender
}

// loginURL builds the login redirect target for unauthenticated requests.
// The redirect parameter is the application-relative URL of the current
// request; the base path is applied when the callback redirects back to
// it.
func (a *OIDCAuth) loginURL(r *http.Request) string {
	v := url.Values{
		"redirect": {r.URL.String()},
	}

	return a.basePath.Path("/auth/login") + "?" + v.Encode()
}

// safeRedirectPath checks that a client-supplied redirect target is an
// absolute path within the application, rejecting values that a browser
// would treat as a scheme-relative or absolute URL to another host.
func safeRedirectPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}

	return !strings.HasPrefix(path, "//") && !strings.HasPrefix(path, "/\\")
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err //nolint: wrapcheck
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sessionPayloadV1 is the version of the session payload this build writes.
// It is independent of the envelope version: the envelope says how the
// bytes are sealed, this says what they mean once they are open.
const sessionPayloadV1 = 1

// sessionPayload is the plaintext a session cookie's envelope wraps. It is
// a struct rather than the bare oauth2.Token JSON so that a session carries
// the time it started, which is what lets the server cap the session's age
// — a weaker expires_at that needs no database.
//
// This is a wire contract, not an internal detail. The howdah release that
// moves sealing behind a token store has to produce these bytes
// byte-compatibly or every session in the fleet is logged out on upgrade,
// so fields may be added but never renamed or repurposed, and anything else
// takes a new Version.
type sessionPayload struct {
	Version  int           `json:"v"`
	IssuedAt time.Time     `json:"issued_at"`
	Token    *oauth2.Token `json:"token"`
}

// authSession is a session as read from the cookie, and carries what the
// write path needs to put it back.
type authSession struct {
	token    *oauth2.Token
	issuedAt time.Time

	// value is the cookie value the session was read from. It keys the
	// refresh group, so the concurrent requests of one page load
	// deduplicate against each other and nothing else.
	value string

	// stale reports that the value was sealed under a key that is no
	// longer the one we seal with, so it wants re-sealing on the way out.
	// See checkTokenExpiry, which is where that happens.
	stale bool
}

// insecureCookies implements cookieSecurity so that the application can
// give its language cookie the same treatment as the session cookie.
func (a *OIDCAuth) insecureCookies() bool {
	return a.insecure
}

// cookieAttributeBudget is a generous allowance for the attributes
// setCookie adds — Path, Expires, Max-Age, HttpOnly, Secure, SameSite — so
// the size check below fails before the browser does rather than after.
const cookieAttributeBudget = 120

func (a *OIDCAuth) setTokenCookie(
	w http.ResponseWriter, token *oauth2.Token, issuedAt time.Time,
) error {
	data, err := json.Marshal(sessionPayload{
		Version:  sessionPayloadV1,
		IssuedAt: issuedAt,
		Token:    token,
	})
	if err != nil {
		return fmt.Errorf("marshal session payload: %w", err)
	}

	value, err := a.keyring.seal(a.sessionDomain, data)
	if err != nil {
		return fmt.Errorf("seal session payload: %w", err)
	}

	// Refuse rather than hand the browser a cookie it will drop on the
	// floor. A dropped session cookie is a login that reports success and
	// lands the user back on the login page, over and over, with nothing
	// anywhere saying why — so failing the login outright is the kinder
	// outcome, and the only one that names the cause.
	//
	// The store-less session carries the whole token set, so a provider
	// that issues large access tokens — a fat roles or groups claim is the
	// usual reason — can push it past what a cookie can hold.
	if size := len(value) + len(a.cookieName) + cookieAttributeBudget; size > cookieSizeLimit {
		return fmt.Errorf(
			"the sealed session is %d bytes, over the %d a cookie can hold:"+
				" the provider's tokens are too large to keep in a cookie",
			size, cookieSizeLimit)
	}

	setCookie(w, &http.Cookie{
		Name:  a.cookieName,
		Value: value,
		// The browser is asked to drop the cookie at the moment the
		// server would stop accepting it, so that the two agree on when
		// the session ends. The server's copy of that deadline is the
		// sealed issued_at, which is the one that counts.
		Expires: issuedAt.Add(a.maxSessionAge),
		Path:    a.basePath.Path("/"),
	}, a.insecure)

	return nil
}

// readTokenCookie opens the session cookie. A cookie that cannot be used —
// unsealed, sealed under a key that is gone, tampered with, or simply older
// than the maximum session age — is cleared on the way out, so the browser
// stops sending it.
//
// The age cap is enforced here rather than in RequireAuth alone because
// this is the single place a session enters the process: Keepalive would
// otherwise keep refreshing a session past the cap that RequireAuth
// refuses, leaving the user with a cookie that works everywhere except on
// the pages they wanted.
func (a *OIDCAuth) readTokenCookie(
	w http.ResponseWriter, r *http.Request,
) (*authSession, error) {
	c, err := r.Cookie(a.cookieName)
	if err != nil {
		return nil, fmt.Errorf("read session cookie: %w", err)
	}

	plaintext, current, err := a.keyring.open(a.sessionDomain, c.Value)
	if err != nil {
		return nil, a.rejectTokenCookie(w, r,
			fmt.Errorf("open session cookie: %w", err))
	}

	var payload sessionPayload

	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		return nil, a.rejectTokenCookie(w, r,
			fmt.Errorf("unmarshal session payload: %w", err))
	}

	if payload.Version != sessionPayloadV1 {
		return nil, a.rejectTokenCookie(w, r, fmt.Errorf(
			"unsupported session payload version %d", payload.Version))
	}

	if payload.Token == nil {
		return nil, a.rejectTokenCookie(w, r,
			errors.New("the session payload carries no token"))
	}

	if age := time.Since(payload.IssuedAt); age >= a.maxSessionAge {
		return nil, a.rejectTokenCookie(w, r, fmt.Errorf(
			"the session is %s old, past the maximum age of %s",
			age.Round(time.Second), a.maxSessionAge))
	}

	return &authSession{
		token:    payload.Token,
		issuedAt: payload.IssuedAt,
		value:    c.Value,
		stale:    !current,
	}, nil
}

// rejectTokenCookie clears an unusable session cookie, logs why at the level
// the failure taxonomy calls for, and returns the error it was given so the
// caller can hand it straight back.
//
// Every case ends the same way — the cookie is unset and the user is sent to
// login — but they do not mean the same thing: ErrAuthentication is
// tampering, crossed environments or a truncated cookie, and is the one row
// worth alerting on, while the rest are the expected noise of a rollout, a
// rollback, or a key that has been retired.
func (a *OIDCAuth) rejectTokenCookie(
	w http.ResponseWriter, r *http.Request, err error,
) error {
	level := slog.LevelInfo
	if errors.Is(err, ErrAuthentication) {
		level = slog.LevelWarn
	}

	slog.Log(r.Context(), level, "unusable session cookie",
		"cookie", a.cookieName, "err", err)

	a.clearTokenCookie(w)

	return err
}

func (a *OIDCAuth) clearTokenCookie(w http.ResponseWriter) {
	setCookie(w, &http.Cookie{
		Name:  a.cookieName,
		Value: "",
		// Both, rather than one or the other: Max-Age is what current
		// browsers act on and takes precedence where they support it,
		// while the expiry in the past is what an old one understands.
		// A cookie cleared by only one of them is a cookie something
		// out there keeps sending back.
		Expires: time.Now().Add(-24 * time.Hour),
		MaxAge:  -1,
		Path:    a.basePath.Path("/"),
	}, a.insecure)
}

// setAuthRedirCookie seals the post-login redirect target into the
// auth_redir cookie. The value is bound to this application's session
// cookie name, so a co-hosted application sharing the keyring cannot
// supply it.
func (a *OIDCAuth) setAuthRedirCookie(
	w http.ResponseWriter, r *http.Request, redirect string,
) error {
	value, err := a.keyring.seal(a.redirDomain, []byte(redirect))
	if err != nil {
		return fmt.Errorf("seal redirect target: %w", err)
	}

	a.setCallbackCookie(w, authRedirCookieName, value)

	return nil
}

// readAuthRedirCookie returns the post-login redirect target, if the
// request carries one that opens. The caller still has to resolve it through
// resolveRedirect: sealing says the value is ours, not that it is a path we
// are willing to redirect to.
func (a *OIDCAuth) readAuthRedirCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(authRedirCookieName)
	if err != nil {
		return "", false
	}

	// The current flag is ignored: the cookie is read once, at the end of
	// the login it belongs to, so there is nothing to migrate.
	plaintext, _, err := a.keyring.open(a.redirDomain, c.Value)
	if err != nil {
		// Not worth failing the login over — the user lands on the
		// application root rather than where they were headed.
		slog.InfoContext(r.Context(), "unusable auth redirect cookie",
			"err", err)

		return "", false
	}

	return string(plaintext), true
}

func (a *OIDCAuth) setCallbackCookie(
	w http.ResponseWriter, name, value string,
) {
	setCookie(w, &http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: int(time.Hour.Seconds()),
		Path:   a.basePath.Path("/auth"),
	}, a.insecure)
}

// clearCallbackCookie unsets one of the cookies a login attempt carries.
// They live for an hour, which is a long time for a value that belongs to a
// single attempt, so anything that ends an attempt clears them rather than
// waiting them out. Both expiry attributes are written, for the reason
// clearTokenCookie gives.
func (a *OIDCAuth) clearCallbackCookie(w http.ResponseWriter, name string) {
	setCookie(w, &http.Cookie{
		Name:    name,
		Value:   "",
		Expires: time.Now().Add(-24 * time.Hour),
		MaxAge:  -1,
		Path:    a.basePath.Path("/auth"),
	}, a.insecure)
}
