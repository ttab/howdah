package howdah

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
// an issued_at the store keeps, so it is a limit the server enforces rather
// than an instruction the browser is asked to follow — and it survives a
// refresh, because the issued_at is carried forward unchanged.
//
// Raising it is not free. A store-less session cannot be revoked, so the
// maximum session age is also how long a copied cookie value keeps working,
// and how long a retired cookie key has to stay in the keyring before it
// can be dropped.
//
// It configures the store howdah builds for itself, so it cannot be
// combined with WithTokenStore: a store brings its own session lifetime, and
// an option that quietly did nothing would be the wrong kind of surprise for
// a session limit.
func WithMaxSessionAge(d time.Duration) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.maxSessionAge = d
		a.maxSessionAgeSet = true
	}
}

// WithTokenStore hands the auth component a store to keep sessions in,
// instead of the cookie-backed one it builds for itself. The store owns the
// session: it seals the handle that goes in the cookie, enforces the
// absolute expiry, and decides how far the deduplication of a concurrent
// refresh reaches.
//
// The store still needs the keyring — every store seals — so the keyring
// argument to NewOIDCAuth remains required whether or not this is passed.
func WithTokenStore(store TokenStore) OIDCAuthOption {
	return func(a *OIDCAuth) {
		a.store = store
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
	insecure       bool

	// store holds the sessions. It is a CookieTokenStore unless the
	// application passed WithTokenStore, and OIDCAuth cannot tell the
	// difference: it writes the Handle a write hands back and reads it
	// again on the next request.
	store TokenStore

	// maxSessionAge configures the store howdah builds for itself, and is
	// refused together with WithTokenStore — a store of the
	// application's own brings its own lifetime.
	maxSessionAge    time.Duration
	maxSessionAgeSet bool

	// sessionDomain and redirDomain are the domain strings the session
	// and auth_redir cookie values are sealed under. They are built once,
	// at construction, so that a cookie name a value cannot be bound to
	// is a startup error rather than a failure on the first login.
	sessionDomain string
	redirDomain   string
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

	if a.store != nil && a.maxSessionAgeSet {
		return nil, errors.New(
			"WithMaxSessionAge configures the store howdah builds for" +
				" itself and cannot be combined with WithTokenStore:" +
				" the session lifetime is the store's")
	}

	// Store-less by default, which is v0.2.0's session exactly: the whole
	// payload sealed into the cookie. An upgrade that quietly moved the
	// sessions somewhere else would be an upgrade that logs the fleet out.
	if a.store == nil {
		a.store = newCookieTokenStore(
			a.keyring, a.sessionDomain, a.maxSessionAge)
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
// request. There are two reasons to write it — the handle changed, or the
// value came in under a key we no longer seal with — and each branch below
// resolves both into a single write, so a response carries at most one
// Set-Cookie for the session whichever path the request takes.
//
// Both reasons are needed, and the second is the one that is easy to drop. A
// store whose handles are stable across a refresh — a session kept in a
// database is — hands back the handle that went in, so "the handle changed"
// alone would never fire and a key rollover would never migrate a stored
// session at all.
func (a *OIDCAuth) checkTokenExpiry(
	w http.ResponseWriter, r *http.Request, session *StoredToken,
) (*oauth2.Token, bool) {
	if time.Until(session.Token.Expiry) > tokenRefreshMargin {
		if session.Stale {
			// The value opened under a key that is on its way out, so
			// it is re-sealed under the current one. This is what
			// drains the old key during a rollover; without it a
			// retired key can only be dropped once every outstanding
			// session has aged out.
			a.migrateSessionCookie(w, r, session)
		}

		return session.Token, true
	}

	refreshed, err := a.store.Refresh(
		r.Context(), session, a.exchangeToken)
	if err != nil {
		slog.ErrorContext(r.Context(), "refresh token", "err", err)

		return nil, false
	}

	// A refresh does not necessarily move the handle — for a stored
	// session it deliberately does not — so a value that came in under a
	// retiring key still has to be re-sealed, or writing the refresh back
	// would put the stale value in the cookie again and the rollover
	// would never drain. Both happen before the single write below.
	if session.Stale {
		refreshed = a.resealSession(r.Context(), refreshed)
	}

	if refreshed.Handle != session.Handle {
		err = a.setTokenCookie(w, refreshed)
		if err != nil {
			slog.ErrorContext(r.Context(), "set token cookie", "err", err)

			return nil, false
		}
	}

	return refreshed.Token, true
}

// resealSession returns the session with a handle sealed under the key the
// keyring seals with now, or the session it was given if that fails. A
// failed re-seal is not a reason to log anybody out: the value stays under
// the old key and the next request tries again.
func (a *OIDCAuth) resealSession(
	ctx context.Context, session *StoredToken,
) *StoredToken {
	resealed, err := a.store.Reseal(ctx, session)
	if err != nil {
		slog.ErrorContext(ctx, "re-seal session cookie", "err", err)

		return session
	}

	return resealed
}

// migrateSessionCookie moves a session that opened under a retiring key to
// the current one. It is the request path's half of a key rollover, and it
// writes nothing at all if the store cannot produce a new handle — a store
// whose handles do not carry a key has nothing to migrate.
func (a *OIDCAuth) migrateSessionCookie(
	w http.ResponseWriter, r *http.Request, session *StoredToken,
) {
	resealed := a.resealSession(r.Context(), session)
	if resealed.Handle == session.Handle {
		return
	}

	err := a.setTokenCookie(w, resealed)
	if err != nil {
		slog.ErrorContext(r.Context(),
			"re-seal session cookie", "err", err)
	}
}

// exchangeToken is the token endpoint round trip a store's Refresh runs, and
// the only part of a refresh that is OIDCAuth's business: which requests
// share one exchange, and whether that reach is a process or the fleet, is
// the store's.
//
// It may run in a goroutine other than the one that asked for it, and it may
// not run at all for a caller that lost the race, so it holds no request
// state.
func (a *OIDCAuth) exchangeToken(
	ctx context.Context, token *oauth2.Token,
) (*oauth2.Token, error) {
	return a.exchangeRefreshToken(ctx, token.RefreshToken)
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

// loginFailedParam marks the login page as following a failed attempt. It
// is a query parameter, so anyone can set it and see the notice; all that
// buys them is a notice, and it keeps the reason for the failure server-side
// where it belongs.
const loginFailedParam = "login_failed"

// LoginPage is the Contents of the login page. A template can show the
// notice with {{if .Contents.Failed}}; one that ignores it renders exactly
// as before.
type LoginPage struct {
	// Failed reports that the visitor arrived here because a login attempt
	// did not complete. Why it did not is in the log rather than here:
	// there is nothing a visitor can do with the detail but try again, and
	// some of it should not be shown to them at all.
	Failed bool
}

// failLogin logs why a login attempt ended and sends the visitor back to the
// login page to start another one.
//
// The reason is deliberately not rendered at the callback URL. That URL still
// carries the authorization code in its query string, so an error page there
// is one that a reload re-submits — and a provider's answer to a code it has
// already redeemed is "code not valid", which replaces the real reason with a
// misleading one and makes a recoverable failure look permanent. Redirecting
// takes the code out of the address bar, so trying again actually tries
// again.
func (a *OIDCAuth) failLogin(
	w http.ResponseWriter, r *http.Request, err error,
) (*Page, error) {
	slog.WarnContext(r.Context(), "login attempt failed", "err", err)

	http.Redirect(w, r,
		a.basePath.Path("/auth/login")+"?"+loginFailedParam+"=1",
		http.StatusFound)

	return nil, ErrSkipRender
}

func (a *OIDCAuth) authLogin(
	_ context.Context, _ http.ResponseWriter, r *http.Request,
) (*Page, error) {
	return &Page{
		Template: "login.html",
		Title:    TL("LogIn", "Log In"),
		Contents: LoginPage{
			Failed: r.URL.Query().Get(loginFailedParam) != "",
		},
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
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	a.deleteSession(ctx, r)
	a.clearTokenCookie(w)

	http.Redirect(w, r, a.basePath.Path("/"), http.StatusFound)

	return nil, ErrSkipRender
}

// deleteSession asks the store to forget the session the request carries,
// which is what makes logout a revocation rather than a gesture at one
// browser. A store-less session has nothing to forget and says so by doing
// nothing.
//
// A failure is logged and nothing more. The cookie is cleared either way:
// there is nothing the user can do about a store that would not answer, and
// leaving them logged in on the strength of it would be the wrong reading of
// "log me out".
func (a *OIDCAuth) deleteSession(ctx context.Context, r *http.Request) {
	c, err := r.Cookie(a.cookieName)
	if err != nil {
		// No cookie, so no handle, so nothing to forget.
		return
	}

	err = a.store.Delete(ctx, c.Value)
	if err != nil {
		slog.ErrorContext(ctx, "delete the session", "err", err)
	}
}

func (a *OIDCAuth) authCallback(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
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
		return a.failLogin(w, r, errors.New("no state cookie"))
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		return a.failLogin(w, r, errors.New("no nonce cookie"))
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
		return a.failLogin(w, r, errors.New("state did not match"))
	}

	oauth2Token, err := a.conf.Exchange(
		ctx, r.URL.Query().Get("code"))
	if err != nil {
		return a.failLogin(w, r,
			fmt.Errorf("exchange the authorization code: %w", err))
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return a.failLogin(w, r,
			errors.New("the token response carries no id_token"))
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return a.failLogin(w, r,
			fmt.Errorf("verify the ID token: %w", err))
	}

	if idToken.Nonce != nonce.Value {
		return a.failLogin(w, r, errors.New("nonce did not match"))
	}

	if a.onLogin != nil {
		err = a.onLogin(ctx, idToken)
		if err != nil {
			return a.failLogin(w, r,
				fmt.Errorf("the login callback refused the login: %w", err))
		}
	}

	// The provider's own exchange leaves Expiry at the zero time when the
	// response carries no expires_in, exactly as the refresh does.
	assumeTokenExpiry(ctx, oauth2Token)

	// This is the one place a session is created, and so the one place its
	// issued_at is set — by the store, which carries it forward across
	// every refresh and re-seal, so the absolute expiry is measured from
	// the login and from nothing else.
	session, err := a.store.Create(ctx, NewSession{
		Subject: idToken.Subject,
		Token:   oauth2Token,
		IDToken: rawIDToken,
	})
	if err != nil {
		return a.failLogin(w, r,
			fmt.Errorf("create the session: %w", err))
	}

	err = a.setTokenCookie(w, session)
	if err != nil {
		return a.failLogin(w, r,
			fmt.Errorf("set the session cookie: %w", err))
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

// sessionPayload is the plaintext a store-less session's envelope wraps. It
// is a struct rather than the bare oauth2.Token JSON so that a session
// carries the time it started, which is what lets the server cap the
// session's age — a weaker expires_at that needs no database.
//
// This is a wire contract, not an internal detail: it is what a v0.2.0 build
// wrote, and CookieTokenStore still writes and reads exactly it, so nobody is
// logged out by the release that moved sealing behind a store. Fields may be
// added — omitempty, so an existing cookie's bytes are unchanged — but never
// renamed or repurposed, and anything else takes a new Version.
//
// The id_token StoredToken carries is deliberately not here; see
// CookieTokenStore.Create for why a store-less session cannot afford it.
type sessionPayload struct {
	Version  int           `json:"v"`
	IssuedAt time.Time     `json:"issued_at"`
	Token    *oauth2.Token `json:"token"`

	// Subject is the OIDC sub claim, added after v0.2.0. A store-less
	// session has no use for it of its own — nothing store-less can log a
	// subject out everywhere — but it is part of what a TokenStore
	// promises to hand back, and it costs a few dozen bytes rather than
	// the kilobyte an id_token would.
	Subject string `json:"sub,omitempty"`
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

// setTokenCookie writes a session's handle to the session cookie. It is the
// only place the handle reaches the browser, whichever store produced it.
func (a *OIDCAuth) setTokenCookie(
	w http.ResponseWriter, session *StoredToken,
) error {
	// Refuse rather than hand the browser a cookie it will drop on the
	// floor. A dropped session cookie is a login that reports success and
	// lands the user back on the login page, over and over, with nothing
	// anywhere saying why — so failing the login outright is the kinder
	// outcome, and the only one that names the cause.
	//
	// A store-less session's handle is the whole token set, so a provider
	// that issues large access tokens — a fat roles or groups claim is the
	// usual reason — can push it past what a cookie can hold. A handle to a
	// stored session is a hundred bytes and will not.
	size := len(session.Handle) + len(a.cookieName) + cookieAttributeBudget
	if size > cookieSizeLimit {
		return fmt.Errorf(
			"the session cookie would be %d bytes, over the %d a cookie"+
				" can hold: the provider's tokens are too large to keep"+
				" in a cookie",
			size, cookieSizeLimit)
	}

	setCookie(w, &http.Cookie{
		Name:  a.cookieName,
		Value: session.Handle,
		// The browser is asked to drop the cookie at the moment the
		// server would stop accepting it, so that the two agree on when
		// the session ends. The store's copy of that deadline is the one
		// that counts.
		Expires: session.ExpiresAt,
		Path:    a.basePath.Path("/"),
	}, a.insecure)

	return nil
}

// readTokenCookie resolves the session cookie through the store. A cookie
// that cannot be used — unsealed, sealed under a key that is gone, tampered
// with, unknown to the store, or simply past the session's absolute expiry —
// is cleared on the way out, so the browser stops sending it.
//
// The expiry is enforced wherever a session enters the process, not in
// RequireAuth alone, because Keepalive would otherwise keep refreshing a
// session past the limit RequireAuth refuses, leaving the user with a cookie
// that works everywhere except on the pages they wanted. The store is what
// makes that uniform: every reader goes through Get.
func (a *OIDCAuth) readTokenCookie(
	w http.ResponseWriter, r *http.Request,
) (*StoredToken, error) {
	c, err := r.Cookie(a.cookieName)
	if err != nil {
		return nil, fmt.Errorf("read session cookie: %w", err)
	}

	session, err := a.store.Get(r.Context(), c.Value)
	if err != nil {
		return nil, a.rejectTokenCookie(w, r, err)
	}

	// A store is a third party now, and everything downstream reads the
	// token without checking. Refusing the session here turns a store that
	// hands back nothing into a login redirect rather than a panic in
	// whichever handler happened to call RequireAuth.
	if session.Token == nil {
		return nil, a.rejectTokenCookie(w, r,
			fmt.Errorf("%w: the store returned a session with no token",
				ErrNoSession))
	}

	return session, nil
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
