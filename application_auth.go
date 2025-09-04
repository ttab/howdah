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
)

type OIDCUserInfoSource interface {
	OIDCUserInfo(ctx context.Context) (*oidc.UserInfo, error)
}

type OIDCAuth struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	conf     oauth2.Config
}

func NewOIDCAuth(
	provider *oidc.Provider,
	verifier *oidc.IDTokenVerifier,
	conf oauth2.Config,
) *OIDCAuth {
	return &OIDCAuth{
		provider: provider,
		verifier: verifier,
		conf:     conf,
	}
}

func (a *OIDCAuth) RegisterRoutes(mux *PageMux) {
	mux.HandleFunc("GET /auth/login", a.authLogin)
	mux.HandleFunc("POST /auth/login", a.authRedirect)
	mux.HandleFunc("GET /auth/logout", a.authLogout)
	mux.HandleFunc("GET /auth/callback", a.authCallback)
}

func (a *OIDCAuth) MenuHook(hooks *MenuHooks) {
	hooks.RegisterHook(func() []MenuItem {
		return []MenuItem{
			{Title: TL("LogOut", "Log out"), HREF: "/auth/logout", Weight: 999},
		}
	})
}

var tokenCtxKey int

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
	token, err := readTokenCookie(w, r)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			slog.ErrorContext(r.Context(), "read token cookie",
				"err", err)
		}

		http.Redirect(w, r, loginURL(r), http.StatusFound)

		return ctx, ErrSkipRender
	}

	token, ok := a.checkTokenExpiry(w, r, token)
	if !ok {
		http.Redirect(w, r, loginURL(r), http.StatusFound)

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

	return authCtx, nil
}

func (a *OIDCAuth) checkTokenExpiry(
	w http.ResponseWriter, r *http.Request, token *oauth2.Token,
) (*oauth2.Token, bool) {
	if time.Until(token.Expiry) > 10*time.Second {
		return token, true
	}

	values := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {a.conf.ClientID},
		"client_secret": {a.conf.ClientSecret},
	}

	req, err := http.NewRequest("POST",
		a.provider.Endpoint().TokenURL,
		strings.NewReader(values.Encode()))
	if err != nil {
		slog.ErrorContext(r.Context(), "create token refresh request",
			"err", err)

		return nil, false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	newToken, err := doTokenRoundTrip(r.Context(), http.DefaultClient, req)
	if err != nil {
		slog.ErrorContext(r.Context(), "refresh token",
			"err", err)

		return nil, false
	}

	err = setTokenCookie(w, r, newToken)
	if err != nil {
		slog.ErrorContext(r.Context(), "set token cookie",
			"err", err)

		return nil, false
	}

	return newToken, true
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

	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	redirect := r.URL.Query().Get("redirect")
	if redirect != "" {
		setCallbackCookie(w, r, "auth_redir", redirect)
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
	clearTokenCookie(w, r)

	http.Redirect(w, r, "/", http.StatusFound)

	return nil, ErrSkipRender
}

func (a *OIDCAuth) authCallback(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*Page, error) {
	failMsg := TL("FailedToHandleLogin",
		"Failed to handle login, please try again")

	state, err := r.Cookie("state")
	if err != nil {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"state not found")
	}

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

	nonce, err := r.Cookie("nonce")
	if err != nil {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"nonce not found")
	}

	if idToken.Nonce != nonce.Value {
		return nil, HTTPErrorf(http.StatusBadRequest, failMsg,
			"nonce did not match")
	}

	err = setTokenCookie(w, r, oauth2Token)
	if err != nil {
		return nil, HTTPErrorf(http.StatusInternalServerError, failMsg,
			"set token cookie: %w", err)
	}

	redir := "/"

	redirCookie, err := r.Cookie("auth_redir")
	if err == nil {
		redir = redirCookie.Value
	}

	http.Redirect(w, r, redir, http.StatusFound)

	return nil, ErrSkipRender
}

func loginURL(r *http.Request) string {
	v := url.Values{
		"redirect": {r.URL.String()},
	}

	return "/auth/login?" + v.Encode()
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err //nolint: wrapcheck
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setTokenCookie(
	w http.ResponseWriter, r *http.Request, token *oauth2.Token,
) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	val := base64.RawURLEncoding.EncodeToString(data)

	c := &http.Cookie{
		Name:     "token",
		Value:    val,
		Expires:  time.Now().AddDate(0, 0, 7),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(w, c)

	return nil
}

func readTokenCookie(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	token, err := r.Cookie("token")
	if err != nil {
		return nil, fmt.Errorf("failed to read cookie: %w", err)
	}

	data, err := base64.RawURLEncoding.DecodeString(token.Value)
	if err != nil {
		clearTokenCookie(w, r)

		return nil, errors.New("invalid token cookie")
	}

	var tok oauth2.Token

	err = json.Unmarshal(data, &tok)
	if err != nil {
		clearTokenCookie(w, r)

		return nil, errors.New("invalid token cookie")
	}

	return &tok, nil
}

func clearTokenCookie(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-24 * time.Hour),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(w, c)
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Path:     "/auth",
	}

	http.SetCookie(w, c)
}
