// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package howdah

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// Adapted from OAuth2 internals.

func doTokenRoundTrip(ctx context.Context, client *http.Client, req *http.Request) (*oauth2.Token, error) {
	r, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	_ = r.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err) //nolint: errorlint
	}

	failureStatus := r.StatusCode < 200 || r.StatusCode > 299
	retrieveError := &oauth2.RetrieveError{
		Response: r,
		Body:     body,
		// attempt to populate error detail below
	}

	var token *oauth2.Token

	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		// some endpoints return a query string
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			if failureStatus {
				return nil, retrieveError
			}

			return nil, fmt.Errorf("oauth2: cannot parse response: %v", err) //nolint: errorlint
		}

		retrieveError.ErrorCode = vals.Get("error")
		retrieveError.ErrorDescription = vals.Get("error_description")
		retrieveError.ErrorURI = vals.Get("error_uri")

		token = &oauth2.Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
		}

		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)

		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON

		if err = json.Unmarshal(body, &tj); err != nil {
			if failureStatus {
				return nil, retrieveError
			}

			return nil, fmt.Errorf("oauth2: cannot parse json: %v", err) //nolint: errorlint
		}

		retrieveError.ErrorCode = tj.ErrorCode
		retrieveError.ErrorDescription = tj.ErrorDescription
		retrieveError.ErrorURI = tj.ErrorURI
		token = &oauth2.Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			ExpiresIn:    int64(tj.ExpiresIn),
		}
	}
	// according to spec, servers should respond status 400 in error case
	// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
	// but some unorthodox servers respond 200 in error case
	if failureStatus || retrieveError.ErrorCode != "" {
		return nil, retrieveError
	}

	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}

	return token, nil
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token or error in JSON form.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}

	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}

	var n json.Number

	err := json.Unmarshal(b, &n)
	if err != nil {
		return err //nolint: wrapcheck
	}

	i, err := n.Int64()
	if err != nil {
		return err //nolint: wrapcheck
	}

	if i > math.MaxInt32 {
		i = math.MaxInt32
	}

	*e = expirationTime(i) //nolint: gosec

	return nil
}
