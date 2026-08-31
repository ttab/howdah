package pgstore

import (
	"encoding/json"
	"fmt"

	"github.com/ttab/howdah"
	"golang.org/x/oauth2"
)

// sessionPayloadV1 is the version of the plaintext a row's payload column
// wraps. It is a wire contract: the rows outlive the process that wrote
// them, so a reader dispatches on the version and a writer only ever emits
// the current one. Adding a field is free; changing what one means takes a
// new version.
const sessionPayloadV1 = 1

// sessionPayload is what the payload column holds, sealed. The subject is in
// here as well as in a column of its own — the column is what the index and
// "log this person out everywhere" use, and the sealed copy is the one a
// read trusts, because a writer with database access can edit a column and
// cannot edit a payload.
type sessionPayload struct {
	Version int `json:"v"`

	Subject string `json:"sub,omitempty"`

	// Token is the session's token set. json.Marshal on an oauth2.Token
	// drops its Extra map, which is where an id_token arrives, so the raw
	// id_token is carried beside it rather than inside it.
	Token *oauth2.Token `json:"token"`

	// IDToken is the raw id_token from the login, kept because
	// RP-initiated logout at the provider needs it as id_token_hint and
	// there is no getting it back later. A row has the space for it, so
	// unlike a session sealed into a cookie this store keeps it.
	IDToken string `json:"id_token,omitempty"`
}

// sealPayload seals a payload for the row it belongs to and reports the key
// it sealed under, which the caller writes to the row's key_id column.
func (s *Store) sealPayload(
	id []byte, payload sessionPayload,
) ([]byte, howdah.KeyID, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, howdah.KeyID{}, fmt.Errorf(
			"marshal the session payload: %w", err)
	}

	sealed, kid, err := s.sealer.SealPayload(id, data)
	if err != nil {
		return nil, howdah.KeyID{}, err //nolint: wrapcheck
	}

	return sealed, kid, nil
}

// openPayload opens a row's payload. Every failure wraps
// howdah.ErrNoSession: a payload that will not open is a session nobody can
// use, whether that is a retired key or something worse.
func (s *Store) openPayload(
	id, sealed []byte,
) (*sessionPayload, error) {
	plaintext, _, _, err := s.sealer.OpenPayload(id, sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", howdah.ErrNoSession, err)
	}

	var payload sessionPayload

	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		return nil, fmt.Errorf("%w: unmarshal the session payload: %w",
			howdah.ErrNoSession, err)
	}

	if payload.Version != sessionPayloadV1 {
		return nil, fmt.Errorf(
			"%w: unsupported session payload version %d",
			howdah.ErrNoSession, payload.Version)
	}

	if payload.Token == nil {
		return nil, fmt.Errorf("%w: the session payload carries no token",
			howdah.ErrNoSession)
	}

	return &payload, nil
}
