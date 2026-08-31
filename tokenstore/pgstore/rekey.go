package pgstore

import (
	"context"
	"fmt"

	"github.com/ttab/howdah/tokenstore/pgstore/postgres"
)

// Rekey re-seals at most batch sessions under the key the keyring seals with
// now and returns how many rows it dealt with. Call it until it returns 0.
//
// This is what makes a key rollover finish in a minute rather than in a
// session lifetime. Outstanding cookies cannot be swept, so a store-less
// application has to keep a retired key in the keyring until the longest
// possible session has aged out; a table can be swept, so once this returns
// 0 the old key is only holding open the cookies themselves, which the
// request path re-seals as it sees them.
//
// The rows are found through the key_id index rather than by opening every
// payload to discover which key it used, which is why the key id is a column
// as well as a field inside the sealed payload.
//
// Two things it is careful about:
//
//   - **The write is fenced on both the key id and the refreshed_at the
//     sweep read.** A sweep that interleaves with a refresh would otherwise
//     commit a re-sealed copy of the *old* payload over the new one — which,
//     with refresh token rotation on, resurrects a token the provider has
//     revoked and kills the session. A row the fence rejects has been
//     written by a refresh, which sealed it under the current key anyway, so
//     there is nothing left to do for it.
//   - **A payload that will not open is deleted, not skipped.** It is a
//     session nobody can use — its key is gone from the keyring, or worse —
//     and skipping it would leave it in the set this query selects, so "call
//     until it returns 0" would never terminate.
func (s *Store) Rekey(ctx context.Context, batch int) (int64, error) {
	size, err := batchSize(batch)
	if err != nil {
		return 0, err
	}

	kid := s.sealer.SealingKeyID()

	rows, err := s.q.ListRekeySessions(ctx, postgres.ListRekeySessionsParams{
		KeyID: kid.Bytes(),
		Batch: size,
	})
	if err != nil {
		return 0, fmt.Errorf("list the sessions to re-seal: %w", err)
	}

	var done int64

	for _, row := range rows {
		payload, _, _, err := s.sealer.OpenPayload(row.ID, row.Payload)
		if err != nil {
			_, delErr := s.q.DeleteSession(ctx, row.ID)
			if delErr != nil {
				return done, fmt.Errorf(
					"delete the session that would not open: %w",
					delErr)
			}

			done++

			continue
		}

		// The key that is current now, rather than the one the listing
		// asked for: a key's use-after can pass between the two, and
		// the column has to name the key the payload was actually
		// sealed under.
		sealed, newKID, err := s.sealer.SealPayload(row.ID, payload)
		if err != nil {
			return done, fmt.Errorf("re-seal the session payload: %w", err)
		}

		// The row count is deliberately not looked at. A row the fence
		// rejected was written by a refresh, which sealed it under the
		// current key, so it is out of the set the listing selects and
		// it counts as dealt with — a batch of nothing but those would
		// otherwise return 0 and stop a sweep that still had rows to
		// go.
		_, err = s.q.ResealSession(ctx, postgres.ResealSessionParams{
			ID:              row.ID,
			KeyID:           newKID.Bytes(),
			Payload:         sealed,
			SeenKeyID:       row.KeyID,
			SeenRefreshedAt: row.RefreshedAt,
		})
		if err != nil {
			return done, fmt.Errorf("write the re-sealed session: %w", err)
		}

		done++
	}

	return done, nil
}
