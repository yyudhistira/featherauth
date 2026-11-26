package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
)

// ImportOptions are the options of Import.
type ImportOptions struct {
	// IncludeWithoutIdentity imports users that have no identities too.
	IncludeWithoutIdentity bool
	// IDFormat is the realm's user_data.id_format: the format of the id given
	// to a row without one, config.IDFormatUUID or config.IDFormatULID. Empty
	// means uuid. An id given in the file is kept whatever its format.
	IDFormat string
}

// ImportReport says what an import did. Rows are numbered from 1 in file order.
type ImportReport struct {
	Created  int   // users written
	Existing int   // users that existed already and were left as they are
	Skipped  []int // rows without identities, skipped by default
}

type importIdentity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type importRow struct {
	ID            string           `json:"id"`
	Email         string           `json:"email"`
	EmailVerified bool             `json:"email_verified"`
	Name          string           `json:"name"`
	Disabled      bool             `json:"disabled"`
	Identities    []importIdentity `json:"identities"`
}

func invalid(row int, format string, a ...any) error {
	return fmt.Errorf("%w: row %d: %s", ErrInvalid, row, fmt.Sprintf(format, a...))
}

// parseImport reads and validates the whole file; nothing is written yet.
func parseImport(r io.Reader) ([]importRow, error) {
	br := bufio.NewReader(r)
	if head, _ := br.Peek(3); bytes.Equal(head, []byte("\xef\xbb\xbf")) {
		_, _ = br.Discard(3) // a UTF-8 byte order mark, as some editors write
	}
	dec := json.NewDecoder(br)
	var rows []importRow
	if err := dec.Decode(&rows); err != nil {
		return nil, fmt.Errorf("%w: the file is not a JSON list of users: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected data after the list", ErrInvalid)
	}
	ids := map[string]bool{}
	idents := map[importIdentity]bool{}
	verified := map[string]bool{}
	for i, row := range rows {
		n := i + 1
		if row.ID != "" && row.ID != strings.TrimSpace(row.ID) {
			return nil, invalid(n, "id has surrounding spaces")
		}
		if row.ID != "" {
			if ids[row.ID] {
				return nil, invalid(n, "id given twice")
			}
			ids[row.ID] = true
		}
		key := strings.ToLower(strings.TrimSpace(row.Email))
		if row.EmailVerified && key == "" {
			return nil, invalid(n, "email_verified without an email")
		}
		if len(row.Identities) == 0 && key == "" {
			return nil, invalid(n, "a user without identities needs an email")
		}
		if row.EmailVerified {
			if verified[key] {
				return nil, invalid(n, "a second user with the same verified email")
			}
			verified[key] = true
		}
		for _, id := range row.Identities {
			if strings.TrimSpace(id.Provider) == "" || id.Subject == "" {
				return nil, invalid(n, "identity needs a provider and a subject")
			}
			if idents[id] {
				return nil, invalid(n, "identity given twice")
			}
			idents[id] = true
		}
	}
	return rows, nil
}

// Import reads a JSON list of {id?, email, email_verified, name, disabled,
// identities: [{provider, subject}]} and writes the users into the realm,
// creating the realm's row when it has none. The whole file is validated
// first and everything is written in one transaction, so a failure writes
// nothing. Ids are kept when given. A user is left as it is when it exists
// already: by id, else by an identity, else (no identities) by email. Each user
// written gets one audit row. A user that would give a verified email a second
// holder, or an identity that is linked to someone else, gives ErrConflict.
func (o *Ops) Import(ctx context.Context, realm config.RealmName, r io.Reader, opts ImportOptions) (ImportReport, error) {
	// The caller checks that realm is a configured realm (config validation
	// already rejects invalid and reserved names); only an empty one is
	// refused here, so no nameless realm row can be made.
	if realm == "" {
		return ImportReport{}, fmt.Errorf("%w: realm is empty", ErrInvalid)
	}
	rows, err := parseImport(r)
	if err != nil {
		return ImportReport{}, err
	}
	var rep ImportReport
	var publish []func()
	err = o.store.Write(ctx, func(tx store.Tx) error {
		rep, publish = ImportReport{}, nil
		newRealm, err := secure.NewID(secure.Default, o.clock)
		if err != nil {
			return err
		}
		rid, err := tx.Realms().Ensure(ctx, realm, store.RealmID(newRealm), o.clock.Now())
		if err != nil {
			return err
		}
		for i, row := range rows {
			if len(row.Identities) == 0 && !opts.IncludeWithoutIdentity {
				rep.Skipped = append(rep.Skipped, i+1)
				continue
			}
			exists, err := o.imported(ctx, tx, rid, row)
			if err != nil {
				return err
			}
			if exists {
				rep.Existing++
				continue
			}
			pub, err := o.create(ctx, tx, rid, row, opts.IDFormat)
			if err != nil {
				return err
			}
			publish = append(publish, pub)
			rep.Created++
		}
		return nil
	})
	if err != nil {
		return ImportReport{}, err
	}
	for _, p := range publish {
		p()
	}
	return rep, nil
}

// imported reports whether the row's user exists already.
func (o *Ops) imported(ctx context.Context, tx store.Tx, rid store.RealmID, row importRow) (bool, error) {
	found := func(err error) (bool, error) {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	if row.ID != "" {
		_, err := tx.Users().Get(ctx, rid, store.UserID(row.ID))
		return found(err)
	}
	if len(row.Identities) > 0 {
		for _, id := range row.Identities {
			ok, err := found(func() error {
				_, err := tx.Identities().Find(ctx, rid, config.ProviderKey(id.Provider), id.Subject)
				return err
			}())
			if ok || err != nil {
				return ok, err
			}
		}
		return false, nil
	}
	same, err := tx.Users().ListByEmailKey(ctx, rid, strings.ToLower(strings.TrimSpace(row.Email)))
	return len(same) > 0, err
}

// create writes the user, its identities and its audit row.
func (o *Ops) create(ctx context.Context, tx store.Tx, rid store.RealmID, row importRow, idFormat string) (func(), error) {
	id := row.ID
	now := o.clock.Now()
	if id == "" {
		var err error
		switch idFormat {
		case "", config.IDFormatUUID:
			id, err = secure.NewUUID(secure.Default)
		case config.IDFormatULID:
			id, err = secure.NewID(secure.Default, o.clock)
		default:
			err = fmt.Errorf("admin: unknown user id format %q", idFormat)
		}
		if err != nil {
			return nil, err
		}
	}
	u := store.User{
		ID: store.UserID(id), RealmID: rid, Email: strings.TrimSpace(row.Email),
		EmailKey:      strings.ToLower(strings.TrimSpace(row.Email)),
		EmailVerified: row.EmailVerified, Name: row.Name, CreatedAt: now, UpdatedAt: now,
	}
	if row.Disabled {
		u.DisabledAt = now
	}
	if err := tx.Users().Create(ctx, u); err != nil {
		return nil, importErr(err)
	}
	for _, ident := range row.Identities {
		iid, err := secure.NewID(secure.Default, o.clock)
		if err != nil {
			return nil, err
		}
		err = tx.Identities().Create(ctx, store.Identity{
			ID: store.IdentityID(iid), RealmID: rid, UserID: u.ID,
			Provider: config.ProviderKey(ident.Provider), ProviderSub: ident.Subject, CreatedAt: now,
		})
		if err != nil {
			return nil, importErr(err)
		}
	}
	return o.audit.WriteTx(ctx, tx, audit.Event{Realm: rid, Actor: Actor, Action: ActionImport, User: u.ID})
}

func importErr(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return ErrConflict
	}
	return fmt.Errorf("admin: import: %w", err)
}
