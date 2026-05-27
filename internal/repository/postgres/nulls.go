package postgres

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// deletedAtScan is a thin wrapper around sql.NullTime so we can
// scan a NULLable TIMESTAMPTZ column directly with row.Scan, then
// project into a `*time.Time` field on the repository type
// without dragging database/sql import noise across every struct.
type deletedAtScan struct {
	Valid bool
	Time  time.Time
}

// Scan implements sql.Scanner so deletedAtScan can be passed directly
// to row.Scan. pgx routes through this interface for nullable
// timestamps when the destination is a custom type.
func (d *deletedAtScan) Scan(src any) error {
	if src == nil {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	if v, ok := src.(time.Time); ok {
		d.Valid = true
		d.Time = v.UTC()
		return nil
	}
	// Fall back to sql.NullTime's broader scanner — handles
	// driver.Value interface wrappers we might see in the future.
	var nt sql.NullTime
	if err := nt.Scan(src); err != nil {
		return err
	}
	d.Valid = nt.Valid
	d.Time = nt.Time.UTC()
	return nil
}

// nullableUUID is a Scanner for UUID columns that may be NULL.
type nullableUUID struct {
	Valid bool
	ID    uuid.UUID
}

func (n *nullableUUID) Scan(src any) error {
	if src == nil {
		n.Valid = false
		n.ID = uuid.Nil
		return nil
	}
	switch v := src.(type) {
	case [16]byte:
		n.Valid = true
		n.ID = uuid.UUID(v)
		return nil
	case []byte:
		// Some drivers pass the textual form of the uuid.
		id, err := uuid.ParseBytes(v)
		if err != nil {
			return err
		}
		n.Valid = true
		n.ID = id
		return nil
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return err
		}
		n.Valid = true
		n.ID = id
		return nil
	}
	return errInvalidNullScan
}

// errInvalidNullScan is returned by nullableUUID.Scan for src types
// it does not know how to handle. Errors are not wrapped because the
// scanner path is internal and the failure is interesting only when
// a future schema change introduces a column type we missed.
var errInvalidNullScan = errScanUnsupported{}

type errScanUnsupported struct{}

func (errScanUnsupported) Error() string {
	return "postgres: unsupported scan source for nullable UUID"
}
