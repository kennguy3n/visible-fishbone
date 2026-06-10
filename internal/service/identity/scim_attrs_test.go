package identity

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestScimUserVersionNoSeparatorCollision verifies the meta.version hash
// is injective in its field tuple: two users whose field values differ
// only by where a delimiter-like character falls must hash differently
// (a fixed in-band separator would collide here).
func TestScimUserVersionNoSeparatorCollision(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	ts := time.Unix(0, 1234567890).UTC()

	a := repository.User{ID: id, Email: "x@y.z", Name: "a|b", ExternalID: "c", Status: repository.UserStatusActive, UpdatedAt: ts}
	b := repository.User{ID: id, Email: "x@y.z", Name: "a", ExternalID: "b|c", Status: repository.UserStatusActive, UpdatedAt: ts}

	if scimUserVersion(a) == scimUserVersion(b) {
		t.Error("expected distinct versions for distinct field tuples that share a delimiter boundary")
	}

	// Identical state must still produce a stable, equal version.
	if scimUserVersion(a) != scimUserVersion(a) {
		t.Error("version is not stable for identical input")
	}
}

func TestScimGroupVersionNoSeparatorCollision(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	a := repository.Role{ID: id, Name: "eng|ops", ExternalID: "x"}
	b := repository.Role{ID: id, Name: "eng", ExternalID: "ops|x"}
	if scimGroupVersion(a) == scimGroupVersion(b) {
		t.Error("expected distinct group versions for distinct field tuples sharing a delimiter boundary")
	}
}
