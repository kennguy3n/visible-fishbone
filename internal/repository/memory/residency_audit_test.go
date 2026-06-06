// Package memory_test — residency_audit_test pins the write-time
// validation contract for the ResidencyAuditRepository so the memory
// store stays a faithful double for the postgres CHECK in migration 046
// (plane IN ('telemetry','policy_bundle','cold_storage')).
package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestResidencyAuditRepository_Record_RejectsInvalidPlane(t *testing.T) {
	t.Parallel()
	repo := memory.NewResidencyAuditRepository(memory.NewStore())
	_, err := repo.Record(context.Background(), uuid.New(), repository.ResidencyAuditEntry{
		Plane:            "unknown", // not in the migration-046 CHECK set
		DesignatedRegion: "ap-southeast-1",
		AttemptedRegion:  "eu-central-1",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestResidencyAuditRepository_Record_AcceptsValidPlane(t *testing.T) {
	t.Parallel()
	repo := memory.NewResidencyAuditRepository(memory.NewStore())
	for _, plane := range []string{"telemetry", "policy_bundle", "cold_storage"} {
		_, err := repo.Record(context.Background(), uuid.New(), repository.ResidencyAuditEntry{
			Plane:            plane,
			DesignatedRegion: "ap-southeast-1",
			AttemptedRegion:  "eu-central-1",
		})
		if err != nil {
			t.Fatalf("plane %q should be accepted: %v", plane, err)
		}
	}
}
