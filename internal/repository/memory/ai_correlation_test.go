// Package memory_test — ai_correlation_test pins the create-time
// validation contract for the AICorrelationRepository: both status and
// severity must be one of the allowed enum values, mirroring the
// postgres CHECK constraints in migration 029.
package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestAICorrelationRepository_Create_RejectsInvalidSeverity(t *testing.T) {
	t.Parallel()
	repo := memory.NewAICorrelationRepository(memory.NewStore())
	_, err := repo.Create(context.Background(), uuid.New(), repository.AICorrelation{
		Severity: "catastrophic", // not in [low, medium, high, critical]
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAICorrelationRepository_Create_RejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	repo := memory.NewAICorrelationRepository(memory.NewStore())
	_, err := repo.Create(context.Background(), uuid.New(), repository.AICorrelation{
		Severity: "high",
		Status:   "bogus", // not in [open, acknowledged, resolved]
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAICorrelationRepository_Create_AcceptsValidEnums(t *testing.T) {
	t.Parallel()
	repo := memory.NewAICorrelationRepository(memory.NewStore())
	tenantID := uuid.New()
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		out, err := repo.Create(context.Background(), tenantID, repository.AICorrelation{
			Severity: sev, // status defaults to "open"
		})
		if err != nil {
			t.Fatalf("Create(severity=%q) unexpected error: %v", sev, err)
		}
		if out.Status != "open" {
			t.Fatalf("status = %q, want open (default)", out.Status)
		}
	}
}
