package troubleshoot_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
)

// mockLLMProvider is a test double for the AI LLM provider. It records
// the tenant ID carried on the context it was called with so tests can
// assert per-tenant attribution.
type mockLLMProvider struct {
	response  ai.LLMResponse
	err       error
	gotTenant uuid.UUID
}

func (m *mockLLMProvider) Complete(ctx context.Context, _ ai.LLMRequest) (ai.LLMResponse, error) {
	m.gotTenant = ai.TenantIDFromContext(ctx)
	return m.response, m.err
}

func TestAssistant_Respond_WithLLM(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	kbSvc := troubleshoot.NewKBService(kbRepo)

	// Seed a KB entry.
	_, err := kbSvc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryConnectivity,
		Title:    "VPN Issues",
		Content:  "Check VPN tunnel status and certificates",
	})
	if err != nil {
		t.Fatal(err)
	}

	llm := &mockLLMProvider{
		response: ai.LLMResponse{
			Text:    "Step 1: Check VPN tunnel. Step 2: Verify certificates.",
			ModelID: "test-model",
		},
	}

	assistant := troubleshoot.NewAssistant(llm, kbSvc, nil)
	resp, err := assistant.Respond(context.Background(), tenantID, "VPN not working", "My VPN keeps disconnecting")
	if err != nil {
		t.Fatal(err)
	}

	if !resp.AIGenerated {
		t.Fatal("expected AI-generated response")
	}
	if resp.Content == "" {
		t.Fatal("expected non-empty content")
	}
	// The tenant ID must reach the provider so the guardrails and the
	// shared inference pool attribute / fair-queue per tenant rather
	// than collapsing every troubleshoot call onto uuid.Nil.
	if llm.gotTenant != tenantID {
		t.Fatalf("LLM tenant on context = %v, want %v", llm.gotTenant, tenantID)
	}
}

func TestAssistant_Respond_FallbackTemplate(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	kbSvc := troubleshoot.NewKBService(kbRepo)

	// No LLM provider — should fall back to template.
	assistant := troubleshoot.NewAssistant(nil, kbSvc, nil)
	resp, err := assistant.Respond(context.Background(), tenantID, "Policy issue", "Rules not applying")
	if err != nil {
		t.Fatal(err)
	}

	if resp.AIGenerated {
		t.Fatal("expected non-AI-generated response for nil LLM")
	}
	if resp.Content == "" {
		t.Fatal("expected non-empty template content")
	}
}

func TestAssistant_Respond_LLMError_FallsBack(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	kbSvc := troubleshoot.NewKBService(kbRepo)

	llm := &mockLLMProvider{
		err: context.DeadlineExceeded,
	}

	assistant := troubleshoot.NewAssistant(llm, kbSvc, nil)
	resp, err := assistant.Respond(context.Background(), tenantID, "Issue", "Help")
	if err != nil {
		t.Fatal(err)
	}

	if resp.AIGenerated {
		t.Fatal("expected fallback response when LLM errors")
	}
	if resp.Content == "" {
		t.Fatal("expected non-empty fallback content")
	}
}
