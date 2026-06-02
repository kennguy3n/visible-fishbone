package troubleshoot

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// Assistant provides RAG-based troubleshooting assistance. It
// retrieves relevant KB entries, runs diagnostics, and uses the
// LLM to generate step-by-step troubleshooting guidance.
//
// Hard invariant: the assistant CANNOT apply changes — it only suggests.
type Assistant struct {
	llm        ai.LLMProvider
	kb         *KBService
	diagnostic *DiagnosticEngine
}

// NewAssistant creates a troubleshooting assistant.
// llm may be nil — the assistant falls back to deterministic templates.
func NewAssistant(llm ai.LLMProvider, kb *KBService, diagnostic *DiagnosticEngine) *Assistant {
	return &Assistant{llm: llm, kb: kb, diagnostic: diagnostic}
}

// Respond generates a troubleshooting response for the given message
// in the context of an ongoing session. It retrieves relevant KB
// entries, optionally runs diagnostics, and generates a response.
func (a *Assistant) Respond(ctx context.Context, tenantID uuid.UUID, issue string, message string) (AssistantResponse, error) {
	// 1. Search KB for relevant entries.
	kbEntries, err := a.kb.Search(ctx, &tenantID, extractSearchTerms(issue, message), 5)
	if err != nil {
		kbEntries = nil
	}

	// 2. Run diagnostics to gather context.
	var diagnosticResults []DiagnosticResult
	if a.diagnostic != nil {
		diagnosticResults = a.diagnostic.RunAll(ctx, tenantID)
	}

	// 3. Generate response via LLM or fallback to templates.
	var content string
	var aiGenerated bool

	if a.llm != nil {
		prompt := buildPrompt(issue, message, kbEntries, diagnosticResults)
		resp, err := a.llm.Complete(ctx, ai.LLMRequest{
			Prompt:         prompt,
			TemperatureX10: 3,
			MaxTokens:      1024,
		})
		if err == nil && resp.Text != "" {
			content = resp.Text
			aiGenerated = true
		}
	}

	if content == "" {
		content = buildTemplateResponse(issue, message, kbEntries, diagnosticResults)
		aiGenerated = false
	}

	return AssistantResponse{
		Content:           content,
		ReferencedKB:      kbEntries,
		DiagnosticResults: diagnosticResults,
		AIGenerated:       aiGenerated,
	}, nil
}

func extractSearchTerms(issue, message string) string {
	combined := issue + " " + message
	combined = strings.TrimSpace(combined)
	if len(combined) > 200 {
		combined = combined[:200]
	}
	return combined
}

func buildPrompt(issue, message string, kbEntries []KBEntry, diagnostics []DiagnosticResult) string {
	var b strings.Builder
	b.WriteString("You are a network security troubleshooting assistant for the ShieldNet Gateway platform.\n")
	b.WriteString("You CANNOT apply changes — only suggest steps.\n\n")
	b.WriteString(fmt.Sprintf("Issue: %s\n", issue))
	b.WriteString(fmt.Sprintf("Operator message: %s\n\n", message))

	if len(kbEntries) > 0 {
		b.WriteString("Relevant knowledge base articles:\n")
		for _, e := range kbEntries {
			b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", e.Category, e.Title, truncateContent(e.Content, 200)))
		}
		b.WriteString("\n")
	}

	if len(diagnostics) > 0 {
		b.WriteString("Current diagnostic results:\n")
		for _, d := range diagnostics {
			b.WriteString(fmt.Sprintf("- %s: %s — %s\n", d.CheckName, d.Status, d.Message))
		}
		b.WriteString("\n")
	}

	b.WriteString("Provide a step-by-step troubleshooting guide. Be concise and actionable.")
	return b.String()
}

func buildTemplateResponse(issue, message string, kbEntries []KBEntry, diagnostics []DiagnosticResult) string {
	var b strings.Builder
	b.WriteString("## Troubleshooting Summary\n\n")

	if len(diagnostics) > 0 {
		b.WriteString("### Diagnostic Results\n\n")
		for _, d := range diagnostics {
			status := "PASS"
			switch d.Status {
			case DiagnosticFail:
				status = "FAIL"
			case DiagnosticWarn:
				status = "WARN"
			}
			b.WriteString(fmt.Sprintf("- **%s** [%s]: %s\n", d.CheckName, status, d.Message))
		}
		b.WriteString("\n")
	}

	if len(kbEntries) > 0 {
		b.WriteString("### Relevant Knowledge Base Articles\n\n")
		for _, e := range kbEntries {
			b.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", e.Title, e.Category, truncateContent(e.Content, 100)))
		}
		b.WriteString("\n")
	}

	b.WriteString("### Suggested Steps\n\n")
	b.WriteString("1. Review the diagnostic results above for any failures or warnings.\n")
	b.WriteString("2. Check the referenced knowledge base articles for resolution guidance.\n")
	b.WriteString("3. If the issue persists, consider escalating to a senior operator.\n")

	return b.String()
}

func truncateContent(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// marshalDiagnosticResults encodes diagnostic results as JSON for storage.
func marshalDiagnosticResults(results []DiagnosticResult) json.RawMessage {
	if results == nil {
		return json.RawMessage("[]")
	}
	b, err := json.Marshal(results)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// marshalMessages encodes session messages as JSON for storage.
func marshalMessages(messages []SessionMessage) json.RawMessage {
	if messages == nil {
		return json.RawMessage("[]")
	}
	b, err := json.Marshal(messages)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// unmarshalMessages decodes session messages from JSON.
func unmarshalMessages(data json.RawMessage) []SessionMessage {
	if data == nil {
		return nil
	}
	var msgs []SessionMessage
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil
	}
	return msgs
}

// unmarshalDiagnosticResults decodes diagnostic results from JSON.
func unmarshalDiagnosticResults(data json.RawMessage) []DiagnosticResult {
	if data == nil {
		return nil
	}
	var results []DiagnosticResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil
	}
	return results
}

// nowFunc returns the current UTC time — matches the package-level
// variable in diagnostic.go so session.go can share it.
var nowFunc = func() time.Time { return time.Now().UTC() }
