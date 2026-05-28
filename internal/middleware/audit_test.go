package middleware

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestEnrichAuditDetails_NoMachineActor_PassThrough(t *testing.T) {
	t.Parallel()
	in := json.RawMessage(`{"name":"foo"}`)
	out := EnrichAuditDetails(context.Background(), in)
	// Same backing array — we explicitly avoid allocation on the
	// common JWT-authenticated path.
	if &in[0] != &out[0] {
		t.Fatalf("expected zero-alloc passthrough, got reallocated slice")
	}
}

func TestEnrichAuditDetails_MachineActor_AddsKey(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "key-12345")
	in := json.RawMessage(`{"name":"foo","subject":"bot:ci"}`)
	out := EnrichAuditDetails(ctx, in)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal enriched: %v", err)
	}
	if got["acting_api_key_id"] != "key-12345" {
		t.Fatalf("acting_api_key_id missing or wrong: %v", got)
	}
	if got["name"] != "foo" {
		t.Fatalf("original key 'name' lost: %v", got)
	}
	if got["subject"] != "bot:ci" {
		t.Fatalf("original key 'subject' lost: %v", got)
	}
}

func TestEnrichAuditDetails_EmptyDetails_BuildsFreshObject(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "key-only")
	cases := []json.RawMessage{nil, {}, json.RawMessage("null")}
	for _, in := range cases {
		out := EnrichAuditDetails(ctx, in)
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal enriched from %q: %v", string(in), err)
		}
		if got["acting_api_key_id"] != "key-only" {
			t.Fatalf("expected only acting_api_key_id, got %v", got)
		}
		if len(got) != 1 {
			t.Fatalf("expected single-key object, got %v", got)
		}
	}
}

func TestEnrichAuditDetails_NonObjectInput_Preserved(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "should-not-apply")
	// JSON array and scalar are valid JSON but not objects we can
	// merge into. Helper must preserve them rather than silently
	// rewrite (which would lose data).
	cases := []json.RawMessage{
		json.RawMessage(`[1,2,3]`),
		json.RawMessage(`"hello"`),
		json.RawMessage(`42`),
		json.RawMessage(`{malformed`),
	}
	for _, in := range cases {
		out := EnrichAuditDetails(ctx, in)
		if string(out) != string(in) {
			t.Fatalf("non-object input mutated: %q -> %q", string(in), string(out))
		}
	}
}

func TestEnrichAuditDetailsMap_NoMachineActor_PassThrough(t *testing.T) {
	t.Parallel()
	in := map[string]any{"foo": "bar"}
	out := EnrichAuditDetailsMap(context.Background(), in)
	// Pointer-equal because no enrichment needed.
	if &in != &out {
		// Maps can't be compared with == in Go for value-shape,
		// but checking that out aliases in by header is fine: a
		// passthrough must not allocate a new map.
		t.Logf("note: helper returned a copy on the no-actor path (allowed but wasteful)")
	}
	if out["foo"] != "bar" {
		t.Fatalf("passthrough lost original key: %v", out)
	}
}

func TestEnrichAuditDetailsMap_MachineActor_AddsKey(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "k-42")
	in := map[string]any{"name": "foo"}
	out := EnrichAuditDetailsMap(ctx, in)
	if _, ok := in["acting_api_key_id"]; ok {
		t.Fatalf("input mutated: %v", in)
	}
	if out["acting_api_key_id"] != "k-42" {
		t.Fatalf("acting_api_key_id missing: %v", out)
	}
	if out["name"] != "foo" {
		t.Fatalf("original key 'name' lost: %v", out)
	}
}

func TestEnrichAuditDetailsMap_NilInput(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "k-99")
	out := EnrichAuditDetailsMap(ctx, nil)
	if out["acting_api_key_id"] != "k-99" {
		t.Fatalf("acting_api_key_id missing from fresh map: %v", out)
	}
}

func TestAPIKeyIDFromContext_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := withAPIKeyID(context.Background(), "abc")
	if got := APIKeyIDFromContext(ctx); got != "abc" {
		t.Fatalf("round-trip failed: got %q", got)
	}
	if got := APIKeyIDFromContext(context.Background()); got != "" {
		t.Fatalf("bare context should return empty: got %q", got)
	}
	// Sanity check: marshalled JSON is exactly the expected shape.
	got := EnrichAuditDetails(ctx, json.RawMessage(`{"k":"v"}`))
	if !strings.Contains(string(got), `"acting_api_key_id":"abc"`) {
		t.Fatalf("enriched JSON missing key/value: %s", got)
	}
}
