package identity

import (
	"context"
	"encoding/json"
	"testing"
)

// TestBulkCreateResolvesBulkIDReferences exercises the core bulk flow: a
// POST with a client bulkId, then a PATCH that addresses the just-created
// user by its server id resolved from that bulkId.
func TestBulkCreateResolvesBulkIDReferences(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)

	userData, _ := json.Marshal(SCIMUser{
		Schemas:  []string{SCIMSchemaUser},
		UserName: "bulk@example.com",
		Active:   boolPtr(true),
	})
	patchData, _ := json.Marshal(SCIMPatchRequest{
		Schemas: []string{SCIMSchemaPatch},
		Operations: []SCIMPatchOp{{
			Op:    "replace",
			Path:  "displayName",
			Value: "Bulk User",
		}},
	})

	resp, err := svc.Bulk(context.Background(), tid, SCIMBulkRequest{
		Schemas: []string{SCIMSchemaBulkRequest},
		Operations: []SCIMBulkOperation{
			{Method: "POST", Path: "/Users", BulkID: "u1", Data: userData},
			{Method: "PATCH", Path: "/Users/bulkId:u1", Data: patchData},
		},
	})
	if err != nil {
		t.Fatalf("Bulk: %v", err)
	}
	if len(resp.Operations) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Operations))
	}
	if resp.Operations[0].Status != "201" {
		t.Errorf("POST status = %s, want 201 (%+v)", resp.Operations[0].Status, resp.Operations[0].Response)
	}
	if resp.Operations[1].Status != "200" {
		t.Errorf("PATCH status = %s, want 200 (%+v)", resp.Operations[1].Status, resp.Operations[1].Response)
	}
}

// TestBulkVersionPreconditionEnforced verifies that an operation's
// "version" (the bulk If-Match precondition, RFC 7644 §3.7.1) is
// enforced: a stale version yields 412 and leaves the resource
// unchanged, while the current version is accepted.
func TestBulkVersionPreconditionEnforced(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()

	created, err := svc.CreateUser(ctx, tid, SCIMUser{
		Schemas:  []string{SCIMSchemaUser},
		UserName: "ver@example.com",
		Active:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	currentVersion := created.Meta.Version
	if currentVersion == "" {
		t.Fatal("expected created user to carry a meta.version")
	}

	patchData, _ := json.Marshal(SCIMPatchRequest{
		Schemas: []string{SCIMSchemaPatch},
		Operations: []SCIMPatchOp{{
			Op:    "replace",
			Path:  "displayName",
			Value: "Renamed",
		}},
	})

	// Stale precondition -> 412, no mutation.
	stale, err := svc.Bulk(ctx, tid, SCIMBulkRequest{
		Schemas: []string{SCIMSchemaBulkRequest},
		Operations: []SCIMBulkOperation{{
			Method:  "PATCH",
			Path:    "/Users/" + created.ID,
			Version: `W/"deadbeefdeadbeef"`,
			Data:    patchData,
		}},
	})
	if err != nil {
		t.Fatalf("Bulk (stale): %v", err)
	}
	if stale.Operations[0].Status != "412" {
		t.Fatalf("stale version status = %s, want 412 (%+v)", stale.Operations[0].Status, stale.Operations[0].Response)
	}
	if got, _ := svc.GetUser(ctx, tid, uuidFromString(created.ID)); got.DisplayName == "Renamed" {
		t.Error("resource was mutated despite a failed precondition")
	}

	// Current precondition -> 200, mutation applied.
	fresh, err := svc.Bulk(ctx, tid, SCIMBulkRequest{
		Schemas: []string{SCIMSchemaBulkRequest},
		Operations: []SCIMBulkOperation{{
			Method:  "PATCH",
			Path:    "/Users/" + created.ID,
			Version: currentVersion,
			Data:    patchData,
		}},
	})
	if err != nil {
		t.Fatalf("Bulk (fresh): %v", err)
	}
	if fresh.Operations[0].Status != "200" {
		t.Fatalf("current version status = %s, want 200 (%+v)", fresh.Operations[0].Status, fresh.Operations[0].Response)
	}
	if got, _ := svc.GetUser(ctx, tid, uuidFromString(created.ID)); got.DisplayName != "Renamed" {
		t.Errorf("displayName = %q, want Renamed", got.DisplayName)
	}
}
