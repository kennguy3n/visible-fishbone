package middleware

import (
	"context"
	"encoding/json"
)

// EnrichAuditDetails merges machine-actor metadata from ctx into
// the JSON details blob persisted on an audit_log row. Today this
// stamps `acting_api_key_id` whenever the request was authenticated
// via API key (auth middleware sets it via withAPIKeyID).
//
// Motivation: the audit_log.actor_id column holds a *user* UUID
// and is NULL for machine-to-machine API-key authentication —
// API keys are not user identities. Operators inspecting the audit
// log without this enrichment cannot tell which key created or
// revoked a resource (and so cannot trace a compromised key back
// to its actions). Threading the key ID into the details payload
// preserves the user-UUID semantics of `actor_id` while still
// recording the machine actor for post-hoc forensics.
//
// The helper is intentionally JSON-RawMessage-shaped because four
// of the five non-policy services (tenant, webhook, rbac, site,
// identity) already pre-marshal details to RawMessage at the call
// site; threading the enrichment in at the appendAudit boundary
// minimises diff to those services. Services whose appendAudit
// builds a `map[string]any` (apikey, policy/keys) inject the same
// key directly into the map before marshalling.
//
// Behaviour contract:
//
//   - If `details` is nil or empty, returns a fresh JSON object
//     containing only the enrichment keys (or `{}` if no
//     enrichment applies).
//   - If `details` is not valid JSON, returns it unchanged — the
//     caller's marshalling presumably already passed validation,
//     so this is a defensive guard against future callers
//     accidentally passing partial JSON.
//   - If no machine-actor context is set, returns `details`
//     unchanged.
//
// The helper allocates only when enrichment actually applies; the
// common JWT-authenticated case is a zero-cost early return.
func EnrichAuditDetails(ctx context.Context, details json.RawMessage) json.RawMessage {
	keyID := APIKeyIDFromContext(ctx)
	if keyID == "" {
		return details
	}
	// Decode-modify-encode round trip. `json.RawMessage` is a
	// `[]byte` alias so we can't merge symbolically without
	// parsing; doing it here keeps the per-service appendAudit
	// helpers free of any JSON-merging logic.
	var obj map[string]any
	if len(details) == 0 || string(details) == "null" {
		obj = make(map[string]any, 1)
	} else {
		if err := json.Unmarshal(details, &obj); err != nil || obj == nil {
			// Either the caller passed something that isn't a JSON
			// object (an array, a scalar) or a malformed blob. We
			// prefer to keep their original payload over silently
			// rewriting it; operators chasing missing
			// acting_api_key_id should look upstream.
			return details
		}
	}
	obj["acting_api_key_id"] = keyID
	merged, err := json.Marshal(obj)
	if err != nil {
		// Marshal failure on a map we just unmarshalled would
		// indicate value types JSON can't represent. Fall back to
		// the original to avoid losing the audit row entirely.
		return details
	}
	return merged
}

// EnrichAuditDetailsMap is the map-shaped sibling of
// EnrichAuditDetails for services whose appendAudit accepts a
// `map[string]any` instead of a pre-marshalled RawMessage. Mutates
// nothing on the input; callers pass the returned map to
// json.Marshal.
func EnrichAuditDetailsMap(ctx context.Context, details map[string]any) map[string]any {
	keyID := APIKeyIDFromContext(ctx)
	if keyID == "" {
		return details
	}
	out := make(map[string]any, len(details)+1)
	for k, v := range details {
		out[k] = v
	}
	out["acting_api_key_id"] = keyID
	return out
}
