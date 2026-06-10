package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- meta.version / ETag (RFC 7644 §3.14) --------------------------------
//
// Every resource carries a weak ETag in meta.version derived from a
// stable hash of its identifying + mutable state. A weak validator
// ("W/") is correct here: the version tracks the resource's logical
// state, not a byte-exact serialisation (attribute projection or
// key ordering must not change it). Clients use the value for
// optimistic concurrency (If-Match) and caching (If-None-Match).

// scimUserVersion computes the meta.version ETag for a user. It folds
// in every field a SCIM client can observe or mutate plus the
// monotonic UpdatedAt, so any provisioning change rotates the version.
func scimUserVersion(u repository.User) string {
	h := sha256.New()
	fmt.Fprintf(h, "user|%s|%s|%s|%s|%s|%d",
		u.ID, u.Email, u.Name, u.ExternalID, u.Status, u.UpdatedAt.UnixNano())
	return weakETag(h.Sum(nil))
}

// scimGroupVersion computes the meta.version ETag for a group (role).
// Roles have no UpdatedAt column, so the hash folds the mutable
// name/externalId alongside the id; a rename or externalId change
// rotates the version.
func scimGroupVersion(r repository.Role) string {
	h := sha256.New()
	fmt.Fprintf(h, "group|%s|%s|%s", r.ID, r.Name, r.ExternalID)
	return weakETag(h.Sum(nil))
}

func weakETag(sum []byte) string {
	return `W/"` + hex.EncodeToString(sum[:16]) + `"`
}

// resourceVersion extracts meta.version from a SCIM resource (the typed
// SCIMUser/SCIMGroup the service emits). Returns "" when the resource
// carries no version.
func resourceVersion(resource any) string {
	switch r := resource.(type) {
	case SCIMUser:
		if r.Meta != nil {
			return r.Meta.Version
		}
	case SCIMGroup:
		if r.Meta != nil {
			return r.Meta.Version
		}
	}
	return ""
}

// etagMatches reports whether a client-supplied If-Match / If-None-Match
// header value matches the resource's current version. It honours the
// "*" wildcard (any existing resource matches) and tolerates the weak
// "W/" prefix being present or absent on either side, since clients
// echo the value back inconsistently.
func etagMatches(header, version string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		if normalizeETag(candidate) == normalizeETag(version) {
			return true
		}
	}
	return false
}

func normalizeETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	s = strings.TrimPrefix(s, "w/")
	return strings.Trim(s, `"`)
}

// ResourceVersion returns the meta.version ETag of a SCIM resource the
// service emitted, or "" if it carries none. Exposed for the HTTP layer
// to populate the ETag response header and evaluate preconditions.
func ResourceVersion(resource any) string { return resourceVersion(resource) }

// ETagMatches reports whether an If-Match / If-None-Match header value
// matches a resource version, honouring the "*" wildcard and the weak
// "W/" prefix. Exposed for the HTTP layer's conditional-request checks.
func ETagMatches(header, version string) bool { return etagMatches(header, version) }

// ProjectResource applies the SCIM attributes / excludedAttributes query
// parameters to a resource for the HTTP layer (RFC 7644 §3.9).
func ProjectResource(resource any, attributes, excluded []string) any {
	return projectResource(resource, attributes, excluded)
}

// ParseAttributeList splits a comma-separated attributes /
// excludedAttributes query parameter for the HTTP layer.
func ParseAttributeList(raw string) []string { return parseAttributeList(raw) }

// --- attributes / excludedAttributes projection (RFC 7644 §3.9) ----------

// projectResource applies the SCIM `attributes` / `excludedAttributes`
// query parameters to a single resource, returning a map ready for JSON
// encoding. Exactly one of the two parameters should be set (RFC 7644
// §3.9 makes them mutually exclusive); when both are empty the resource
// is returned unchanged.
//
// `id` and `schemas` have returned="always" and are never removed, even
// when excluded or omitted from an `attributes` list. Matching is
// case-insensitive and ignores schema-URN prefixes. Sub-attribute paths
// (e.g. "name.givenName") project at their top-level container
// ("name"), which is the common server behaviour and keeps complex
// attributes intact.
func projectResource(resource any, attributes, excluded []string) any {
	if len(attributes) == 0 && len(excluded) == 0 {
		return resource
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		return resource
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return resource
	}

	if len(attributes) > 0 {
		want := topLevelSet(attributes)
		// returned=always attributes are included regardless.
		want["id"] = struct{}{}
		want["schemas"] = struct{}{}
		for k := range m {
			if _, keep := want[strings.ToLower(k)]; !keep {
				delete(m, k)
			}
		}
		return m
	}

	// excludedAttributes path.
	drop := topLevelSet(excluded)
	delete(drop, "id")      // returned=always
	delete(drop, "schemas") // returned=always
	for k := range m {
		if _, remove := drop[strings.ToLower(k)]; remove {
			delete(m, k)
		}
	}
	return m
}

// topLevelSet normalises a list of SCIM attribute paths to a set of
// lower-cased top-level attribute names, stripping schema-URN prefixes
// and reducing sub-attribute paths to their container.
func topLevelSet(attrs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(attrs))
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		// Strip a leading schema URN ("urn:...:User:userName").
		if i := strings.LastIndex(a, ":"); i >= 0 {
			a = a[i+1:]
		}
		// Reduce a sub-attribute path to its top-level container.
		if i := strings.Index(a, "."); i >= 0 {
			a = a[:i]
		}
		out[strings.ToLower(a)] = struct{}{}
	}
	return out
}

// parseAttributeList splits a comma-separated SCIM attributes /
// excludedAttributes query parameter into trimmed, non-empty entries.
func parseAttributeList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
