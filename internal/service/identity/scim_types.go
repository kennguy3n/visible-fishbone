package identity

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// SCIM 2.0 schema URIs per RFC 7643.
const (
	SCIMSchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMSchemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMSchemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SCIMSchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// SCIMName represents the SCIM name complex attribute.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// SCIMEmail represents one email in the SCIM emails multi-valued attribute.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMUser is the SCIM 2.0 User resource (RFC 7643 §4.1).
type SCIMUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        SCIMName    `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Active      *bool       `json:"active,omitempty"`

	Meta *SCIMMeta `json:"meta,omitempty"`
}

// SCIMGroupMember represents one member in a SCIM Group.
type SCIMGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMGroup is the SCIM 2.0 Group resource (RFC 7643 §4.2).
type SCIMGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members,omitempty"`

	Meta *SCIMMeta `json:"meta,omitempty"`
}

// SCIMMeta is the standard SCIM meta sub-attribute.
type SCIMMeta struct {
	ResourceType string `json:"resourceType,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	// Version is the resource's weak ETag (RFC 7644 §3.14), surfaced
	// both here and in the HTTP ETag header for optimistic concurrency.
	Version string `json:"version,omitempty"`
}

// SCIMListResponse is the SCIM 2.0 list response (RFC 7644 §3.4.2).
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// SCIMPatchOp is a single SCIM PATCH operation (RFC 7644 §3.5.2).
type SCIMPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// SCIMPatchRequest wraps the PatchOp envelope.
type SCIMPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// SCIMError is the SCIM 2.0 error response (RFC 7644 §3.12).
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// --- SCIM filter parser ---------------------------------------------------

// SCIMFilterOp enumerates the supported SCIM filter operators.
type SCIMFilterOp string

const (
	SCIMFilterEq SCIMFilterOp = "eq"
	SCIMFilterCo SCIMFilterOp = "co"
	SCIMFilterSw SCIMFilterOp = "sw"
)

// SCIMFilter is a parsed single-attribute SCIM filter expression.
type SCIMFilter struct {
	Attribute string
	Op        SCIMFilterOp
	Value     string
}

// ParseSCIMFilter parses simple SCIM filter expressions of the form
// `attribute op "value"`. Only single-clause filters with eq, co, sw
// are supported — this covers the IdP provisioning patterns (Okta,
// Azure AD, OneLogin all use `userName eq "x"` for dedup lookups).
// Compound filters (using `and`/`or`) are rejected with a clear error.
func ParseSCIMFilter(raw string) (SCIMFilter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SCIMFilter{}, fmt.Errorf("empty filter")
	}

	// Reject compound filters — we only support single-clause.
	lower := strings.ToLower(raw)
	for _, keyword := range []string{" and ", " or "} {
		// Only check outside of quoted values by looking for the
		// keyword after the closing quote of the first clause.
		idx := strings.Index(lower, keyword)
		if idx < 0 {
			continue
		}
		// Count quotes before the keyword — if even, it's outside a value.
		if strings.Count(raw[:idx], "\"")%2 == 0 {
			return SCIMFilter{}, fmt.Errorf("compound filters are not supported; only single-clause filters (eq, co, sw) are accepted")
		}
	}

	// Split into exactly 3 tokens: attr op "value"
	parts := strings.SplitN(raw, " ", 3)
	if len(parts) < 3 {
		return SCIMFilter{}, fmt.Errorf("malformed filter: expected 'attribute op value', got %q", raw)
	}

	attr := parts[0]
	op := SCIMFilterOp(strings.ToLower(parts[1]))
	valRaw := parts[2]

	switch op {
	case SCIMFilterEq, SCIMFilterCo, SCIMFilterSw:
	default:
		return SCIMFilter{}, fmt.Errorf("unsupported filter operator %q", parts[1])
	}

	// Strip surrounding quotes.
	val := strings.TrimSpace(valRaw)
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}

	return SCIMFilter{Attribute: attr, Op: op, Value: val}, nil
}

// MatchUser reports whether a user matches this filter expression.
func (f SCIMFilter) MatchUser(u SCIMUser) bool {
	var field string
	switch strings.ToLower(f.Attribute) {
	case "username":
		field = u.UserName
	case "displayname":
		field = u.DisplayName
	case "externalid":
		field = u.ExternalID
	default:
		// Primary email for "emails.value".
		if strings.EqualFold(f.Attribute, "emails.value") || strings.EqualFold(f.Attribute, "email") {
			for _, e := range u.Emails {
				if e.Primary {
					field = e.Value
					break
				}
			}
			if field == "" && len(u.Emails) > 0 {
				field = u.Emails[0].Value
			}
		}
	}
	return matchOp(f.Op, field, f.Value)
}

// MatchGroup reports whether a group matches this filter expression.
func (f SCIMFilter) MatchGroup(g SCIMGroup) bool {
	var field string
	switch strings.ToLower(f.Attribute) {
	case "displayname":
		field = g.DisplayName
	case "externalid":
		field = g.ExternalID
	}
	return matchOp(f.Op, field, f.Value)
}

func matchOp(op SCIMFilterOp, field, value string) bool {
	fl := strings.ToLower(field)
	vl := strings.ToLower(value)
	switch op {
	case SCIMFilterEq:
		return fl == vl
	case SCIMFilterCo:
		return strings.Contains(fl, vl)
	case SCIMFilterSw:
		return strings.HasPrefix(fl, vl)
	}
	return false
}

// --- Helpers --------------------------------------------------------------

// boolPtr returns a pointer to a bool value.
func boolPtr(v bool) *bool { return &v }

// uuidFromString parses a string into a uuid or returns Nil.
func uuidFromString(s string) uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return u
}
