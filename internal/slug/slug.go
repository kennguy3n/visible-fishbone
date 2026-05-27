// Package slug provides URL-safe slug derivation and validation
// shared by services that need DNS-label-safe identifiers (tenants,
// sites, etc.). Centralising the logic eliminates the duplicate
// implementations that previously lived in the tenant and site
// service packages.
//
// Algorithm: lowercase the input, collapse runs of non-[a-z0-9]
// chars into single hyphens, trim leading/trailing hyphens, cap at
// 63 bytes (DNS label max). This mirrors sn360-security-platform's
// DeriveSlug convention.
package slug

import (
	"regexp"
	"strings"
)

// alnumRun matches runs of non-lowercase-alphanumeric chars.
var alnumRun = regexp.MustCompile(`[^a-z0-9]+`)

// validFormat validates a caller-supplied slug (DNS-label-safe).
var validFormat = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// MaxLen is the maximum length of a slug (DNS label compat).
const MaxLen = 63

// Derive projects a free-form name into a URL-safe slug.
func Derive(name string) string {
	s := strings.Trim(alnumRun.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > MaxLen {
		s = strings.TrimRight(s[:MaxLen], "-")
	}
	return s
}

// IsValid reports whether s is a well-formed slug: 1–63 bytes,
// lowercase alphanumeric + hyphens, no leading/trailing/consecutive
// hyphens.
func IsValid(s string) bool {
	if s == "" || len(s) > MaxLen || strings.Contains(s, "--") {
		return false
	}
	return validFormat.MatchString(s)
}
