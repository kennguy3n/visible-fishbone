// Package routenorm provides a single, shared implementation of
// HTTP path-template normalisation. High-cardinality path segments
// — UUIDs and purely numeric IDs — are collapsed to a fixed ":id"
// token so that observability labels (Prometheus `path`, tracing
// span names / `http.route`) stay proportional to the number of
// route templates (a few dozen) rather than the number of
// tenants/devices (tens of thousands).
//
// It lives in its own leaf package so both the metrics middleware
// and the tracing middleware can share one tested implementation
// without creating a dependency between those two packages.
package routenorm

import "strings"

// Normalize rewrites a request path into a bounded route template,
// replacing each variable (UUID or all-digit) segment with ":id".
//
// It is allocation-light: the input is returned unchanged when no
// segment needs rewriting (the common case for static routes); a
// new string is only built when at least one variable segment is
// present.
func Normalize(path string) string {
	if path == "" || path == "/" {
		return path
	}
	segs := strings.Split(path, "/")
	rewrote := false
	for i, seg := range segs {
		if isVariableSegment(seg) {
			segs[i] = ":id"
			rewrote = true
		}
	}
	if !rewrote {
		return path
	}
	return strings.Join(segs, "/")
}

// isVariableSegment reports whether a single path segment looks
// like a high-cardinality identifier: an all-digit ID or a
// canonical hyphenated UUID.
func isVariableSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] < '0' || seg[i] > '9' {
			return isHyphenatedUUID(seg)
		}
	}
	return true // all digits
}

// isHyphenatedUUID reports whether s is a canonical 8-4-4-4-12
// hyphenated UUID. Avoids a regexp / google/uuid parse on the hot
// path.
func isHyphenatedUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
