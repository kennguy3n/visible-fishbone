package dem

import (
	"sort"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ProbeKind tokens, mirroring the edge sng-dem crate's ProbeKind
// serde representation. The service validates ingested + configured
// values against this set so a typo never reaches storage.
const (
	ProbeKindDNS   = "dns"
	ProbeKindTCP   = "tcp"
	ProbeKindHTTP  = "http"
	ProbeKindHTTPS = "https"
)

// ErrorKind tokens, mirroring the crate's ProbeErrorKind. A failed
// probe always carries one of these.
const (
	ErrorKindTimeout  = "timeout"
	ErrorKindDNS      = "dns"
	ErrorKindConnect  = "connect"
	ErrorKindTLS      = "tls"
	ErrorKindHTTP     = "http"
	ErrorKindConfig   = "config"
	ErrorKindInternal = "internal"
)

// validProbeKind reports whether k is a known probe transport.
func validProbeKind(k string) bool {
	switch k {
	case ProbeKindDNS, ProbeKindTCP, ProbeKindHTTP, ProbeKindHTTPS:
		return true
	}
	return false
}

// validErrorKind reports whether k is a known failure bucket.
func validErrorKind(k string) bool {
	switch k {
	case ErrorKindTimeout, ErrorKindDNS, ErrorKindConnect,
		ErrorKindTLS, ErrorKindHTTP, ErrorKindConfig, ErrorKindInternal:
		return true
	}
	return false
}

// managedDefault is a code-defined critical SaaS target every tenant
// gets for free, so an SME configures nothing. The set is small and
// HTTPS-only on purpose: it bounds the edge probe budget (see the
// cost model in the WP5 PR) and covers the apps whose degradation an
// SME actually feels. A tenant can override or disable any of these
// by adding a custom dem_targets row with the same target_key.
type managedDefault struct {
	Key     string
	Name    string
	Kind    string
	Address string
}

// managedDefaults is the canonical default target catalog. Keep this
// list short — every entry multiplies the aggregate edge probe rate
// across all 5,000 tenants.
var managedDefaults = []managedDefault{
	{Key: "m365", Name: "Microsoft 365", Kind: ProbeKindHTTPS, Address: "https://outlook.office365.com"},
	{Key: "google_workspace", Name: "Google Workspace", Kind: ProbeKindHTTPS, Address: "https://workspace.google.com"},
	{Key: "salesforce", Name: "Salesforce", Kind: ProbeKindHTTPS, Address: "https://login.salesforce.com"},
	{Key: "zoom", Name: "Zoom", Kind: ProbeKindHTTPS, Address: "https://zoom.us"},
	{Key: "slack", Name: "Slack", Kind: ProbeKindHTTPS, Address: "https://slack.com"},
	{Key: "github", Name: "GitHub", Kind: ProbeKindHTTPS, Address: "https://github.com"},
}

// DefaultProbeIntervalSeconds / DefaultProbeTimeoutMs are the bounded
// cadence + per-probe timeout applied to the managed defaults. The
// interval is deliberately coarse (one probe per target per minute)
// to keep the fleet-wide probe rate cheap; the edge applies jitter on
// top so 5,000 agents do not fire in lockstep.
const (
	DefaultProbeIntervalSeconds = 60
	DefaultProbeTimeoutMs       = 5000
)

// ManagedDefaultTargets returns the managed default set as repository
// rows (TenantID/ID left zero — they are code-defined, not persisted).
// Returned fresh each call so callers cannot mutate the catalog.
func ManagedDefaultTargets() []repository.DEMTarget {
	out := make([]repository.DEMTarget, 0, len(managedDefaults))
	for _, d := range managedDefaults {
		out = append(out, repository.DEMTarget{
			TargetKey:       d.Key,
			Name:            d.Name,
			ProbeKind:       d.Kind,
			Address:         d.Address,
			Enabled:         true,
			IntervalSeconds: DefaultProbeIntervalSeconds,
			TimeoutMs:       DefaultProbeTimeoutMs,
		})
	}
	return out
}

// mergeEffectiveTargets overlays a tenant's custom targets onto the
// managed defaults: an enabled custom row overrides (same key) or
// adds (new key) a target; a disabled custom row removes the matching
// default (or itself). The result is sorted by target_key for a
// stable API response.
func mergeEffectiveTargets(defaults, custom []repository.DEMTarget) []repository.DEMTarget {
	byKey := make(map[string]repository.DEMTarget, len(defaults)+len(custom))
	for _, d := range defaults {
		byKey[d.TargetKey] = d
	}
	for _, c := range custom {
		if c.Enabled {
			byKey[c.TargetKey] = c
		} else {
			delete(byKey, c.TargetKey)
		}
	}
	out := make([]repository.DEMTarget, 0, len(byKey))
	for _, t := range byKey {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetKey < out[j].TargetKey })
	return out
}
