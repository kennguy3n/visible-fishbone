// Package stats holds the small read-side result types the
// telemetry subsystem produces for operator-facing aggregations.
//
// The types live in a neutral package below both the handler
// (`internal/handler`) and the storage backend
// (`internal/service/telemetry/clickhouse`) so the handler can
// state its read-side contract without importing the storage
// driver and so the storage driver can produce typed results
// without round-tripping through a hand-written adapter shim.
//
// Layering:
//
//	internal/handler  ─┐
//	                   ├──► internal/service/telemetry/stats
//	internal/service/telemetry/clickhouse ──┘
//
// Both depend on stats; neither depends on the other. This is
// the structural shape that eliminates the
// `clickhouseStatsAdapter` shim that previously lived in
// cmd/sng-control/main.go.
package stats

// TrafficClassCount is one row of the per-class flow
// distribution returned by a telemetry-backend
// QueryTrafficClassDistribution call.
//
// Used by the operator UI to render the cost-attribution chart
// (per-class event volume and per-class byte totals over a
// rolling window).
type TrafficClassCount struct {
	// Class is the traffic_class label (one of the closed-set
	// values in repository.AllTrafficClasses:
	// trusted_direct | trusted_media_bypass | inspect_lite |
	// inspect_full | tunnel_private | block).
	Class string `json:"class"`
	// Events is the total number of telemetry events recorded
	// for the class in the requested window.
	Events uint64 `json:"events"`
	// Bytes is the sum of bytes_in + bytes_out across flow
	// events for the class. Zero when the window contained no
	// FlowEvents (DNS / HTTP / IPS event classes do not carry
	// the bytes-in / bytes-out columns).
	Bytes uint64 `json:"bytes"`
}
