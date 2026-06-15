package threatfeed

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// DegradedSource yields the managed threat-content engine's current
// degraded state: true when the last refresh kept serving the last good
// bundle because it could not produce a complete fresh result (every
// upstream down). *Engine satisfies it via Degraded().
type DegradedSource interface {
	Degraded() bool
}

// RegisterDegradedMetric constructs and registers the
// sng_threatcontent_degraded gauge against reg, reporting src's degraded
// state at scrape time (a GaugeFunc, so no background goroutine and no
// sampling lag — the value is always current as of the scrape).
//
// The gauge reads 1 while the engine is serving the last good bundle
// because the latest refresh produced no indicators, and 0 when healthy
// or while the kill switch is off. Ingestion runs only on the elected
// leader, so alert on the fleet maximum (max(sng_threatcontent_degraded)
// == 1) to catch the one replica that actually produces content.
//
// namespace defaults to "sng" when empty so the exported series reads
// sng_threatcontent_degraded, matching the other control-plane metrics.
// A nil registerer or nil source is a no-op (returns nil) so the caller
// can wire it unconditionally. If an equivalent gauge is already
// registered (e.g. two engines share a registry) the existing
// registration is kept rather than returning an error. This mirrors the
// leader.WithTransitionsMetric registration convention: a domain
// service self-registers its metric against the shared registry
// (exposed by metrics.Metrics.Registry) instead of widening the central
// Metrics struct.
func RegisterDegradedMetric(reg prometheus.Registerer, namespace string, src DegradedSource) error {
	if reg == nil || src == nil {
		return nil
	}
	if namespace == "" {
		namespace = "sng"
	}
	g := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "threatcontent",
		Name:      "degraded",
		Help:      "1 when the managed threat-content engine is serving the last good bundle because the latest refresh produced no indicators (every upstream down); 0 when healthy or disabled. Scoped to the elected leader, which runs ingestion.",
	}, func() float64 {
		if src.Degraded() {
			return 1
		}
		return 0
	})
	if err := reg.Register(g); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			return nil
		}
		return err
	}
	return nil
}
