package hibernation

import "github.com/prometheus/client_golang/prometheus"

// Metrics is the hibernation controller's Prometheus surface. It proves
// the cost/efficiency curve moved: a rising hibernated_tenants gauge and
// hibernate_total counter show dormant trials being parked, and the
// sampled_events_total counter (by traffic class) shows the telemetry
// the parked tenants would otherwise have written being shed — while
// inspect_full stays absent from the shed set because the sampler's 1:1
// floor keeps it. wake_latency_seconds proves the wake SLA.
//
// Metrics is constructed against the shared metrics registry (mirroring
// leader.WithTransitionsMetric) and is nil-safe: a nil *Metrics makes
// every record method a no-op, so the controller/coordinator run
// uninstrumented when metrics are disabled.
type Metrics struct {
	hibernatedTenants prometheus.Gauge
	hibernateTotal    prometheus.Counter
	wakeTotal         prometheus.Counter
	hibernateFailures prometheus.Counter
	wakeLatency       prometheus.Histogram
	sampledEvents     *prometheus.CounterVec
}

// NewMetrics registers the hibernation collectors against reg under the
// given namespace and "hibernation" subsystem. A nil reg returns nil so
// callers can wire metrics unconditionally and degrade to a no-op when
// the metrics subsystem is disabled.
func NewMetrics(reg prometheus.Registerer, namespace string) *Metrics {
	if reg == nil {
		return nil
	}
	if namespace == "" {
		namespace = "sng"
	}
	f := promauto(reg)
	return &Metrics{
		hibernatedTenants: f.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "hibernated_tenants",
			Help:      "Number of tenants currently in scale-to-zero hibernation.",
		}),
		hibernateTotal: f.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "hibernate_total",
			Help:      "Total tenant hibernate transitions performed by the controller.",
		}),
		wakeTotal: f.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "wake_total",
			Help:      "Total tenant wake transitions (controller backstop + activity-triggered).",
		}),
		hibernateFailures: f.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "hibernate_failures_total",
			Help:      "Total hibernate attempts that errored and left the tenant active (fail-safe).",
		}),
		wakeLatency: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "wake_latency_seconds",
			Help:      "Latency from observing activity for a hibernated tenant to full rehydration.",
			Buckets:   prometheus.ExponentialBucketsRange(0.001, 10, 12),
		}),
		sampledEvents: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "hibernation",
			Name:      "sampled_events_total",
			Help:      "Resolver decisions: telemetry events for a hibernated tenant for which the near-zero hibernation sample rate was returned, by traffic class. This counts decisions at the resolver, NOT events actually shed: the inspect_full label still appears here, but those events are recaptured at full 1:1 fidelity by the sampler's mandatory floor downstream and are never dropped.",
		}, []string{"traffic_class"}),
	}
}

// promauto is a tiny local factory mirroring promauto.With so each
// collector is registered at construction and a duplicate registration
// fails fast (the same contract the mx package relies on).
func promauto(reg prometheus.Registerer) promautoFactory { return promautoFactory{reg} }

type promautoFactory struct{ reg prometheus.Registerer }

func (f promautoFactory) NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	c := prometheus.NewGauge(opts)
	f.reg.MustRegister(c)
	return c
}

func (f promautoFactory) NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	f.reg.MustRegister(c)
	return c
}

func (f promautoFactory) NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	c := prometheus.NewHistogram(opts)
	f.reg.MustRegister(c)
	return c
}

func (f promautoFactory) NewCounterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labels)
	f.reg.MustRegister(c)
	return c
}

func (m *Metrics) setHibernatedCount(n int) {
	if m == nil {
		return
	}
	m.hibernatedTenants.Set(float64(n))
}

func (m *Metrics) incHibernate() {
	if m == nil {
		return
	}
	m.hibernateTotal.Inc()
}

func (m *Metrics) incWake() {
	if m == nil {
		return
	}
	m.wakeTotal.Inc()
}

func (m *Metrics) incHibernateFailure() {
	if m == nil {
		return
	}
	m.hibernateFailures.Inc()
}

func (m *Metrics) observeWakeLatency(seconds float64) {
	if m == nil {
		return
	}
	m.wakeLatency.Observe(seconds)
}

func (m *Metrics) observeSampledEvent(trafficClass string) {
	if m == nil {
		return
	}
	if trafficClass == "" {
		trafficClass = "unknown"
	}
	m.sampledEvents.WithLabelValues(trafficClass).Inc()
}
