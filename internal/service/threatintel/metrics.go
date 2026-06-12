package threatintel

import (
	"sync"
	"time"
)

// metrics tracks per-service pipeline telemetry. Safe for concurrent
// use; RefreshOnce may be called from the Run loop and (in tests)
// directly.
type metrics struct {
	mu              sync.Mutex
	refreshes       int64
	publishes       int64
	lastPublishAt   time.Time
	lastSerial      int64
	lastBundleBytes int
	perSource       map[string]*SourceStat
}

// SourceStat is the public per-source telemetry snapshot.
type SourceStat struct {
	Fetches       int64
	Failures      int64
	LastFetchAt   time.Time
	LastSuccessAt time.Time
}

// Stats is the public pipeline telemetry snapshot.
type Stats struct {
	Refreshes       int64
	Publishes       int64
	LastPublishAt   time.Time
	LastSerial      int64
	LastBundleBytes int
	PerSource       map[string]SourceStat
}

func (m *metrics) recordFetch(source string, ok bool, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.perSource == nil {
		m.perSource = map[string]*SourceStat{}
	}
	st := m.perSource[source]
	if st == nil {
		st = &SourceStat{}
		m.perSource[source] = st
	}
	st.Fetches++
	st.LastFetchAt = at
	if ok {
		st.LastSuccessAt = at
	} else {
		st.Failures++
	}
}

func (m *metrics) recordRefresh() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshes++
}

func (m *metrics) recordPublish(serial int64, bundleBytes int, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publishes++
	m.lastPublishAt = at
	m.lastSerial = serial
	m.lastBundleBytes = bundleBytes
}

func (m *metrics) snapshot() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	per := make(map[string]SourceStat, len(m.perSource))
	for k, v := range m.perSource {
		per[k] = *v
	}
	return Stats{
		Refreshes:       m.refreshes,
		Publishes:       m.publishes,
		LastPublishAt:   m.lastPublishAt,
		LastSerial:      m.lastSerial,
		LastBundleBytes: m.lastBundleBytes,
		PerSource:       per,
	}
}
