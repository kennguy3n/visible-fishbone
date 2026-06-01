// Package telemetry — dedup.go implements the bounded-memory LRU
// dedup layer that protects ClickHouse + S3 from rolling-window
// duplicate events.
//
// The existing dedupRing in service.go is a fixed-size hash-set
// of EventIDs keyed on the wire-format UUID. That is correct as
// a "last N events" defence in depth, but two real-world failure
// modes need a richer key:
//
//  1. **Edge-side retries replay the same envelope with the same
//     EventID across multiple delivery attempts.** The ring is
//     adequate here.
//
//  2. **An edge or agent that survives a process restart and
//     resumes from its on-disk spool re-emits previously-emitted
//     envelopes with new EventIDs but the same per-device
//     sequence number.** The ring cannot detect that, because it
//     only sees EventIDs.
//
// LRUDedup keys on (DeviceID, SequenceNumber) — the sequence
// number is monotonic per device on the producer side, so a
// replayed envelope is detectable even when its EventID is new.
// EventID remains the secondary key (we also store it on the
// LRU entry so the lookup can fall through to EventID-only on
// envelopes whose producer doesn't emit a sequence number — the
// schema version SchemaVersion=1 doesn't include one yet, and
// we plumb a Source-of-truth identifier so subsequent schema
// versions can promote the sequence number to a first-class
// envelope field without breaking the wire contract).
//
// LRUDedup is intentionally NOT a drop-in replacement for the
// dedupRing in service.go (the in-process ring is keyed by the
// older EventID and tested in concert with the dispatch path).
// New callers — the per-batch normalisation pipeline, the
// archiver's pre-flush filter, and the replay path — should use
// LRUDedup; the in-process ring remains the EventID defence in
// depth on the consumer hot path.

package telemetry

import (
	"container/list"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

// DefaultLRUDedupCapacity is the default number of (DeviceID,
// SequenceNumber) tuples LRUDedup retains in memory. 1 entry is
// ~80 bytes (uuid.UUID + uint64 + list.Element overhead), so the
// default budget sits at roughly 5 MiB per process — fine on a
// control plane that has GiB of RAM and millions of events
// per minute crossing the consumer.
const DefaultLRUDedupCapacity = 65_536

// DedupKey is the composite key used by LRUDedup.
//
// DeviceID is the producer device ID; on every Phase-2 producer
// (edge appliance, endpoint client) the device ID is set on
// boot from the device enrolment exchange.
//
// SequenceNumber is the producer's monotonic per-device counter.
// When zero, only EventID is consulted (the SchemaVersion=1
// envelope does not carry a sequence number; producers backfill
// zero so the lookup falls through to the EventID-only check).
type DedupKey struct {
	DeviceID       uuid.UUID
	SequenceNumber uint64
	EventID        uuid.UUID
}

// LRUDedup is the bounded-memory rolling-window dedup.
//
// Internal layout — doubly-linked list + map — matches the
// canonical Go LRU implementation (e.g. hashicorp/golang-lru):
// `list.Element.Value` is a *lruEntry, the map points from
// composite key to the same element. Eviction pops the back
// element when the count exceeds the capacity.
//
// Safe for concurrent use.
//
// Lock choice: sync.RWMutex (not Mutex) because `Seen` is
// invoked on the hot path before every downstream write and
// only reads from the index maps — it never mutates the LRU
// order, never calls *list.List mutators, and uses atomic
// counters for hits/misses. Concurrent `Seen` callers can
// safely fan out under RLock; `Add` / `SeenOrAdd` take the
// write lock since they touch the list or the maps; `Len`
// and `Stats` take the **read** lock — they only read
// `order.Len()` plus the atomic counters, all of which are
// safe under RLock. See PR #38 Devin Review thread on
// dedup.go:138 (round-4 ack of the RLock-safe path on Seen)
// and round-6 doc audit reconciling the comment with the
// actual lock each method takes.
type LRUDedup struct {
	mu       sync.RWMutex
	capacity int
	order    *list.List               // back = least-recent
	deviceMu map[deviceSeqKey]*list.Element
	eventMu  map[uuid.UUID]*list.Element

	hits    atomic.Uint64
	misses  atomic.Uint64
	evicted atomic.Uint64
}

// deviceSeqKey is the (device, sequence) composite — used as the
// primary key when SequenceNumber > 0. Separate from the
// EventID-only fallback so an EventID and a (device, seq) entry
// cannot accidentally collide in the map.
type deviceSeqKey struct {
	device uuid.UUID
	seq    uint64
}

type lruEntry struct {
	key      DedupKey
	hasSeq   bool
	hasEvent bool
}

// NewLRUDedup constructs a dedup with the given capacity. Capacity
// <= 0 maps to DefaultLRUDedupCapacity.
func NewLRUDedup(capacity int) *LRUDedup {
	if capacity <= 0 {
		capacity = DefaultLRUDedupCapacity
	}
	return &LRUDedup{
		capacity: capacity,
		order:    list.New(),
		deviceMu: make(map[deviceSeqKey]*list.Element, capacity),
		eventMu:  make(map[uuid.UUID]*list.Element, capacity),
	}
}

// Seen reports whether key has been recorded as already-processed
// without recording a new entry. Two key paths:
//
//   - When SequenceNumber > 0, (DeviceID, SequenceNumber) is the
//     primary lookup; EventID is consulted as a fallback so a
//     resend that arrives before the (device, seq) entry has been
//     populated is still caught.
//   - When SequenceNumber == 0, only EventID is consulted (the
//     schema-version-1 producers don't carry a sequence number).
//
// Calling Seen does NOT update the LRU ordering. Pair with Add
// after the downstream write succeeds — splitting the check
// from the insertion guarantees a transient writer failure can
// retry on the redelivered envelope rather than being silently
// dedup-suppressed.
func (d *LRUDedup) Seen(key DedupKey) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if key.SequenceNumber > 0 && key.DeviceID != uuid.Nil {
		if _, ok := d.deviceMu[deviceSeqKey{device: key.DeviceID, seq: key.SequenceNumber}]; ok {
			d.hits.Add(1)
			return true
		}
	}
	if key.EventID != uuid.Nil {
		if _, ok := d.eventMu[key.EventID]; ok {
			d.hits.Add(1)
			return true
		}
	}
	d.misses.Add(1)
	return false
}

// Add records key in the LRU. Calling Add on an already-recorded
// key promotes the entry to the front of the LRU.
//
// Eviction is LRU: when the count exceeds the capacity, the
// least-recently-Added entry is dropped. Both index maps are
// kept in sync.
//
// Returns true when the entry was newly added, false when the
// entry was already present (the caller can treat the latter as
// a no-op).
func (d *LRUDedup) Add(key DedupKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addLocked(key)
}

// SeenOrAdd combines Seen + Add into a single lock acquisition
// for callers who don't need the split-check semantic (e.g. the
// replay path, where a duplicate is unambiguously a drop).
//
// Returns true when the key was already present, false when
// freshly inserted.
func (d *LRUDedup) SeenOrAdd(key DedupKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if key.SequenceNumber > 0 && key.DeviceID != uuid.Nil {
		if elt, ok := d.deviceMu[deviceSeqKey{device: key.DeviceID, seq: key.SequenceNumber}]; ok {
			d.order.MoveToFront(elt)
			d.hits.Add(1)
			return true
		}
	}
	if key.EventID != uuid.Nil {
		if elt, ok := d.eventMu[key.EventID]; ok {
			d.order.MoveToFront(elt)
			d.hits.Add(1)
			return true
		}
	}
	d.misses.Add(1)
	d.addLocked(key)
	return false
}

// addLocked is the unlocked insertion. Caller holds d.mu.
func (d *LRUDedup) addLocked(key DedupKey) bool {
	hasSeq := key.SequenceNumber > 0 && key.DeviceID != uuid.Nil
	hasEvent := key.EventID != uuid.Nil
	if !hasSeq && !hasEvent {
		// Nothing to key on — ignore. A real envelope always
		// has an EventID, so this only triggers on
		// programming errors / synthetic test inputs.
		return false
	}
	// If either key is already present, just promote.
	if hasSeq {
		if elt, ok := d.deviceMu[deviceSeqKey{device: key.DeviceID, seq: key.SequenceNumber}]; ok {
			d.order.MoveToFront(elt)
			return false
		}
	}
	if hasEvent {
		if elt, ok := d.eventMu[key.EventID]; ok {
			d.order.MoveToFront(elt)
			return false
		}
	}
	entry := &lruEntry{key: key, hasSeq: hasSeq, hasEvent: hasEvent}
	elt := d.order.PushFront(entry)
	if hasSeq {
		d.deviceMu[deviceSeqKey{device: key.DeviceID, seq: key.SequenceNumber}] = elt
	}
	if hasEvent {
		d.eventMu[key.EventID] = elt
	}
	if d.order.Len() > d.capacity {
		d.evictOldestLocked()
	}
	return true
}

func (d *LRUDedup) evictOldestLocked() {
	back := d.order.Back()
	if back == nil {
		return
	}
	entry := back.Value.(*lruEntry)
	if entry.hasSeq {
		delete(d.deviceMu, deviceSeqKey{device: entry.key.DeviceID, seq: entry.key.SequenceNumber})
	}
	if entry.hasEvent {
		delete(d.eventMu, entry.key.EventID)
	}
	d.order.Remove(back)
	d.evicted.Add(1)
}

// Len reports the current number of entries. Read under
// RLock — `*list.List.Len()` is a single int load and the
// hot path doesn't need to coordinate with concurrent Add.
func (d *LRUDedup) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.order.Len()
}

// Capacity reports the configured maximum.
func (d *LRUDedup) Capacity() int { return d.capacity }

// Stats returns the current counter values.
func (d *LRUDedup) Stats() DedupStats {
	return DedupStats{
		Hits:     d.hits.Load(),
		Misses:   d.misses.Load(),
		Evicted:  d.evicted.Load(),
		Len:      d.Len(),
		Capacity: d.capacity,
	}
}

// DedupStats is the read-only counter snapshot.
type DedupStats struct {
	Hits     uint64
	Misses   uint64
	Evicted  uint64
	Len      int
	Capacity int
}
