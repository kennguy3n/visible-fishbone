package telemetry

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestLRUDedup_SeenAddCycle(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10)
	key := DedupKey{DeviceID: uuid.New(), SequenceNumber: 1, EventID: uuid.New()}
	if d.Seen(key) {
		t.Fatalf("freshly constructed dedup must not report Seen")
	}
	if !d.Add(key) {
		t.Fatalf("Add of a fresh key must return true")
	}
	if !d.Seen(key) {
		t.Fatalf("post-Add, Seen must return true")
	}
	if d.Add(key) {
		t.Fatalf("repeat Add must return false")
	}
}

func TestLRUDedup_SeqAndEventBothChecked(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10)
	dev := uuid.New()
	first := DedupKey{DeviceID: dev, SequenceNumber: 7, EventID: uuid.New()}
	d.Add(first)
	// Same (device, seq), different EventID — must still hit.
	replay := DedupKey{DeviceID: dev, SequenceNumber: 7, EventID: uuid.New()}
	if !d.Seen(replay) {
		t.Fatalf("(device, seq) collision must dedup even with different EventID")
	}
	// Same EventID, different device — must still hit (EventID
	// is the secondary key).
	eventCollision := DedupKey{DeviceID: uuid.New(), SequenceNumber: 99, EventID: first.EventID}
	if !d.Seen(eventCollision) {
		t.Fatalf("EventID collision must dedup even with different device")
	}
}

func TestLRUDedup_EventOnlyFallback(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10)
	// Schema-version-1 producer with SequenceNumber=0 only
	// keys on EventID.
	id := uuid.New()
	key := DedupKey{DeviceID: uuid.New(), SequenceNumber: 0, EventID: id}
	d.Add(key)
	// A new key with the same EventID but seq=0 should hit.
	if !d.Seen(DedupKey{DeviceID: uuid.New(), SequenceNumber: 0, EventID: id}) {
		t.Fatalf("EventID fallback must match")
	}
}

func TestLRUDedup_EvictsOldest(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(3)
	dev := uuid.New()
	keys := []DedupKey{
		{DeviceID: dev, SequenceNumber: 1, EventID: uuid.New()},
		{DeviceID: dev, SequenceNumber: 2, EventID: uuid.New()},
		{DeviceID: dev, SequenceNumber: 3, EventID: uuid.New()},
		{DeviceID: dev, SequenceNumber: 4, EventID: uuid.New()},
	}
	for _, k := range keys {
		d.Add(k)
	}
	if d.Len() != 3 {
		t.Fatalf("len after over-fill: got %d want 3", d.Len())
	}
	if d.Seen(keys[0]) {
		t.Fatalf("oldest entry (%v) should have been evicted", keys[0])
	}
	for _, k := range keys[1:] {
		if !d.Seen(k) {
			t.Fatalf("recent entry %v should remain", k)
		}
	}
	stats := d.Stats()
	if stats.Evicted != 1 {
		t.Fatalf("evicted counter: got %d want 1", stats.Evicted)
	}
}

func TestLRUDedup_PromoteOnSeenOrAdd(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(3)
	dev := uuid.New()
	a := DedupKey{DeviceID: dev, SequenceNumber: 1, EventID: uuid.New()}
	b := DedupKey{DeviceID: dev, SequenceNumber: 2, EventID: uuid.New()}
	c := DedupKey{DeviceID: dev, SequenceNumber: 3, EventID: uuid.New()}
	d.Add(a)
	d.Add(b)
	d.Add(c)
	// Re-touching a should promote it to the front.
	if !d.SeenOrAdd(a) {
		t.Fatalf("a should already be present")
	}
	// Adding a fourth key evicts the now-LRU b, not a.
	fourth := DedupKey{DeviceID: dev, SequenceNumber: 4, EventID: uuid.New()}
	d.Add(fourth)
	if !d.Seen(a) {
		t.Fatalf("recently-promoted a should survive eviction")
	}
	if d.Seen(b) {
		t.Fatalf("b should have been evicted as LRU")
	}
}

func TestLRUDedup_NilKeyIgnored(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10)
	if d.Add(DedupKey{}) {
		t.Fatalf("all-nil key must not be added")
	}
	if d.Len() != 0 {
		t.Fatalf("len after nil-key insertion: got %d", d.Len())
	}
}

func TestLRUDedup_CapacityDefault(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(0)
	if d.Capacity() != DefaultLRUDedupCapacity {
		t.Fatalf("zero capacity should map to default; got %d", d.Capacity())
	}
}

func TestLRUDedup_Stats(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10)
	dev := uuid.New()
	k := DedupKey{DeviceID: dev, SequenceNumber: 1, EventID: uuid.New()}
	d.Add(k)
	d.Seen(k)
	d.Seen(k)
	d.Seen(DedupKey{DeviceID: uuid.New(), SequenceNumber: 99, EventID: uuid.New()})
	s := d.Stats()
	if s.Hits != 2 {
		t.Fatalf("hits: got %d want 2", s.Hits)
	}
	if s.Misses != 1 {
		t.Fatalf("misses: got %d want 1", s.Misses)
	}
	if s.Len != 1 {
		t.Fatalf("len: got %d want 1", s.Len)
	}
}

func TestLRUDedup_Concurrent(t *testing.T) {
	t.Parallel()
	d := NewLRUDedup(10_000)
	const workers = 16
	const perWorker = 500
	dev := uuid.New()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				seq := uint64(w*perWorker + i)
				k := DedupKey{DeviceID: dev, SequenceNumber: seq, EventID: uuid.New()}
				d.SeenOrAdd(k)
				_ = d.Seen(k) // should be a hit
			}
		}()
	}
	wg.Wait()
	if d.Len() != workers*perWorker {
		t.Fatalf("len after concurrent inserts: got %d want %d", d.Len(), workers*perWorker)
	}
}
