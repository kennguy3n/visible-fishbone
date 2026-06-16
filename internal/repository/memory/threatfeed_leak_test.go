package memory

import (
	"runtime"
	"testing"
	"time"
	"weak"
)

// TestThreatFeedStateSideTableReclaimed proves the weak-keyed side table
// does not pin Stores. A plain map[*Store] key would keep every Store ever
// constructed alive for the lifetime of the process (a leak that grows with
// the test suite); with a weak.Pointer[Store] key plus the runtime.AddCleanup
// hook, the entry is reclaimed once the owning Store becomes unreachable.
func TestThreatFeedStateSideTableReclaimed(t *testing.T) {
	// Build a Store, populate its threat-content state, then capture only a
	// weak key and let every strong reference (the Store and the repo that
	// points back at it) go out of scope.
	key := func() weak.Pointer[Store] {
		s := NewStore()
		_ = s.NewThreatFeedRepository() // inserts threatFeedStates[weak.Make(s)]
		return weak.Make(s)
	}()

	threatFeedStates.mu.Lock()
	_, present := threatFeedStates.m[key]
	threatFeedStates.mu.Unlock()
	if !present {
		t.Fatal("entry should be present before GC")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		threatFeedStates.mu.Lock()
		_, present := threatFeedStates.m[key]
		threatFeedStates.mu.Unlock()
		if !present {
			break // cleanup ran => Store was reclaimed, no leak
		}
		if time.Now().After(deadline) {
			t.Fatal("side-table entry not reclaimed after the Store became unreachable (leak)")
		}
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}

	if v := key.Value(); v != nil {
		t.Fatal("Store still reachable after its side-table entry was reclaimed")
	}
}
