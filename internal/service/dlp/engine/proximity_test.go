package engine

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func matchOne(t *testing.T, content, pattern string) (Match, bool) {
	t.Helper()
	e := NewRegexEngine()
	rules := []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: pattern}}
	ms := e.Match([]byte(content), rules)
	if len(ms) == 0 {
		return Match{}, false
	}
	return ms[0], true
}

func TestProximity_ValidatedHitFullConfidence(t *testing.T) {
	// Valid China resident id, no context: validator passes -> 1.0.
	m, ok := matchOne(t, "value 110101199001010015 here", "china_resident_id")
	if !ok {
		t.Fatal("expected a match")
	}
	if m.Confidence != 1.0 {
		t.Errorf("validated hit confidence = %v, want 1.0", m.Confidence)
	}
}

func TestProximity_CounterContextSinksValidated(t *testing.T) {
	// "example" nearby marks the hit illustrative: 1.0 - 0.30 = 0.70.
	m, ok := matchOne(t, "example id 110101199001010015", "china_resident_id")
	if !ok {
		t.Fatal("expected a match")
	}
	if m.Confidence != 0.70 {
		t.Errorf("counter-context confidence = %v, want 0.70", m.Confidence)
	}
}

func TestProximity_ContextBoostBarePattern(t *testing.T) {
	// Qatar QID has no validator: bare base 0.5, boosted by "qatar id".
	withCtx, ok := matchOne(t, "qatar id: 12345678901", "qatar_qid")
	if !ok {
		t.Fatal("expected a match")
	}
	if withCtx.Confidence != 0.65 {
		t.Errorf("bare+context confidence = %v, want 0.65", withCtx.Confidence)
	}
	// No context keyword: stays at bare base 0.5.
	noCtx, ok := matchOne(t, "reference 12345678901 only", "qatar_qid")
	if !ok {
		t.Fatal("expected a match")
	}
	if noCtx.Confidence != 0.5 {
		t.Errorf("bare confidence = %v, want 0.5", noCtx.Confidence)
	}
}

func TestProximity_InvalidValidatedHitDropped(t *testing.T) {
	// Same shape, bad check digit: validator fails -> no match.
	if _, ok := matchOne(t, "id 110101199001010010 here", "china_resident_id"); ok {
		t.Error("hit with failing check digit should be dropped")
	}
}

func TestProximity_AdjustClampsAndFloors(t *testing.T) {
	kws := proximityKeywords("saudi_id")
	if kws == nil {
		t.Fatal("expected saudi_id proximity keywords")
	}
	// Counter-context floors at 0.1 even from bare base.
	got := proximityAdjust("this is a test", 0, 4, confidenceBare, kws)
	if got != confidenceBare-proximityCounterPenalty {
		t.Errorf("counter penalty = %v, want %v", got, confidenceBare-proximityCounterPenalty)
	}
	// Boost caps at 1.0 from validated base.
	got = proximityAdjust("national id field", 0, 4, confidenceValidated, kws)
	if got != 1.0 {
		t.Errorf("boost from validated = %v, want 1.0 (capped)", got)
	}
}
