package threatfeed

import (
	"math"
	"testing"
	"time"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestNoisyOr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		weights []float64
		want    float64
	}{
		{"empty is zero", nil, 0},
		{"single weight passthrough", []float64{0.7}, 0.7},
		{"two sources corroborate", []float64{0.7, 0.8}, 1 - 0.3*0.2}, // 0.94
		{"monotonic above each input", []float64{0.5, 0.5, 0.5}, 1 - 0.125},
		{"clamps garbage high", []float64{2.0}, 1},
		{"clamps garbage low", []float64{-1.0}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := noisyOr(tc.weights); !approx(got, tc.want) {
				t.Fatalf("noisyOr(%v) = %v, want %v", tc.weights, got, tc.want)
			}
		})
	}
}

func TestNoisyOr_CorroborationRaisesScore(t *testing.T) {
	t.Parallel()
	single := noisyOr([]float64{0.7})
	corroborated := noisyOr([]float64{0.7, 0.6})
	if !(corroborated > single) {
		t.Fatalf("corroborated %v should exceed single %v", corroborated, single)
	}
}

func TestRecencyFactor(t *testing.T) {
	t.Parallel()
	hl := DefaultHalfLife
	if got := recencyFactor(0, hl); !approx(got, 1) {
		t.Fatalf("fresh recency = %v, want 1", got)
	}
	if got := recencyFactor(-time.Hour, hl); !approx(got, 1) {
		t.Fatalf("future lastSeen recency = %v, want 1", got)
	}
	if got := recencyFactor(hl, hl); !approx(got, 0.5) {
		t.Fatalf("one half-life recency = %v, want 0.5", got)
	}
	if got := recencyFactor(2*hl, hl); !approx(got, 0.25) {
		t.Fatalf("two half-lives recency = %v, want 0.25", got)
	}
	if got := recencyFactor(time.Hour, 0); !approx(got, 1) {
		t.Fatalf("non-positive half-life recency = %v, want 1", got)
	}
}

func TestClamp01(t *testing.T) {
	t.Parallel()
	cases := map[float64]float64{
		-1:           0,
		0:            0,
		0.5:          0.5,
		1:            1,
		2:            1,
		math.Inf(1):  1,
		math.Inf(-1): 0,
		math.NaN():   0,
	}
	for in, want := range cases {
		if got := clamp01(in); got != want {
			t.Fatalf("clamp01(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestEarliestLatest(t *testing.T) {
	t.Parallel()
	var zero time.Time
	a := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	if got := earliest(zero, b); !got.Equal(b) {
		t.Fatalf("earliest(zero,b) = %v, want b", got)
	}
	if got := earliest(a, zero); !got.Equal(a) {
		t.Fatalf("earliest(a,zero) = %v, want a", got)
	}
	if got := earliest(a, b); !got.Equal(a) {
		t.Fatalf("earliest(a,b) = %v, want a", got)
	}
	if got := latest(a, b); !got.Equal(b) {
		t.Fatalf("latest(a,b) = %v, want b", got)
	}
	if got := latest(zero, a); !got.Equal(a) {
		t.Fatalf("latest(zero,a) = %v, want a", got)
	}
}
