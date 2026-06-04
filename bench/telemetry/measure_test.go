package main

import "testing"

func TestMeasureEncode(t *testing.T) {
	g := NewGenerator(GenConfig{Tenants: 100, Seed: 1})
	st, err := MeasureEncode(g, 5000)
	if err != nil {
		t.Fatalf("MeasureEncode: %v", err)
	}
	if st.Events != 5000 || st.TotalWireBytes <= 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if st.EventsPerSec() <= 0 {
		t.Fatalf("events/sec must be > 0, got %v", st.EventsPerSec())
	}
	// Flow envelopes are designed to sit well under ~1 KiB on the wire.
	if avg := st.AvgWireBytes(); avg < 40 || avg > 1024 {
		t.Fatalf("avg wire size %v out of expected range", avg)
	}
}

func TestMeasureArchiveCompression(t *testing.T) {
	g := NewGenerator(GenConfig{Tenants: 100, Seed: 1})
	st, err := MeasureArchiveCompression(g, 5000)
	if err != nil {
		t.Fatalf("MeasureArchiveCompression: %v", err)
	}
	if st.Events != 5000 || st.Uncompressed <= 0 || st.Compressed <= 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	// gzip must shrink the base64 JSON-Lines payload.
	if st.Ratio() <= 1.0 {
		t.Fatalf("compression ratio = %v, want > 1", st.Ratio())
	}
	if st.AvgCompressedBytesPerEvent() <= 0 {
		t.Fatalf("avg compressed bytes/event must be > 0")
	}
}

func TestZeroStats(t *testing.T) {
	if (EncodeStats{}).EventsPerSec() != 0 || (EncodeStats{}).AvgWireBytes() != 0 {
		t.Fatal("zero EncodeStats must yield zeroes, not NaN")
	}
	if (CompressionStats{}).Ratio() != 0 || (CompressionStats{}).AvgCompressedBytesPerEvent() != 0 {
		t.Fatal("zero CompressionStats must yield zeroes, not NaN")
	}
}
