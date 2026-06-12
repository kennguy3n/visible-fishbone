// Command wildcorpus generates the *noisy wild-traffic* labelled corpus the
// sng-efficacy sustained-load driver replays through the real enforcement
// engines (YARA malware scanner + DLP content classifier; the Suricata IPS
// tier replays its own committed PCAP corpus).
//
// Why this exists — and what it is NOT
// ------------------------------------
// The curated `bench/efficacy` corpora are decision-boundary fixtures: every
// case is hand-placed on the right side of a rule so the suite scores ~100%
// *by construction*. That is a correctness proof of the enforcement code, NOT
// a real-world catch rate. This generator emits a deliberately larger and
// noisier signal: benign and malicious payloads blended at a realistic ratio
// (the vast majority of real traffic is benign), across mixed file types and
// payload shapes, including:
//
//   - benign-but-suspicious-looking traffic that a signature engine genuinely
//     flags (legitimate software installers with PE/ELF headers, real apps
//     that call String.fromCharCode, PDF forms carrying /JavaScript) — these
//     surface honest false positives, and
//   - evasive / novel-packed malicious payloads a signature scanner genuinely
//     misses (encrypted droppers with no static marker) — these surface honest
//     false negatives.
//
// It is still a *synthetic proxy*, not a capture of production traffic: every
// "malicious" byte is an inert synthetic stand-in (the EICAR industry test
// marker, minimal valid headers, fabricated-but-format-valid secrets). It does
// not prove a universal real-world catch rate; it gives a noisier, FPR-aware
// signal than the curated suite, measured under sustained concurrent load.
//
// Determinism & provenance
// -------------------------
// The corpus is fully deterministic: a single seeded PRNG (default seed
// `0x53_4757_44` = "SGWD") drives every random choice and the final shuffle,
// so the same seed always produces a byte-identical `wild-corpus.json`. The
// generated file is committed; the sng-efficacy harness has no runtime
// dependency on this tool. Re-run it only when the corpus definition changes:
//
//	go run ./blog/harness/wildcorpus            # writes the default fixture path
//	go run ./blog/harness/wildcorpus --out /tmp/wild-corpus.json --seed 1397113412
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
)

// schemaVersion is embedded in the artifact and asserted by the Rust loader so
// a corpus produced by an incompatible generator is rejected rather than
// silently mis-scored.
const schemaVersion = "sng-wild-corpus/v1"

// defaultSeed ("SGWD") — any fixed value works; this one is recorded in the
// artifact so a reader can reproduce the exact corpus.
const defaultSeed int64 = 0x0053_4757_44

// Engine lanes. Each entry is routed to exactly one real engine by the load
// driver: YARA over file bytes, or the DLP content classifier over text.
const (
	engineYARA = "yara"
	engineDLP  = "dlp"
)

const (
	labelBenign    = "benign"
	labelMalicious = "malicious"
)

// Entry is one labelled corpus sample. The payload is base64 so arbitrary
// bytes (binaries, high-entropy blobs) survive JSON round-trip intact.
type Entry struct {
	ID         string `json:"id"`
	Label      string `json:"label"`  // benign | malicious (ground truth)
	Engine     string `json:"engine"` // yara | dlp
	Family     string `json:"family"`
	Desc       string `json:"desc"`
	PayloadB64 string `json:"payload_b64"`
}

// Blend records the target malicious/benign mix so the methodology can be read
// straight off the artifact without re-deriving it from the entries.
type Blend struct {
	MaliciousFractionTarget float64 `json:"malicious_fraction_target"`
	BenignFractionTarget    float64 `json:"benign_fraction_target"`
}

// Counts is the realised census (computed from the entries actually emitted).
type Counts struct {
	Total     int            `json:"total"`
	Benign    int            `json:"benign"`
	Malicious int            `json:"malicious"`
	ByEngine  map[string]int `json:"by_engine"`
	ByFamily  map[string]int `json:"by_family"`
}

// Corpus is the committed artifact.
type Corpus struct {
	Schema      string `json:"schema"`
	Generator   string `json:"generator"`
	Seed        int64  `json:"seed"`
	Description string `json:"description"`
	Blend       Blend  `json:"blend"`
	Counts      Counts `json:"counts"`
	// ContentSHA256 fingerprints the entries (order-independent) so a reviewer
	// can confirm a committed corpus matches a fresh `go run` regeneration.
	ContentSHA256 string  `json:"content_sha256"`
	Entries       []Entry `json:"entries"`
}

func main() {
	out := flag.String("out", defaultOutPath(), "output path for the generated wild-corpus.json")
	seed := flag.Int64("seed", defaultSeed, "PRNG seed (recorded in the artifact for reproducibility)")
	scale := flag.Int("scale", 1, "multiply per-family counts by this factor (for a larger corpus)")
	flag.Parse()

	if *scale < 1 {
		fmt.Fprintln(os.Stderr, "scale must be >= 1")
		os.Exit(2)
	}

	rng := rand.New(rand.NewSource(*seed))
	entries := build(rng, *scale)

	// Deterministic shuffle so the load driver sees an interleaved benign /
	// malicious / yara / dlp stream (no engine processes a contiguous block),
	// exercising the engines under a realistically mixed sequence.
	rng.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })

	corpus := Corpus{
		Schema:      schemaVersion,
		Generator:   "blog/harness/wildcorpus",
		Seed:        *seed,
		Description: "Noisy wild-traffic proxy: benign+malicious blended across mixed file types and payload shapes, including benign-but-suspicious traffic (honest false positives) and evasive/novel-packed malware (honest false negatives). Synthetic, inert stand-ins — NOT captured production traffic, so this does not establish a universal real-world catch rate. The ~1-in-5 malicious density is denser than live traffic on purpose, so each malicious class has a statistically meaningful sample; the false-positive-rate is therefore measured against the large benign majority. Replayed by bench/efficacy under sustained concurrent load to report BOTH catch-rate AND false-positive-rate.",
		Blend: Blend{
			// Design intent: a malicious minority against a benign majority.
			// The realised split is reported in Counts; it is intentionally
			// denser in malicious than live traffic so each attack class is
			// statistically meaningful (documented in the harness README).
			MaliciousFractionTarget: 0.20,
			BenignFractionTarget:    0.80,
		},
		Counts:  census(entries),
		Entries: entries,
	}
	corpus.ContentSHA256 = fingerprint(entries)

	data, err := json.MarshalIndent(&corpus, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal corpus: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}

	c := corpus.Counts
	fmt.Printf("wrote %s\n", *out)
	fmt.Printf("  total=%d  benign=%d (%.1f%%)  malicious=%d (%.1f%%)\n",
		c.Total, c.Benign, pct(c.Benign, c.Total), c.Malicious, pct(c.Malicious, c.Total))
	fmt.Printf("  by engine: yara=%d  dlp=%d\n", c.ByEngine[engineYARA], c.ByEngine[engineDLP])
	fmt.Printf("  sha256=%s\n", corpus.ContentSHA256)
}

// defaultOutPath resolves the committed fixture path relative to this source
// file, so `go run ./blog/harness/wildcorpus` works from the repo root.
func defaultOutPath() string {
	// blog/harness/wildcorpus -> repo root is three levels up.
	return filepath.Join("bench", "efficacy", "fixtures", "wild", "wild-corpus.json")
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func census(entries []Entry) Counts {
	c := Counts{ByEngine: map[string]int{}, ByFamily: map[string]int{}}
	c.Total = len(entries)
	for _, e := range entries {
		switch e.Label {
		case labelBenign:
			c.Benign++
		case labelMalicious:
			c.Malicious++
		}
		c.ByEngine[e.Engine]++
		c.ByFamily[e.Family]++
	}
	return c
}

// fingerprint hashes the entries order-independently (sort the per-entry
// digests), so a reviewer can verify a committed corpus equals a fresh
// regeneration regardless of the post-shuffle ordering.
func fingerprint(entries []Entry) string {
	digests := make([]string, 0, len(entries))
	for _, e := range entries {
		h := sha256.Sum256([]byte(e.Label + "\x00" + e.Engine + "\x00" + e.Family + "\x00" + e.PayloadB64))
		digests = append(digests, hex.EncodeToString(h[:]))
	}
	sort.Strings(digests)
	roll := sha256.New()
	for _, d := range digests {
		roll.Write([]byte(d))
	}
	return hex.EncodeToString(roll.Sum(nil))
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
