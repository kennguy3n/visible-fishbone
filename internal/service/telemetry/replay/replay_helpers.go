// replay_helpers.go: pure-function helpers for the cold-tier
// replay Service. Split into its own file so the service.go
// orchestration stays focused on the run loop.
package replay

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// verdictPair keys the in-memory transition matrix.
type verdictPair struct {
	prev schema.Verdict
	next schema.Verdict
}

// sealedEventJSON mirrors the s3.sealedEvent struct: the JSON-Lines
// row format the archiver writes. Duplicated here (rather than
// imported) so the replay package does not depend on the s3 package
// — that keeps the import graph one-way (s3 → replay would not
// compile because replay does not import s3 either, but
// duplicating the struct also lets a non-s3 ColdReader implementation
// (e.g. GCS) reuse the same wire format trivially).
type sealedEventJSON struct {
	Envelope schema.Envelope `json:"envelope"`
}

// decodeSealedBatch decodes a JSON-Lines stream of sealed events
// (produced by s3.Archiver.Flush) into a slice of envelopes.
// Malformed lines are skipped with the running error returned at
// the end; partial decode is preferable to abandoning the whole
// object because one bad row at line N should not lose lines
// N+1..M.
//
// The reader is consumed but not closed — the caller owns
// closure semantics.
func decodeSealedBatch(r io.Reader) ([]schema.Envelope, error) {
	if r == nil {
		return nil, errors.New("replay: nil reader")
	}
	out := make([]schema.Envelope, 0, 64)
	scanner := bufio.NewScanner(r)
	// JSON-Lines rows can carry the full Envelope including a
	// base64-encoded raw_b64 blob. The scanner's default
	// 64 KiB buffer is too small for realistic envelopes
	// (especially HTTP events with header dumps). Bump to 8
	// MiB which is well above any single-row size while still
	// bounded.
	const maxLine = 8 * 1024 * 1024
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	var firstErr error
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var row sealedEventJSON
		if err := json.Unmarshal(line, &row); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, row.Envelope)
	}
	if err := scanner.Err(); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	return out, firstErr
}

// sortedTransitions materialises the verdict transition map in
// a deterministic order: alphabetical by PrevVerdict then by
// NextVerdict. The deterministic order is REQUIRED for the
// report's reproducibility contract (two runs over the same
// input must produce byte-identical reports) and lets the API
// layer cache the report by hash.
func sortedTransitions(m map[verdictPair]int) []VerdictTransition {
	if len(m) == 0 {
		return nil
	}
	out := make([]VerdictTransition, 0, len(m))
	for k, v := range m {
		out = append(out, VerdictTransition{
			PrevVerdict: k.prev,
			NextVerdict: k.next,
			Count:       v,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrevVerdict != out[j].PrevVerdict {
			return out[i].PrevVerdict < out[j].PrevVerdict
		}
		return out[i].NextVerdict < out[j].NextVerdict
	})
	return out
}

// sortedUUIDs materialises a UUID set in canonical lexicographic
// order — same determinism contract as sortedTransitions.
func sortedUUIDs(set map[uuid.UUID]struct{}) []uuid.UUID {
	if len(set) == 0 {
		return nil
	}
	out := make([]uuid.UUID, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}
