package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// FingerprintMatch describes how closely incoming content matches
// a registered fingerprint.
type FingerprintMatch struct {
	FingerprintID uuid.UUID
	Name          string
	Similarity    float64
}

// FingerprintEngine provides SimHash-based near-duplicate detection.
type FingerprintEngine struct {
	repo repository.DLPFingerprintRepository
}

// NewFingerprintEngine constructs a fingerprint engine.
func NewFingerprintEngine(repo repository.DLPFingerprintRepository) *FingerprintEngine {
	return &FingerprintEngine{repo: repo}
}

// RegisterFingerprint computes the SimHash of the content and
// persists it as a named fingerprint for the tenant.
func (e *FingerprintEngine) RegisterFingerprint(
	ctx context.Context,
	tenantID uuid.UUID,
	name string,
	contentType string,
	content []byte,
) (repository.DLPFingerprint, error) {
	hash := SimHash(content)
	hashBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(hashBytes, hash)
	return e.repo.Create(ctx, tenantID, repository.DLPFingerprint{
		Name:        name,
		Hash:        hashBytes,
		ContentType: contentType,
	})
}

// MatchFingerprints compares incoming content against all registered
// fingerprints for the tenant, returning matches above the similarity
// threshold (0.8).
func (e *FingerprintEngine) MatchFingerprints(
	ctx context.Context,
	tenantID uuid.UUID,
	content []byte,
) ([]FingerprintMatch, error) {
	all, err := e.repo.ListAll(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, nil
	}
	contentHash := SimHash(content)
	var matches []FingerprintMatch
	for _, fp := range all {
		if len(fp.Hash) < 8 {
			continue
		}
		stored := binary.BigEndian.Uint64(fp.Hash)
		sim := hammingSimilarity(contentHash, stored)
		if sim >= 0.8 {
			matches = append(matches, FingerprintMatch{
				FingerprintID: fp.ID,
				Name:          fp.Name,
				Similarity:    sim,
			})
		}
	}
	return matches, nil
}

// SimHash computes a 64-bit SimHash of the content. Tokenization is
// script-aware (see simhashTokens): whitespace tokens for space-
// delimited scripts, character bigrams for CJK, and character
// trigrams for Thai, so locality-sensitive hashing works for scripts
// that do not delimit words with spaces. Each token is hashed with
// SHA-256 (truncated to the leading 64 bits) and the bit-vectors are
// summed component-wise, MSB-first — byte-identical to the Rust
// `simhash` in crates/sng-dlp/src/classifier.rs.
func SimHash(content []byte) uint64 {
	tokens := simhashTokens(string(content))
	if len(tokens) == 0 {
		return 0
	}
	var v [64]int
	for _, token := range tokens {
		h := sha256.Sum256([]byte(token))
		bits := binary.BigEndian.Uint64(h[:8])
		for i := 0; i < 64; i++ {
			if bits&(1<<uint(63-i)) != 0 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var result uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			result |= 1 << uint(63-i)
		}
	}
	return result
}

// hammingSimilarity returns 1.0 - (hamming_distance / 64).
func hammingSimilarity(a, b uint64) float64 {
	diff := bits.OnesCount64(a ^ b)
	return 1.0 - float64(diff)/64.0
}
