package appdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// EnsureProtection idempotently installs a tenant override that steers
// `domains` to `target`, but ONLY when that tightens the tenant's
// current effective class for the app. It is the enforcement primitive
// the CASB NoOps action engine drives to auto-protect a high-risk
// shadow-IT app, and it encodes the one safety invariant that makes
// unattended enforcement acceptable:
//
//	automation may add inspection, never remove it.
//
// `probe` is a representative concrete host for the app (e.g.
// "console.aws.amazon.com") used to resolve the current effective
// class; `domains` are the override match patterns (e.g.
// "*.console.aws.amazon.com").
//
// An override is written in two cases:
//
//  1. target is strictly stricter than the current effective class —
//     the classic "add inspection" tighten.
//  2. the app currently sits only on the default safe baseline (no
//     explicit rule resolved it) and target is at least that baseline.
//     A shadow-IT app the global catalog has never heard of resolves to
//     the inspect_full default; without this case an auto-protect
//     decision for it would be a silent no-op that depends on the
//     baseline never changing and leaves no override to audit or lift.
//     Persisting an explicit override makes the protection durable
//     (survives a baseline change or a later catalog row at a *lower*
//     class) and attributable.
//
// When an explicit rule already provides at least `target` protection —
// the global catalog, a stricter operator override, or a prior call —
// nothing is written and created=false is returned, so repeated
// reconciles are a no-op (no duplicate overrides accrue).
//
// The override is permanent (no TTL): it represents a durable posture
// decision the operator reviews via the NoOps digest and can lift with
// DeleteOverride. CreateOverride records it in the appdb audit trail,
// so the enforcement is attributable independently of the CASB engine's
// own audit row.
func (s *Service) EnsureProtection(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	probe string,
	domains []string,
	target repository.TrafficClass,
	reason string,
) (bool, error) {
	if tenantID == uuid.Nil {
		return false, fmt.Errorf("appdb: tenant_id required: %w", repository.ErrInvalidArgument)
	}
	if !target.IsValid() {
		return false, fmt.Errorf("appdb: invalid target class %q: %w", target, repository.ErrInvalidArgument)
	}
	if probe == "" {
		return false, fmt.Errorf("appdb: probe host required: %w", repository.ErrInvalidArgument)
	}
	cleaned := cleanDomains(domains)
	if len(cleaned) == 0 {
		return false, fmt.Errorf("appdb: at least one domain required: %w", repository.ErrInvalidArgument)
	}

	current, matched, err := s.resolveTrafficClass(ctx, tenantID, probe)
	if err != nil {
		return false, fmt.Errorf("appdb: resolve current class: %w", err)
	}
	// Never loosen. Decide whether to persist an override:
	//   - target strictly stricter than current  -> tighten (write).
	//   - app on the default baseline only (no explicit rule) and target
	//     at least the baseline                  -> persist a durable
	//     override so the protection is explicit and survives baseline
	//     or catalog drift (write).
	//   - an explicit rule already provides >= target protection, or
	//     target would loosen the baseline       -> no-op.
	targetRank, curRank := protectionRank(target), protectionRank(current)
	switch {
	case targetRank > curRank:
	case !matched && targetRank == curRank:
	default:
		return false, nil
	}

	_, err = s.CreateOverride(ctx, tenantID, actorID, repository.AppRegistryOverride{
		CustomDomains:        cleaned,
		TrafficClassOverride: target,
		Reason:               reason,
	})
	if err != nil {
		return false, fmt.Errorf("appdb: create protection override: %w", err)
	}
	return true, nil
}

// protectionRank orders traffic classes by how much inspection /
// control they impose, so EnsureProtection can compare "stricter than".
// It is a deliberately coarse safety ordering, NOT a claim that the
// classes form a total business-preference order:
//
//	trusted_direct / trusted_media_bypass  -> 0  (no inspection)
//	inspect_lite                           -> 1  (DNS + URL category)
//	inspect_full                           -> 2  (TLS decrypt, AV, IPS, DLP)
//	tunnel_private                         -> 3  (private mTLS overlay)
//	block                                  -> 4  (deny)
//
// An unknown class ranks 0 (treated as "no protection") so a typo can
// never make EnsureProtection believe an app is already protected and
// skip tightening it.
func protectionRank(c repository.TrafficClass) int {
	switch c {
	case repository.TrafficClassInspectLite:
		return 1
	case repository.TrafficClassInspectFull:
		return 2
	case repository.TrafficClassTunnelPrivate:
		return 3
	case repository.TrafficClassBlock:
		return 4
	default:
		// trusted_direct, trusted_media_bypass, and anything unrecognised.
		return 0
	}
}

// cleanDomains lower-cases, trims, drops a trailing dot from, and
// de-duplicates override match patterns, preserving first-seen order
// so the stored override is canonical and free of accidental
// duplicates. ResolveTrafficClass's matcher already lower-cases
// patterns at match time; normalising here keeps the persisted row
// tidy and stable across reconciles.
func cleanDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}
