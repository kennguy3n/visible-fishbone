// lifecycle.go generates and applies the S3 bucket lifecycle
// configuration for the telemetry cold archive.
//
// Why a lifecycle policy instead of writing straight to Deep Archive:
// the archive is written once and read only during the first weeks of
// an incident-forensics / compliance window, then effectively never
// again. Glacier Deep Archive is the cheapest class ($0.00099/GB-mo —
// the price the cost model in internal/service/metering assumes) but
// has a multi-hour restore latency and a 180-day minimum-storage
// charge, which makes it the wrong home for *recent* objects an
// operator may still need to replay quickly. The cost-optimal,
// low-ops shape is therefore: land objects in STANDARD_IA (the
// writer's default class — millisecond reads for the hot forensic
// window) and let S3 itself age them into Deep Archive after a fixed
// number of days. That transition is server-side, free of egress, and
// requires no cron job or worker on our side — S3 runs it. This file
// produces that policy and PUTs it onto the bucket.
//
// The generated config is deterministic and prefix-scoped, so applying
// it is idempotent (PutBucketLifecycleConfiguration replaces the whole
// document) and safe to run on every control-plane boot, and it never
// touches objects outside the archive prefix in a shared bucket.

package s3

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	// DefaultDeepArchiveTransitionDays is the age, in days after object
	// creation, at which cold-archive objects transition to Glacier
	// Deep Archive. 90 days covers the typical incident-investigation
	// and compliance-review window during which an object might still
	// be replayed from low-latency STANDARD_IA; past it the object is
	// almost never read, so Deep Archive's multi-hour restore is an
	// acceptable trade for its ~23× lower storage price.
	DefaultDeepArchiveTransitionDays int32 = 90

	// DefaultAbortIncompleteMultipartDays bounds how long S3 retains the
	// parts of a multipart upload that never completed. The writer
	// uploads large flushes via the multipart manager; a crash mid-
	// upload can otherwise leave orphaned parts that are billed
	// indefinitely and never show up in a normal object listing. Seven
	// days is comfortably longer than any single flush yet short enough
	// to stop orphaned parts accreting cost.
	DefaultAbortIncompleteMultipartDays int32 = 7

	// DefaultLifecycleRuleID is the stable identifier for the managed
	// rule. The ID is stable on purpose so the rule is recognisable and
	// the generated document is deterministic across boots. Note S3's
	// PutBucketLifecycleConfiguration is not a per-rule merge: it replaces
	// the bucket's whole lifecycle document (see ApplyLifecyclePolicy), so
	// convergence comes from re-PUTting the same single-rule document, not
	// from S3 matching on this ID.
	DefaultLifecycleRuleID = "sng-telemetry-cold-archive"
)

// LifecyclePolicyConfig parameterises the generated bucket lifecycle
// configuration. The zero value, after withDefaults, yields the
// cost-model-aligned policy: transition the whole archive prefix to
// Glacier Deep Archive at 90 days, clean up incomplete multipart
// uploads after 7 days, and never expire objects (compliance archives
// are retained, not deleted, unless an operator opts in).
type LifecyclePolicyConfig struct {
	// Prefix scopes the rule to the archive key prefix so the policy is
	// safe on a bucket shared with unrelated objects. Empty means the
	// rule applies to every object in the bucket.
	Prefix string

	// TransitionDays is the object age at which it moves to Deep
	// Archive. Zero is replaced with DefaultDeepArchiveTransitionDays;
	// a negative value disables the transition rule entirely.
	TransitionDays int32

	// AbortIncompleteMultipartDays is the age at which S3 aborts an
	// incomplete multipart upload. Zero is replaced with
	// DefaultAbortIncompleteMultipartDays; a negative value disables
	// the cleanup.
	AbortIncompleteMultipartDays int32

	// ExpirationDays, when > 0, deletes objects this many days after
	// creation. The default (0) never expires the archive — deletion of
	// a compliance/forensic archive must be a deliberate operator
	// decision, never an implicit default. Must be ≥ TransitionDays
	// when both are set (you cannot expire before you transition).
	ExpirationDays int32

	// RuleID overrides the stable rule identifier. Empty uses
	// DefaultLifecycleRuleID.
	RuleID string
}

// EffectiveTransitionDays reports the Deep Archive transition age the
// policy actually applies for a configured value: 0 ⇒ the 90-day
// DefaultDeepArchiveTransitionDays, a negative value ⇒ 0 (the transition
// is disabled), any positive value ⇒ itself. It is the single source of
// truth for this defaulting (withDefaults below uses it), exported so a
// caller can log/report the age that was really applied rather than the
// raw configured input — e.g. an operator who set the knob to 0 sees 90
// in the logs, the value on the bucket.
func EffectiveTransitionDays(configured int32) int32 {
	switch {
	case configured == 0:
		return DefaultDeepArchiveTransitionDays
	case configured < 0:
		return 0
	default:
		return configured
	}
}

func (c LifecyclePolicyConfig) withDefaults() LifecyclePolicyConfig {
	c.TransitionDays = EffectiveTransitionDays(c.TransitionDays)
	if c.AbortIncompleteMultipartDays == 0 {
		c.AbortIncompleteMultipartDays = DefaultAbortIncompleteMultipartDays
	}
	if c.RuleID == "" {
		c.RuleID = DefaultLifecycleRuleID
	}
	return c
}

// validate rejects a config that would produce a semantically invalid
// or self-contradictory policy before it reaches S3, so a
// misconfiguration surfaces as a clear local error rather than an
// opaque API rejection.
func (c LifecyclePolicyConfig) validate() error {
	if c.ExpirationDays > 0 && c.TransitionDays > 0 && c.ExpirationDays < c.TransitionDays {
		return fmt.Errorf(
			"s3 lifecycle: expiration (%d days) must not precede the Deep Archive transition (%d days)",
			c.ExpirationDays, c.TransitionDays)
	}
	return nil
}

// BuildLifecycleConfiguration returns the bucket lifecycle
// configuration for the cold archive. It is a pure function (no I/O)
// so the policy can be unit-tested without an S3 client. The returned
// document always contains exactly one rule; an error is returned only
// for a self-contradictory config.
func BuildLifecycleConfiguration(cfg LifecyclePolicyConfig) (*types.BucketLifecycleConfiguration, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	rule := types.LifecycleRule{
		ID:     aws.String(cfg.RuleID),
		Status: types.ExpirationStatusEnabled,
		// A prefix Filter (never the deprecated top-level Prefix field)
		// scopes the rule. An empty prefix yields an empty-prefix
		// filter, which matches the whole bucket — the documented
		// "no prefix" behaviour.
		Filter: &types.LifecycleRuleFilter{Prefix: aws.String(cfg.Prefix)},
	}

	if cfg.TransitionDays > 0 {
		rule.Transitions = []types.Transition{{
			Days:         aws.Int32(cfg.TransitionDays),
			StorageClass: types.TransitionStorageClassDeepArchive,
		}}
	}
	if cfg.AbortIncompleteMultipartDays > 0 {
		rule.AbortIncompleteMultipartUpload = &types.AbortIncompleteMultipartUpload{
			DaysAfterInitiation: aws.Int32(cfg.AbortIncompleteMultipartDays),
		}
	}
	if cfg.ExpirationDays > 0 {
		rule.Expiration = &types.LifecycleExpiration{Days: aws.Int32(cfg.ExpirationDays)}
	}

	return &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{rule}}, nil
}

// LifecycleAPI is the S3 surface needed to apply a bucket lifecycle
// configuration. It is intentionally separate from the Writer's API /
// Archiver's ArchiverAPI: applying lifecycle is a one-shot management
// call, not part of the hot archive path, and keeping it separate means
// the existing PutObject-only test fakes don't have to grow a method
// they never exercise. The concrete *s3.Client returned by
// s3.NewFromConfig satisfies all three.
type LifecycleAPI interface {
	PutBucketLifecycleConfiguration(
		ctx context.Context,
		in *s3.PutBucketLifecycleConfigurationInput,
		opts ...func(*s3.Options),
	) (*s3.PutBucketLifecycleConfigurationOutput, error)
}

// ApplyLifecyclePolicy generates the cold-archive lifecycle policy and
// PUTs it onto bucket. It is idempotent: the document is deterministic
// and replaces any existing configuration, so it is safe to call on
// every boot.
//
// Note the call replaces the bucket's *entire* lifecycle configuration.
// That is correct for a bucket dedicated to the telemetry archive
// (the documented deployment). Operators who instead manage the bucket
// lifecycle out-of-band (Terraform, an org SCP, a shared bucket) should
// disable control-plane management rather than let two owners fight
// over the document — see the manage-lifecycle config knob in main.
func ApplyLifecyclePolicy(ctx context.Context, api LifecycleAPI, bucket string, cfg LifecyclePolicyConfig) error {
	if api == nil {
		return errors.New("s3 lifecycle: API client is required")
	}
	if strings.TrimSpace(bucket) == "" {
		return errors.New("s3 lifecycle: bucket is required")
	}
	lc, err := BuildLifecycleConfiguration(cfg)
	if err != nil {
		return err
	}
	if _, err := api.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String(bucket),
		LifecycleConfiguration: lc,
	}); err != nil {
		return fmt.Errorf("s3 lifecycle: put configuration on %q: %w", bucket, err)
	}
	return nil
}

// EnsureLifecyclePolicy applies the cold-archive lifecycle policy to the
// Writer's own bucket and prefix, transitioning archived objects to
// Glacier Deep Archive after transitionDays (0 ⇒ the 90-day default).
// It is a thin convenience over ApplyLifecyclePolicy that reuses the
// writer's configured bucket/prefix so the policy can never target a
// different prefix than the writer actually writes to.
func (w *Writer) EnsureLifecyclePolicy(ctx context.Context, api LifecycleAPI, transitionDays int32) error {
	return ApplyLifecyclePolicy(ctx, api, w.cfg.Bucket, LifecyclePolicyConfig{
		Prefix:         w.cfg.Prefix,
		TransitionDays: transitionDays,
	})
}
