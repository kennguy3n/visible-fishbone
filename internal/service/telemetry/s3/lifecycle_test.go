package s3

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeLifecycleAPI captures the most recent PutBucketLifecycleConfiguration
// call and can be told to fail.
type fakeLifecycleAPI struct {
	mu      sync.Mutex
	calls   int
	last    *s3.PutBucketLifecycleConfigurationInput
	failErr error
}

func (f *fakeLifecycleAPI) PutBucketLifecycleConfiguration(
	_ context.Context,
	in *s3.PutBucketLifecycleConfigurationInput,
	_ ...func(*s3.Options),
) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = in
	if f.failErr != nil {
		return nil, f.failErr
	}
	return &s3.PutBucketLifecycleConfigurationOutput{}, nil
}

func i32(p *int32) int32 {
	if p == nil {
		return -1
	}
	return *p
}

func TestBuildLifecycleConfiguration_Defaults(t *testing.T) {
	lc, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{Prefix: "telemetry"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lc.Rules) != 1 {
		t.Fatalf("want exactly 1 rule, got %d", len(lc.Rules))
	}
	r := lc.Rules[0]

	if r.Status != types.ExpirationStatusEnabled {
		t.Errorf("rule status = %q, want Enabled", r.Status)
	}
	if deref(r.ID) != DefaultLifecycleRuleID {
		t.Errorf("rule ID = %q, want %q", deref(r.ID), DefaultLifecycleRuleID)
	}
	// Prefix-scoped via Filter, never the deprecated top-level Prefix.
	if r.Prefix != nil {
		t.Errorf("deprecated top-level Prefix should be nil, got %q", deref(r.Prefix))
	}
	if r.Filter == nil || deref(r.Filter.Prefix) != "telemetry" {
		t.Fatalf("filter prefix = %+v, want \"telemetry\"", r.Filter)
	}

	if len(r.Transitions) != 1 {
		t.Fatalf("want 1 transition, got %d", len(r.Transitions))
	}
	tr := r.Transitions[0]
	if tr.StorageClass != types.TransitionStorageClassDeepArchive {
		t.Errorf("transition class = %q, want DEEP_ARCHIVE", tr.StorageClass)
	}
	if got := i32(tr.Days); got != DefaultDeepArchiveTransitionDays {
		t.Errorf("transition days = %d, want %d", got, DefaultDeepArchiveTransitionDays)
	}

	if r.AbortIncompleteMultipartUpload == nil ||
		i32(r.AbortIncompleteMultipartUpload.DaysAfterInitiation) != DefaultAbortIncompleteMultipartDays {
		t.Errorf("abort-incomplete-multipart = %+v, want %d days",
			r.AbortIncompleteMultipartUpload, DefaultAbortIncompleteMultipartDays)
	}

	// A compliance archive is retained, not deleted, by default.
	if r.Expiration != nil {
		t.Errorf("expiration should be nil by default, got %+v", r.Expiration)
	}
}

func TestBuildLifecycleConfiguration_DefaultTransitionIs90(t *testing.T) {
	if DefaultDeepArchiveTransitionDays != 90 {
		t.Fatalf("DefaultDeepArchiveTransitionDays = %d, want 90", DefaultDeepArchiveTransitionDays)
	}
}

func TestBuildLifecycleConfiguration_Custom(t *testing.T) {
	lc, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{
		Prefix:                       "cold/",
		TransitionDays:               30,
		AbortIncompleteMultipartDays: 3,
		ExpirationDays:               365,
		RuleID:                       "custom-id",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := lc.Rules[0]
	if deref(r.ID) != "custom-id" {
		t.Errorf("rule ID = %q, want custom-id", deref(r.ID))
	}
	if deref(r.Filter.Prefix) != "cold/" {
		t.Errorf("filter prefix = %q, want cold/", deref(r.Filter.Prefix))
	}
	if got := i32(r.Transitions[0].Days); got != 30 {
		t.Errorf("transition days = %d, want 30", got)
	}
	if i32(r.AbortIncompleteMultipartUpload.DaysAfterInitiation) != 3 {
		t.Errorf("abort days = %d, want 3", i32(r.AbortIncompleteMultipartUpload.DaysAfterInitiation))
	}
	if r.Expiration == nil || i32(r.Expiration.Days) != 365 {
		t.Errorf("expiration = %+v, want 365 days", r.Expiration)
	}
}

func TestBuildLifecycleConfiguration_NegativeDisables(t *testing.T) {
	// A negative transition and a negative abort each disable their own
	// action; ExpirationDays keeps one action present so the rule is still
	// valid (a rule with no actions at all is rejected — see below).
	lc, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{
		Prefix:                       "telemetry",
		TransitionDays:               -1,
		AbortIncompleteMultipartDays: -1,
		ExpirationDays:               365,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := lc.Rules[0]
	if len(r.Transitions) != 0 {
		t.Errorf("transitions should be empty when disabled, got %d", len(r.Transitions))
	}
	if r.AbortIncompleteMultipartUpload != nil {
		t.Errorf("abort-incomplete-multipart should be nil when disabled")
	}
	if r.Expiration == nil || i32(r.Expiration.Days) != 365 {
		t.Errorf("expiration should remain the one enabled action, got %+v", r.Expiration)
	}
}

func TestBuildLifecycleConfiguration_NoActionsRejected(t *testing.T) {
	// Disabling every action (negative transition, negative abort, no
	// expiration) would emit an action-less rule that AWS rejects, so the
	// builder must reject it locally with a clear error.
	_, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{
		Prefix:                       "telemetry",
		TransitionDays:               -1,
		AbortIncompleteMultipartDays: -1,
	})
	if err == nil {
		t.Fatal("expected an error for a rule with no actions, got nil")
	}
	if !strings.Contains(err.Error(), "no actions") {
		t.Errorf("error should explain the rule has no actions, got %q", err.Error())
	}
}

func TestEffectiveTransitionDays(t *testing.T) {
	cases := []struct {
		name       string
		configured int32
		want       int32
	}{
		{"zero uses default", 0, DefaultDeepArchiveTransitionDays},
		{"positive passthrough", 45, 45},
		{"negative disables", -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveTransitionDays(tc.configured); got != tc.want {
				t.Errorf("EffectiveTransitionDays(%d) = %d, want %d", tc.configured, got, tc.want)
			}
		})
	}
	// The exported resolver must agree with the value the builder actually
	// applies, so a caller logging EffectiveTransitionDays reports the truth.
	lc, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := i32(lc.Rules[0].Transitions[0].Days); got != EffectiveTransitionDays(0) {
		t.Errorf("built transition days = %d, want EffectiveTransitionDays(0) = %d",
			got, EffectiveTransitionDays(0))
	}
}

func TestBuildLifecycleConfiguration_EmptyPrefixMatchesWholeBucket(t *testing.T) {
	lc, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := lc.Rules[0]
	if r.Filter == nil || deref(r.Filter.Prefix) != "" {
		t.Errorf("empty prefix should yield empty-prefix filter, got %+v", r.Filter)
	}
}

func TestBuildLifecycleConfiguration_ExpirationBeforeTransitionRejected(t *testing.T) {
	_, err := BuildLifecycleConfiguration(LifecyclePolicyConfig{
		TransitionDays: 90,
		ExpirationDays: 30,
	})
	if err == nil {
		t.Fatal("want error when expiration precedes transition, got nil")
	}
}

func TestApplyLifecyclePolicy(t *testing.T) {
	api := &fakeLifecycleAPI{}
	if err := ApplyLifecyclePolicy(context.Background(), api, "my-bucket",
		LifecyclePolicyConfig{Prefix: "telemetry"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.calls != 1 {
		t.Fatalf("want 1 Put call, got %d", api.calls)
	}
	if deref(api.last.Bucket) != "my-bucket" {
		t.Errorf("bucket = %q, want my-bucket", deref(api.last.Bucket))
	}
	if api.last.LifecycleConfiguration == nil || len(api.last.LifecycleConfiguration.Rules) != 1 {
		t.Fatalf("expected one lifecycle rule in PUT input")
	}
}

func TestApplyLifecyclePolicy_Idempotent(t *testing.T) {
	api := &fakeLifecycleAPI{}
	cfg := LifecyclePolicyConfig{Prefix: "telemetry"}
	for i := 0; i < 3; i++ {
		if err := ApplyLifecyclePolicy(context.Background(), api, "b", cfg); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// Each PUT replaces the whole document with the same deterministic
	// rule, so re-applying converges rather than appending duplicates.
	if got := len(api.last.LifecycleConfiguration.Rules); got != 1 {
		t.Fatalf("want 1 rule after repeated applies, got %d", got)
	}
}

func TestApplyLifecyclePolicy_Validation(t *testing.T) {
	api := &fakeLifecycleAPI{}
	if err := ApplyLifecyclePolicy(context.Background(), nil, "b", LifecyclePolicyConfig{}); err == nil {
		t.Error("want error for nil API")
	}
	if err := ApplyLifecyclePolicy(context.Background(), api, "  ", LifecyclePolicyConfig{}); err == nil {
		t.Error("want error for blank bucket")
	}
	if api.calls != 0 {
		t.Errorf("no Put should be issued on validation failure, got %d", api.calls)
	}
}

func TestApplyLifecyclePolicy_PropagatesAPIError(t *testing.T) {
	api := &fakeLifecycleAPI{failErr: errors.New("access denied")}
	err := ApplyLifecyclePolicy(context.Background(), api, "b", LifecyclePolicyConfig{})
	if err == nil {
		t.Fatal("want error when API fails")
	}
}

func TestWriterEnsureLifecyclePolicy_UsesWriterBucketAndPrefix(t *testing.T) {
	w, err := New(&fakeS3{}, Config{Bucket: "telem-bucket", Prefix: "cold-archive"}, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Stop(context.Background()) }()

	api := &fakeLifecycleAPI{}
	if err := w.EnsureLifecyclePolicy(context.Background(), api, 0); err != nil {
		t.Fatalf("EnsureLifecyclePolicy: %v", err)
	}
	if deref(api.last.Bucket) != "telem-bucket" {
		t.Errorf("bucket = %q, want telem-bucket", deref(api.last.Bucket))
	}
	r := api.last.LifecycleConfiguration.Rules[0]
	if deref(r.Filter.Prefix) != "cold-archive" {
		t.Errorf("filter prefix = %q, want cold-archive", deref(r.Filter.Prefix))
	}
	// transitionDays 0 ⇒ the 90-day default.
	if got := i32(r.Transitions[0].Days); got != DefaultDeepArchiveTransitionDays {
		t.Errorf("transition days = %d, want %d", got, DefaultDeepArchiveTransitionDays)
	}
}

func TestWriterEnsureLifecyclePolicy_DefaultPrefixApplied(t *testing.T) {
	// Empty prefix in Config is defaulted to "telemetry" by New; the
	// lifecycle filter must match what the writer actually writes under.
	w, err := New(&fakeS3{}, Config{Bucket: "b"}, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Stop(context.Background()) }()

	api := &fakeLifecycleAPI{}
	if err := w.EnsureLifecyclePolicy(context.Background(), api, 45); err != nil {
		t.Fatalf("EnsureLifecyclePolicy: %v", err)
	}
	r := api.last.LifecycleConfiguration.Rules[0]
	if deref(r.Filter.Prefix) != "telemetry" {
		t.Errorf("filter prefix = %q, want default telemetry", deref(r.Filter.Prefix))
	}
	if got := i32(r.Transitions[0].Days); got != 45 {
		t.Errorf("transition days = %d, want 45", got)
	}
}
