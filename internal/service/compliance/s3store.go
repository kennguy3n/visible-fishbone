package compliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3API is the subset of the AWS S3 v2 client surface the evidence
// archive uses. Defined as an interface so tests inject a fake without
// MinIO, mirroring telemetry/s3.API.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Config configures an S3ObjectStore.
type S3Config struct {
	// Bucket is the destination bucket. Required. For multi-year
	// retention to be enforced the bucket SHOULD have S3 Object Lock
	// enabled; see RetentionYears.
	Bucket string
	// StorageClass for archived bundles. Defaults to "STANDARD_IA"
	// (rarely read, cheaper to store) when empty.
	StorageClass string
	// RetentionYears is the compliance object-lock window applied to
	// every uploaded bundle. When > 0 and the bucket has Object Lock
	// enabled, each PUT sets ObjectLockMode=COMPLIANCE with a
	// retain-until date this many years out, so not even the root
	// account can delete the evidence before it expires. Defaults to
	// DefaultRetentionYears when zero; set to -1 to disable
	// (e.g. buckets without Object Lock).
	RetentionYears int
}

// S3ObjectStore is the production ObjectStore: it archives evidence
// bundle bytes to S3 under a compliance object-lock retention policy.
type S3ObjectStore struct {
	client         s3API
	bucket         string
	storageClass   types.StorageClass
	retentionYears int
	now            func() time.Time
}

var _ ObjectStore = (*S3ObjectStore)(nil)

// NewS3ObjectStore constructs an S3-backed evidence store.
func NewS3ObjectStore(client s3API, cfg S3Config) (*S3ObjectStore, error) {
	if client == nil {
		return nil, errors.New("compliance: NewS3ObjectStore requires an S3 client")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("compliance: NewS3ObjectStore requires a bucket")
	}
	sc := types.StorageClassStandardIa
	if cfg.StorageClass != "" {
		sc = types.StorageClass(cfg.StorageClass)
	}
	retention := cfg.RetentionYears
	switch {
	case retention == 0:
		retention = DefaultRetentionYears
	case retention < 0:
		retention = 0
	}
	return &S3ObjectStore{
		client:         client,
		bucket:         cfg.Bucket,
		storageClass:   sc,
		retentionYears: retention,
		now:            func() time.Time { return time.Now().UTC() },
	}, nil
}

// Put uploads body at key with the configured retention policy.
func (s *S3ObjectStore) Put(ctx context.Context, key string, body []byte) error {
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentType:   aws.String("application/json"),
		ContentLength: aws.Int64(int64(len(body))),
		StorageClass:  s.storageClass,
	}
	if s.retentionYears > 0 {
		in.ObjectLockMode = types.ObjectLockModeCompliance
		in.ObjectLockRetainUntilDate = aws.Time(s.now().AddDate(s.retentionYears, 0, 0))
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("compliance: s3 put %q: %w", key, err)
	}
	return nil
}

// Get downloads the bytes previously written at key.
func (s *S3ObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: s3 get %q: %w", key, err)
	}
	body, err := drainBody(out.Body)
	if err != nil {
		return nil, fmt.Errorf("compliance: s3 read %q: %w", key, err)
	}
	return body, nil
}
