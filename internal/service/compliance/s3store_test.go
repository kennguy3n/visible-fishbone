package compliance_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

// fakeS3 implements the (unexported) s3API the store depends on. It can
// be passed to NewS3ObjectStore by structural typing even though the
// interface name is package-private.
type fakeS3 struct {
	objects map[string][]byte
	lastPut *s3.PutObjectInput
	putErr  error
	getErr  error
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]byte{}} }

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.lastPut = in
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Key] = body
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	body, ok := f.objects[*in.Key]
	if !ok {
		return nil, errors.New("not found")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func TestS3ObjectStore_PutAppliesRetentionAndStorageClass(t *testing.T) {
	fake := newFakeS3()
	store, err := compliance.NewS3ObjectStore(fake, compliance.S3Config{Bucket: "evidence"})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}

	payload := []byte(`{"k":"v"}`)
	if err := store.Put(context.Background(), "key1", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}

	put := fake.lastPut
	if put == nil {
		t.Fatal("PutObject not called")
	}
	if got := string(put.StorageClass); got != string(types.StorageClassStandardIa) {
		t.Fatalf("storage class = %q, want STANDARD_IA", got)
	}
	// Default retention (7y) → object lock COMPLIANCE with a future
	// retain-until date.
	if put.ObjectLockMode != types.ObjectLockModeCompliance {
		t.Fatalf("object lock mode = %q, want COMPLIANCE", put.ObjectLockMode)
	}
	if put.ObjectLockRetainUntilDate == nil {
		t.Fatal("expected retain-until date for default retention")
	}
	if put.ContentType == nil || *put.ContentType != "application/json" {
		t.Fatalf("content type = %v, want application/json", put.ContentType)
	}
}

func TestS3ObjectStore_RetentionDisabled(t *testing.T) {
	fake := newFakeS3()
	store, err := compliance.NewS3ObjectStore(fake, compliance.S3Config{Bucket: "evidence", RetentionYears: -1})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	if err := store.Put(context.Background(), "key1", []byte("{}")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if fake.lastPut.ObjectLockMode != "" {
		t.Fatalf("expected no object lock when retention disabled, got %q", fake.lastPut.ObjectLockMode)
	}
	if fake.lastPut.ObjectLockRetainUntilDate != nil {
		t.Fatal("expected no retain-until date when retention disabled")
	}
}

func TestS3ObjectStore_PutGetRoundTrip(t *testing.T) {
	fake := newFakeS3()
	store, err := compliance.NewS3ObjectStore(fake, compliance.S3Config{Bucket: "evidence", StorageClass: "STANDARD"})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)
	if err := store.Put(context.Background(), "k", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get = %q, want %q", got, payload)
	}
	if string(fake.lastPut.StorageClass) != "STANDARD" {
		t.Fatalf("storage class = %q, want STANDARD", fake.lastPut.StorageClass)
	}
}

func TestS3ObjectStore_Validation(t *testing.T) {
	if _, err := compliance.NewS3ObjectStore(nil, compliance.S3Config{Bucket: "b"}); err == nil {
		t.Fatal("expected error for nil client")
	}
	if _, err := compliance.NewS3ObjectStore(newFakeS3(), compliance.S3Config{}); err == nil {
		t.Fatal("expected error for missing bucket")
	}
}

func TestS3ObjectStore_PutErrorPropagates(t *testing.T) {
	fake := newFakeS3()
	fake.putErr = errors.New("s3 down")
	store, err := compliance.NewS3ObjectStore(fake, compliance.S3Config{Bucket: "evidence"})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	if err := store.Put(context.Background(), "k", []byte("{}")); err == nil {
		t.Fatal("expected Put error to propagate")
	}
}
