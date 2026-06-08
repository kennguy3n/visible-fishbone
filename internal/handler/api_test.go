package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sample struct {
	Name string `json:"name"`
}

func decodeInto(body string, maxBytes int64) (*sample, *httptest.ResponseRecorder, bool) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var dst sample
	ok := DecodeJSONLimit(rec, r, &dst, maxBytes)
	return &dst, rec, ok
}

func TestDecodeJSON_Valid(t *testing.T) {
	t.Parallel()
	dst, _, ok := decodeInto(`{"name":"hi"}`, DefaultMaxJSONBody)
	if !ok {
		t.Fatal("valid body rejected")
	}
	if dst.Name != "hi" {
		t.Errorf("name = %q, want hi", dst.Name)
	}
}

func TestDecodeJSON_RejectsOversizedBody(t *testing.T) {
	t.Parallel()
	// Body larger than the 8-byte cap.
	big := `{"name":"` + strings.Repeat("x", 64) + `"}`
	_, rec, ok := decodeInto(big, 8)
	if ok {
		t.Fatal("oversized body accepted")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "request_too_large") {
		t.Errorf("body = %q, want request_too_large code", rec.Body.String())
	}
}

func TestDecodeJSON_RejectsTrailingData(t *testing.T) {
	t.Parallel()
	_, rec, ok := decodeInto(`{"name":"a"}{"name":"b"}`, DefaultMaxJSONBody)
	if ok {
		t.Fatal("trailing data accepted")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "trailing data") {
		t.Errorf("body = %q, want trailing-data message", rec.Body.String())
	}
}

func TestDecodeJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	_, rec, ok := decodeInto(`{"name":"a","bogus":1}`, DefaultMaxJSONBody)
	if ok {
		t.Fatal("unknown field accepted")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestDecodeJSON_AllowsTrailingWhitespace(t *testing.T) {
	t.Parallel()
	// A single value followed by whitespace/newline is well-formed.
	_, _, ok := decodeInto("{\"name\":\"a\"}\n  \n", DefaultMaxJSONBody)
	if !ok {
		t.Fatal("trailing whitespace wrongly rejected")
	}
}
