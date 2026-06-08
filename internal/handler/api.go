package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultMaxJSONBody bounds the size of a JSON request body accepted
// by the common DecodeJSON path. It is generous for the control
// plane's JSON payloads — the largest legitimate string field (a
// policy rule) is capped at 10 KiB elsewhere — while preventing an
// unbounded or hostile body from exhausting server memory before the
// JSON decoder ever runs. The handful of endpoints that legitimately
// accept larger bodies (bulk CSV import, Terraform state) bound their
// raw body explicitly with their own, larger http.MaxBytesReader.
const DefaultMaxJSONBody int64 = 1 << 20 // 1 MiB

// actorFromCtx returns the authenticated user's ID as a
// *uuid.UUID for audit-actor parameters on service methods, or nil
// when the request has no user-bound credential (e.g. API key
// without a user mapping). Centralised here so every handler that
// stamps an audit actor uses an identical conversion — earlier
// revisions had a per-handler `actorPtr` duplicate which let a
// behavioural drift slip in (e.g. one handler returning a fresh
// zero-uuid pointer instead of nil) without compile-time
// detection.
func actorFromCtx(r *http.Request) *uuid.UUID {
	u := middleware.UserIDFromContext(r.Context())
	if u == uuid.Nil {
		return nil
	}
	return &u
}

// MountTenantScoped registers a handler on mux for the given
// `[METHOD] pattern`, automatically applying the RequireTenant
// middleware when the pattern declares a `{tenant_id}` segment.
// This is the single registration entry point every handler's
// Register method uses; it guarantees no tenant-scoped route can
// be added without picking up the tenant-isolation check.
//
// Why we do this per-route (instead of wrapping the entire api
// mux): Go's http.ServeMux only populates r.PathValue after it has
// matched the request pattern, so a wrapper around the bare mux
// would always observe r.PathValue("tenant_id") == "" and silently
// pass the request through. Wrapping the inner handler ensures the
// middleware runs after pattern matching has bound the path values.
func MountTenantScoped(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	if strings.Contains(pattern, "{tenant_id}") {
		mux.Handle(pattern, middleware.RequireTenant("tenant_id")(h))
		return
	}
	mux.HandleFunc(pattern, h)
}

// ErrorEnvelope is the canonical structured-error response body.
type ErrorEnvelope struct {
	Error ErrorPayload `json:"error"`
}

// ErrorPayload is the nested error object.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError writes a structured error response.
func WriteError(w http.ResponseWriter, status int, code, msg string, details ...any) {
	env := ErrorEnvelope{Error: ErrorPayload{Code: code, Message: msg}}
	if len(details) == 1 {
		env.Error.Details = details[0]
	}
	WriteJSON(w, status, env)
}

// WriteRepositoryError maps repository sentinel errors to HTTP
// status codes and standardised error codes. The human-readable
// message for the fixed-text cases (not_found, conflict, forbidden,
// internal) is localized to the request locale negotiated by
// LocaleMiddleware, falling back to English when no locale was
// negotiated. The error `code` is locale-invariant.
//
// invalid_argument and resource_exhausted keep err.Error() verbatim:
// those carry caller-facing validation detail (e.g. "slug is
// required") that is generated at the call site, not a fixed catalog
// string, so localizing them would discard the specific context.
func WriteRepositoryError(w http.ResponseWriter, err error) {
	loc := localizerFromWriter(w)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		WriteError(w, http.StatusNotFound, "not_found", loc.Message("error.not_found"))
	case errors.Is(err, repository.ErrConflict):
		WriteError(w, http.StatusConflict, "conflict", loc.Message("error.conflict"))
	case errors.Is(err, repository.ErrForbidden):
		WriteError(w, http.StatusForbidden, "forbidden", loc.Message("error.forbidden"))
	case errors.Is(err, repository.ErrInvalidArgument):
		WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
	case errors.Is(err, repository.ErrResourceExhausted):
		WriteError(w, http.StatusTooManyRequests, "resource_exhausted", err.Error())
	default:
		WriteError(w, http.StatusInternalServerError, "internal_error", loc.Message("error.internal"))
	}
}

// DecodeJSON deserializes the request body into dst, bounding it to
// DefaultMaxJSONBody. Returns a rendered 400 if the body is malformed
// (or carries trailing data) and a 413 if it exceeds the limit. On any
// error it renders the response and returns false.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return DecodeJSONLimit(w, r, dst, DefaultMaxJSONBody)
}

// DecodeJSONLimit is DecodeJSON with an explicit maximum body size, for
// the few endpoints whose legitimate payloads are larger (or smaller)
// than the default. It wraps the body in http.MaxBytesReader BEFORE
// decoding so an oversized body is rejected as it streams in, never
// fully buffered, and rejects any trailing bytes after the first JSON
// value (defence against accidental concatenation / smuggling).
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("request body exceeds the %d-byte limit", maxBytes))
			return false
		}
		WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return false
	}
	// A well-formed request carries exactly one JSON value; anything
	// after it is rejected so a client cannot smuggle a second document
	// past the decoder.
	if dec.More() {
		WriteError(w, http.StatusBadRequest, "invalid_body", "unexpected trailing data after JSON value")
		return false
	}
	return true
}

// PathUUID extracts a UUID path parameter or writes a 400 and
// returns uuid.Nil + false if it's missing or malformed.
func PathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	if raw == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", name+" is required")
		return uuid.Nil, false
	}
	u, err := uuid.Parse(raw)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_param", name+" is not a valid UUID")
		return uuid.Nil, false
	}
	return u, true
}

// QueryLimit parses ?limit= or returns the repository default.
func QueryLimit(r *http.Request) int {
	q := r.URL.Query().Get("limit")
	if q == "" {
		return 0 // repository normalises 0 → DefaultPageLimit
	}
	var n int
	if _, err := jsonNumber(q, &n); err != nil {
		return 0
	}
	return n
}

// jsonNumber parses a positive integer string into n.
func jsonNumber(s string, n *int) (int, error) {
	if len(s) == 0 {
		return 0, errors.New("empty")
	}
	var v int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not numeric")
		}
		v = v*10 + int(c-'0')
		if v > repository.MaxPageLimit {
			v = repository.MaxPageLimit
		}
	}
	*n = v
	return v, nil
}
