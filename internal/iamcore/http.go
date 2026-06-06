package iamcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// APIError is returned when iam-core responds with a non-2xx status.
// It preserves the HTTP status so callers (e.g. the SCIM bridge) can
// map provider failures onto the right protocol response — most
// importantly treating 404 as "already gone" on delete/deactivate.
type APIError struct {
	Op         string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	body := e.Body
	if len(body) > 256 {
		body = body[:256]
	}
	return fmt.Sprintf("iamcore: %s: unexpected status %d: %s", e.Op, e.StatusCode, body)
}

// StatusCode of an error, or 0 when err is not an *APIError. Lets
// callers branch on the provider's HTTP status without a type switch
// at every site.
func StatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// getJSON issues a GET and decodes a JSON body, bounding the read.
func (c *Client) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("iamcore: build GET %s: %w", endpoint, err)
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, "GET "+endpoint, out)
}

// postForm issues an application/x-www-form-urlencoded POST (the
// OAuth2 token/introspect endpoints) and decodes the JSON response.
// basicID/basicSecret, when non-empty, are sent as HTTP Basic auth for
// confidential client authentication.
//
// The credentials are passed to SetBasicAuth VERBATIM (no
// percent-encoding). RFC 6749 §2.3.1 nominally requires
// application/x-www-form-urlencoded-encoding the client_id/secret
// before HTTP Basic encoding, but iam-core's token endpoint decodes the
// Basic header without form-decoding it (it base64-decodes and splits
// on ':' verbatim — see iam-core internal/server.parseHTTPBasicAuth).
// Percent-encoding here would therefore corrupt any credential
// containing characters url.QueryEscape rewrites (space -> '+',
// '+' -> '%2B', '/', '=' ...). Sending verbatim matches both iam-core's
// parser and golang.org/x/oauth2's client-credentials behaviour.
func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values, basicID, basicSecret string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("iamcore: build POST %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	return c.do(req, "POST "+endpoint, out)
}

// do executes req, enforces a 2xx status, and decodes the (bounded)
// JSON body into out when out is non-nil.
func (c *Client) do(req *http.Request, op string, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("iamcore: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("iamcore: %s: read body: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Op: op, StatusCode: resp.StatusCode, Body: string(body)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("iamcore: %s: decode response: %w", op, err)
	}
	return nil
}
