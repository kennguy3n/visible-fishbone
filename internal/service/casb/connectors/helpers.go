package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// boolCheck builds a pass/fail posture check from a boolean control
// state. ok==true yields a Pass with passEvidence; ok==false yields a
// Fail with failEvidence. It keeps the many provider posture
// assessments terse and consistent.
func boolCheck(name, category string, ok bool, passEvidence, failEvidence string) casb.PostureCheck {
	if ok {
		return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusPass, Evidence: passEvidence}
	}
	return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusFail, Evidence: failEvidence}
}

// leastPrivilegeAdminCheck rates the admin-to-user ratio of a SaaS
// tenant. A handful of admins is healthy; an unbounded or excessive
// admin population is a classic over-privilege finding (and a larger
// blast radius on account takeover). Thresholds: <=25% passes,
// <=50% warns, otherwise fails. A tenant with no enumerated users
// cannot be rated, so it warns rather than falsely passing.
func leastPrivilegeAdminCheck(prefix string, totalUsers, admins int) casb.PostureCheck {
	const name = "least_privilege_admins"
	const category = "access_control"
	if totalUsers == 0 {
		return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusWarn,
			Evidence: prefix + ": no users enumerated; admin ratio not assessable"}
	}
	evidence := fmt.Sprintf("%s: %d of %d users are administrators", prefix, admins, totalUsers)
	ratio := float64(admins) / float64(totalUsers)
	switch {
	case ratio <= 0.25:
		return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusPass, Evidence: evidence}
	case ratio <= 0.5:
		return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusWarn,
			Evidence: evidence + " (elevated)"}
	default:
		return casb.PostureCheck{Name: name, Category: category, Status: casb.CheckStatusFail,
			Evidence: evidence + " (excessive)"}
	}
}

// This file holds the HTTP + auth plumbing shared by the WS4 CASB
// connectors. Each connector stays small and declarative by
// delegating request execution, error shaping, base-URL validation,
// and token minting here, so the 16 providers share one audited,
// well-tested code path rather than 16 copies of subtly different
// HTTP handling.

// maxErrorBody bounds how much of a non-2xx response body is read
// into an error message. SaaS error pages can be large; a 2 KiB cap
// keeps logs and audit trails bounded while preserving the useful
// leading JSON error envelope every provider returns.
const maxErrorBody = 2 << 10

// newJSONRequest builds a request with the JSON Accept header set.
// body may be nil for GET/DELETE. When body is non-nil the
// Content-Type is set to application/json.
func newJSONRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// bearer sets an OAuth2 Bearer Authorization header.
func bearer(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}

// doJSON sends req through client with the connector's User-Agent,
// enforces a 2xx status, and—when out is non-nil—decodes the JSON
// response body into out. prefix names the connector for error
// wrapping (e.g. "box"). It is the single choke point every
// connector uses so status handling, body-size bounding, and error
// shaping are identical across providers.
func doJSON(client HTTPDoer, userAgent, prefix string, req *http.Request, out any) error {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s %s: %w", prefix, req.Method, req.URL.Path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return fmt.Errorf("%s: %s %s returned %d: %s",
			prefix, req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("%s: decode response: %w", prefix, err)
		}
	}
	return nil
}

// parseInt64 parses a base-10 integer string, returning 0 for empty
// or unparseable input. Used for provider size fields that arrive as
// strings (e.g. Google Drive v3's `size`).
func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// contentTypeFromName resolves the MIME type for a fetched object.
// It prefers a meaningful Content-Type reported by the provider,
// falls back to a guess from the file name's extension, and finally
// to the generic octet-stream so the DLP classifier always receives a
// non-empty content type. A generic/blank reported type does not
// suppress the extension guess (Box, for instance, serves downloads as
// application/octet-stream regardless of the real type).
func contentTypeFromName(reported, name string) string {
	reported = strings.TrimSpace(reported)
	// Strip any "; charset=..." parameter for the genericness check
	// while preserving the original (with charset) when we keep it.
	base := reported
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	if reported != "" && base != "" && base != "application/octet-stream" && base != "binary/octet-stream" {
		return reported
	}
	if ext := name[strings.LastIndexByte(name, '.')+1:]; ext != "" && ext != name {
		if guess := mime.TypeByExtension("." + strings.ToLower(ext)); guess != "" {
			return guess
		}
	}
	if reported != "" {
		return reported
	}
	return "application/octet-stream"
}

// getJSON is the common GET+Bearer+decode path.
func getJSON(ctx context.Context, client HTTPDoer, userAgent, prefix, endpoint, token string, out any) error {
	req, err := newJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	bearer(req, token)
	return doJSON(client, userAgent, prefix, req, out)
}

// fetchContent performs a GET + Bearer request and returns the
// response body bounded to maxBytes, plus the response Content-Type.
// It is the single choke point the content-inspection (DLP retro-scan)
// path uses to pull an object's bytes, so the byte cap that protects
// the control plane from pulling an unbounded blob into memory is
// enforced identically across every connector.
//
// maxBytes <= 0 is treated as "no caller cap" and falls back to a
// hard 64 MiB ceiling so a misconfigured caller can never trigger an
// unbounded read.
//
// Redirects: the injected HTTPDoer (an *http.Client) follows redirects
// with Go's default policy, which strips the Authorization header on a
// cross-host hop. This is the desired behaviour for the providers that
// 302 a content download to a CDN — Box (/files/{id}/content) and M365
// (/drive/items/{id}/content) embed their own auth in the pre-signed
// redirect target, so the Bearer is correctly not leaked off-origin. A
// connector whose content endpoint same-host-redirects to another
// Bearer-protected URL would therefore see a 401; none of the current
// connectors do, but a future one must fetch the final URL directly
// rather than relying on a redirect to carry the token.
func fetchContent(
	ctx context.Context,
	client HTTPDoer,
	userAgent, prefix, endpoint, token string,
	maxBytes int64,
) (data []byte, contentType string, err error) {
	const hardCeiling = 64 << 20
	if maxBytes <= 0 || maxBytes > hardCeiling {
		maxBytes = hardCeiling
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", prefix, err)
	}
	bearer(req, token)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %s %s: %w", prefix, req.Method, req.URL.Path, err)
	}
	defer func() {
		// Drain a bounded remainder so a keep-alive connection can be
		// reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, "", fmt.Errorf("%s: %s %s returned %d: %s",
			prefix, req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Read at most maxBytes; any overflow is dropped by the limiter.
	// The DLP classifier scans a prefix, which is sufficient for the
	// pattern/fingerprint detectors and keeps memory bounded.
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, "", fmt.Errorf("%s: read content: %w", prefix, err)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// getJSONBasic is the common GET + HTTP Basic auth + decode path used
// by the connectors that authenticate with a username/token pair
// (Atlassian email+API token, ServiceNow, Zendesk, Workday).
func getJSONBasic(ctx context.Context, client HTTPDoer, userAgent, prefix, endpoint, user, pass string, out any) error {
	req, err := newJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	req.SetBasicAuth(user, pass)
	return doJSON(client, userAgent, prefix, req, out)
}

// resolveTenantBase resolves the effective base URL for a connector
// whose host is tenant-supplied. When raw is non-empty it is run
// through sanitizeBaseURL (production path, SSRF-validated). When raw
// is empty, defaultBase is used if set (the production default for
// providers like GitLab.com, or the test seam pointing at an
// httptest server); otherwise a "base_url is required" error is
// returned. defaultBase is intentionally not re-sanitized: it is
// operator/test controlled, never tenant-controlled.
func resolveTenantBase(prefix, raw, defaultBase string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return sanitizeBaseURL(prefix, raw)
	}
	if defaultBase != "" {
		return strings.TrimRight(defaultBase, "/"), nil
	}
	return "", fmt.Errorf("%s: base_url is required", prefix)
}

// sanitizeBaseURL validates and normalizes a tenant-supplied base
// URL for a self-hosted / per-tenant-subdomain connector (Jira,
// Confluence, GitLab, ServiceNow, Zendesk, Okta, Workday).
//
// Because the base URL originates from per-tenant configuration in a
// 5000-tenant multi-tenant control plane, it is an SSRF sink: a
// hostile or fat-fingered tenant could otherwise point a connector
// at the metadata service (169.254.169.254), a loopback admin port,
// or an internal RFC 1918 address and have the control plane fetch
// it with the tenant's stored credentials. We therefore require
// https and reject hosts that are IP literals in loopback, private,
// link-local, or unspecified ranges, plus the obvious internal
// hostnames. Public DNS names are allowed (the connector's injected
// HTTP client governs egress); this is config-time defense in depth,
// not a substitute for network egress policy.
func sanitizeBaseURL(prefix, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%s: base_url is required", prefix)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: invalid base_url: %w", prefix, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%s: base_url must use https, got %q", prefix, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%s: base_url must have a host", prefix)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return "", fmt.Errorf("%s: base_url host %q is not externally routable", prefix, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("%s: base_url host %q is in a non-routable range", prefix, host)
		}
	}
	// Normalize: drop any path/query/fragment and trailing slash so
	// callers can append known API paths deterministically.
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

// clientCredentialsToken performs an OAuth2 client-credentials (or
// account-credentials) token exchange and returns the access token.
// When basicUser is non-empty the client id/secret are sent via HTTP
// Basic auth (Zoom, Box CCG with a confidential client); otherwise
// the form is expected to already carry client_id/client_secret.
func clientCredentialsToken(
	ctx context.Context,
	client HTTPDoer,
	userAgent, prefix, tokenURL string,
	form url.Values,
	basicUser, basicPass string,
) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s: %w", prefix, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(client, userAgent, prefix, req, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("%s: token endpoint returned empty access_token", prefix)
	}
	return tok.AccessToken, nil
}

// azureADToken mints an Azure AD v2 client-credentials token for the
// given resource scope (e.g. https://graph.microsoft.com/.default or
// https://management.azure.com/.default). Shared by the Teams and
// Azure Portal connectors.
func azureADToken(
	ctx context.Context,
	client HTTPDoer,
	userAgent, prefix, tokenBaseURL, tenantID, clientID, clientSecret, scope string,
) (string, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", tokenBaseURL, tenantID)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}
	return clientCredentialsToken(ctx, client, userAgent, prefix, tokenURL, form, "", "")
}

// googleSAToken mints an RS256 service-account assertion and
// exchanges it for an access token scoped to scopes. When subject is
// non-empty it is set as the `sub` claim for domain-wide delegation
// (GCP org/IAM read uses the service account itself, so subject is
// usually empty). The key's own token_uri is honored only after
// validating it is an https Google endpoint so a hostile tenant key
// cannot redirect the token POST (SSRF).
func googleSAToken(
	ctx context.Context,
	client HTTPDoer,
	userAgent, prefix string,
	keyJSON []byte,
	scopes, subject string,
	now time.Time,
	defaultTokenURL string,
) (string, error) {
	if trimmed := strings.TrimSpace(string(keyJSON)); trimmed == "" || trimmed == "null" {
		return "", fmt.Errorf("%s: service account key json is required", prefix)
	}
	var key googleSAKey
	if err := json.Unmarshal(keyJSON, &key); err != nil {
		return "", fmt.Errorf("%s: invalid service account key json: %w", prefix, err)
	}
	if key.ClientEmail == "" {
		return "", fmt.Errorf("%s: service account key json missing client_email", prefix)
	}
	if strings.TrimSpace(key.PrivateKey) == "" {
		return "", fmt.Errorf("%s: service account key json missing private_key", prefix)
	}
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%s: parse service account private key: %w", prefix, err)
	}
	tokenURL := defaultTokenURL
	if key.TokenURI != "" {
		if err := validateGoogleTokenURI(key.TokenURI); err != nil {
			return "", fmt.Errorf("%s: %w", prefix, err)
		}
		tokenURL = key.TokenURI
	}
	claims := jwt.MapClaims{
		"iss":   key.ClientEmail,
		"scope": scopes,
		"aud":   tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	if subject != "" {
		claims["sub"] = subject
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if key.PrivateKeyID != "" {
		assertion.Header["kid"] = key.PrivateKeyID
	}
	signed, err := assertion.SignedString(rsaKey)
	if err != nil {
		return "", fmt.Errorf("%s: sign service account assertion: %w", prefix, err)
	}
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {signed},
	}
	return clientCredentialsToken(ctx, client, userAgent, prefix, tokenURL, form, "", "")
}
