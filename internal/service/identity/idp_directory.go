package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// directoryAPITimeout bounds a single directory API request.
const directoryAPITimeout = 15 * time.Second

// maxDirectoryResponseBytes caps a single directory API response body to
// guard against a hostile or malfunctioning provider streaming an
// unbounded payload into memory.
const maxDirectoryResponseBytes = 8 << 20 // 8 MiB

// DefaultDirectoryClientFactory builds provider-specific directory
// clients (Okta, Microsoft Graph, Google Admin SDK, Zoho Directory) over
// a shared HTTP client. A nil http client falls back to a
// timeout-bounded default.
type DefaultDirectoryClientFactory struct {
	HTTP *http.Client
}

// Build returns a DirectoryClient for the config's provider type.
func (f DefaultDirectoryClientFactory) Build(cfg repository.IDPConfig, cred DirectoryCredential) (DirectoryClient, error) {
	httpc := f.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: directoryAPITimeout}
	}
	if strings.TrimSpace(cred.Token) == "" {
		return nil, fmt.Errorf("directory credential token is empty: %w", repository.ErrInvalidArgument)
	}

	switch cfg.ProviderType {
	case repository.IDPProviderOkta:
		base := strings.TrimRight(cred.BaseURL, "/")
		if base == "" {
			return nil, fmt.Errorf("okta directory requires an org base URL: %w", repository.ErrInvalidArgument)
		}
		return &oktaDirectoryClient{http: httpc, base: base, token: cred.Token}, nil
	case repository.IDPProviderMicrosoft365:
		base := strings.TrimRight(cred.BaseURL, "/")
		if base == "" {
			base = "https://graph.microsoft.com"
		}
		return &graphDirectoryClient{http: httpc, base: base, token: cred.Token}, nil
	case repository.IDPProviderGoogleWorkspace:
		base := strings.TrimRight(cred.BaseURL, "/")
		if base == "" {
			base = "https://admin.googleapis.com"
		}
		return &googleDirectoryClient{http: httpc, base: base, token: cred.Token}, nil
	case repository.IDPProviderZoho:
		base := strings.TrimRight(cred.BaseURL, "/")
		if base == "" {
			base = "https://directory.zoho.com"
		}
		return &zohoDirectoryClient{http: httpc, base: base, token: cred.Token}, nil
	default:
		return nil, fmt.Errorf("provider %q has no directory client: %w", cfg.ProviderType, repository.ErrInvalidArgument)
	}
}

// getJSON performs a GET with the given Authorization header and decodes
// a bounded JSON response into dst.
func getJSON(ctx context.Context, httpc *http.Client, rawURL, authHeader string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s returned %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(body, dst)
}

// --- Okta -----------------------------------------------------------------

// oktaDirectoryClient reads the Okta Users API
// (https://developer.okta.com/docs/reference/api/users/). It authenticates
// with an SSWS API token, follows the RFC 5988 `Link` rel="next" cursor,
// and resolves each user's group memberships via the per-user groups
// endpoint.
type oktaDirectoryClient struct {
	http  *http.Client
	base  string
	token string
}

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login       string `json:"login"`
		Email       string `json:"email"`
		FirstName   string `json:"firstName"`
		LastName    string `json:"lastName"`
		DisplayName string `json:"displayName"`
	} `json:"profile"`
}

type oktaGroup struct {
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
}

func (c *oktaDirectoryClient) auth() string { return "SSWS " + c.token }

func (c *oktaDirectoryClient) ListUsers(ctx context.Context) ([]DirectoryUser, error) {
	next := c.base + "/api/v1/users?limit=200"
	var out []DirectoryUser
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", c.auth())
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryResponseBytes))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("okta list users returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var page []oktaUser
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("okta decode users: %w", err)
		}
		for _, u := range page {
			email := u.Profile.Email
			if email == "" {
				email = u.Profile.Login
			}
			groups, gerr := c.userGroups(ctx, u.ID)
			if gerr != nil {
				return nil, fmt.Errorf("okta groups for %s: %w", u.ID, gerr)
			}
			out = append(out, DirectoryUser{
				ExternalID:  u.ID,
				Email:       strings.ToLower(email),
				DisplayName: oktaDisplayName(u),
				Active:      strings.EqualFold(u.Status, "ACTIVE"),
				Groups:      groups,
			})
		}
		next = nextOktaLink(resp.Header.Values("Link"))
	}
	return out, nil
}

func (c *oktaDirectoryClient) userGroups(ctx context.Context, userID string) ([]string, error) {
	var groups []oktaGroup
	u := fmt.Sprintf("%s/api/v1/users/%s/groups", c.base, url.PathEscape(userID))
	if err := getJSON(ctx, c.http, u, c.auth(), &groups); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.Profile.Name != "" {
			names = append(names, g.Profile.Name)
		}
	}
	return names, nil
}

func oktaDisplayName(u oktaUser) string {
	if u.Profile.DisplayName != "" {
		return u.Profile.DisplayName
	}
	full := strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName)
	return full
}

// nextOktaLink extracts the rel="next" URL from Okta's RFC 5988 Link
// headers, returning "" when there is no further page.
func nextOktaLink(links []string) string {
	for _, header := range links {
		for _, part := range strings.Split(header, ",") {
			segs := strings.Split(part, ";")
			if len(segs) < 2 {
				continue
			}
			rel := ""
			for _, s := range segs[1:] {
				s = strings.TrimSpace(s)
				if strings.HasPrefix(s, "rel=") {
					rel = strings.Trim(strings.TrimPrefix(s, "rel="), `"`)
				}
			}
			if rel != "next" {
				continue
			}
			raw := strings.TrimSpace(segs[0])
			raw = strings.TrimPrefix(raw, "<")
			raw = strings.TrimSuffix(raw, ">")
			return raw
		}
	}
	return ""
}

// --- Microsoft Entra (Graph) ----------------------------------------------

// graphDirectoryClient reads the Microsoft Graph users endpoint
// (https://learn.microsoft.com/graph/api/user-list). It authenticates
// with a bearer access token, follows `@odata.nextLink`, and resolves
// each user's group memberships via /memberOf.
type graphDirectoryClient struct {
	http  *http.Client
	base  string
	token string
}

type graphUserPage struct {
	NextLink string `json:"@odata.nextLink"`
	Value    []struct {
		ID                string `json:"id"`
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
		DisplayName       string `json:"displayName"`
		AccountEnabled    bool   `json:"accountEnabled"`
	} `json:"value"`
}

type graphGroupPage struct {
	NextLink string `json:"@odata.nextLink"`
	Value    []struct {
		Type        string `json:"@odata.type"`
		DisplayName string `json:"displayName"`
	} `json:"value"`
}

func (c *graphDirectoryClient) auth() string { return "Bearer " + c.token }

func (c *graphDirectoryClient) ListUsers(ctx context.Context) ([]DirectoryUser, error) {
	next := c.base + "/v1.0/users?$select=id,userPrincipalName,mail,displayName,accountEnabled&$top=999"
	var out []DirectoryUser
	for next != "" {
		var page graphUserPage
		if err := getJSON(ctx, c.http, next, c.auth(), &page); err != nil {
			return nil, fmt.Errorf("graph list users: %w", err)
		}
		for _, u := range page.Value {
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			groups, gerr := c.userGroups(ctx, u.ID)
			if gerr != nil {
				return nil, fmt.Errorf("graph groups for %s: %w", u.ID, gerr)
			}
			out = append(out, DirectoryUser{
				ExternalID:  u.ID,
				Email:       strings.ToLower(email),
				DisplayName: u.DisplayName,
				Active:      u.AccountEnabled,
				Groups:      groups,
			})
		}
		next = page.NextLink
	}
	return out, nil
}

func (c *graphDirectoryClient) userGroups(ctx context.Context, userID string) ([]string, error) {
	next := fmt.Sprintf("%s/v1.0/users/%s/memberOf?$select=displayName&$top=999", c.base, url.PathEscape(userID))
	var names []string
	for next != "" {
		var page graphGroupPage
		if err := getJSON(ctx, c.http, next, c.auth(), &page); err != nil {
			return nil, err
		}
		for _, g := range page.Value {
			// Only directory groups confer membership; skip directory
			// roles / administrative units that also surface on memberOf.
			if g.DisplayName != "" && (g.Type == "" || strings.EqualFold(g.Type, "#microsoft.graph.group")) {
				names = append(names, g.DisplayName)
			}
		}
		next = page.NextLink
	}
	return names, nil
}

// --- Google Workspace -----------------------------------------------------

// googleDirectoryClient reads the Google Admin SDK Directory API
// (https://developers.google.com/admin-sdk/directory). It authenticates
// with a bearer access token (minted by the credential resolver, e.g.
// via domain-wide delegation), follows `nextPageToken`, and resolves
// each user's group memberships via groups.list?userKey=.
type googleDirectoryClient struct {
	http  *http.Client
	base  string
	token string
}

type googleUserPage struct {
	NextPageToken string `json:"nextPageToken"`
	Users         []struct {
		ID           string `json:"id"`
		PrimaryEmail string `json:"primaryEmail"`
		Suspended    bool   `json:"suspended"`
		Archived     bool   `json:"archived"`
		Name         struct {
			FullName string `json:"fullName"`
		} `json:"name"`
	} `json:"users"`
}

type googleGroupPage struct {
	NextPageToken string `json:"nextPageToken"`
	Groups        []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"groups"`
}

func (c *googleDirectoryClient) auth() string { return "Bearer " + c.token }

func (c *googleDirectoryClient) ListUsers(ctx context.Context) ([]DirectoryUser, error) {
	var out []DirectoryUser
	pageToken := ""
	for {
		q := url.Values{}
		q.Set("customer", "my_customer")
		q.Set("maxResults", "500")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u := c.base + "/admin/directory/v1/users?" + q.Encode()

		var page googleUserPage
		if err := getJSON(ctx, c.http, u, c.auth(), &page); err != nil {
			return nil, fmt.Errorf("google list users: %w", err)
		}
		for _, gu := range page.Users {
			groups, gerr := c.userGroups(ctx, gu.PrimaryEmail)
			if gerr != nil {
				return nil, fmt.Errorf("google groups for %s: %w", gu.PrimaryEmail, gerr)
			}
			out = append(out, DirectoryUser{
				ExternalID:  gu.ID,
				Email:       strings.ToLower(gu.PrimaryEmail),
				DisplayName: gu.Name.FullName,
				Active:      !gu.Suspended && !gu.Archived,
				Groups:      groups,
			})
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

func (c *googleDirectoryClient) userGroups(ctx context.Context, userKey string) ([]string, error) {
	if userKey == "" {
		return nil, nil
	}
	var names []string
	pageToken := ""
	for {
		q := url.Values{}
		q.Set("userKey", userKey)
		q.Set("maxResults", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u := c.base + "/admin/directory/v1/groups?" + q.Encode()

		var page googleGroupPage
		if err := getJSON(ctx, c.http, u, c.auth(), &page); err != nil {
			return nil, err
		}
		for _, g := range page.Groups {
			switch {
			case g.Name != "":
				names = append(names, g.Name)
			case g.Email != "":
				names = append(names, g.Email)
			}
		}
		if page.NextPageToken == "" {
			return names, nil
		}
		pageToken = page.NextPageToken
	}
}

// --- Zoho Directory -------------------------------------------------------

// zohoPageLimit is the per-request user page size requested from the
// Zoho Directory Users API. Zoho paginates with an offset (`start`,
// 1-based) plus a `limit`.
const zohoPageLimit = 200

// zohoMaxUserPages bounds the directory user pagination loop. It exists
// only to stop a misbehaving provider (one that always reports "more
// records" while ignoring the offset) from looping forever. On hitting
// it the client returns an ERROR rather than a truncated snapshot,
// because the reconcile treats an absent user as off-boarded — so a
// silently-truncated list would mass-deactivate present users. Failing
// fast leaves the local store untouched (fail-safe toward MORE access,
// never less).
const zohoMaxUserPages = 10000

// zohoDirectoryClient reads the Zoho Directory Users API
// (https://www.zoho.com/directory/). It authenticates with a Zoho OAuth2
// access token using the `Zoho-oauthtoken` Authorization scheme common
// to every Zoho REST API, paginates the offset-based Users endpoint, and
// resolves each user's group memberships via the per-user groups
// endpoint — mirroring the Okta / Graph / Google connectors.
//
// The wire shapes below are modeled from Zoho's published API
// conventions (OAuth token scheme, offset pagination, `page_context`
// continuation flag), NOT validated against a live Zoho tenant — the
// same doc-derived basis as the existing connectors and the SCIM
// conformance vectors. Field decoding is kept tolerant (id accepts a
// JSON number or string; email and name each fall back across the
// documented attribute names) so a minor wire variation degrades a
// field rather than breaking the whole connector. The data-center base
// URL is overridable via the directory credential (directory.zoho.eu,
// .in, .com.au, .jp, …).
type zohoDirectoryClient struct {
	http  *http.Client
	base  string
	token string
}

// zohoID tolerates Zoho returning an identifier as either a JSON number
// (its usual ZUID shape) or a quoted string, so a minor wire variation
// does not break decoding the whole page.
type zohoID string

func (z *zohoID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		s = ""
	}
	*z = zohoID(s)
	return nil
}

type zohoUser struct {
	ZUID                zohoID `json:"zuid"`
	Email               string `json:"email"`
	PrimaryEmailAddress string `json:"primary_email_address"`
	FirstName           string `json:"first_name"`
	LastName            string `json:"last_name"`
	DisplayName         string `json:"display_name"`
	FullName            string `json:"full_name"`
	// Status is Zoho's lifecycle string. A user is treated as off-boarded
	// only when the status is a RECOGNISED disabled value (see
	// zohoActive); an empty or unrecognised status leaves the user active.
	// This direction is deliberate: a status-vocabulary mismatch must
	// never mass-deactivate present users (the reconcile off-boards
	// absent/inactive locals), so the connector fails safe toward MORE
	// access. The disabled vocabulary is doc-modeled and a certification
	// item (see the connector doc comment).
	Status string `json:"status"`
}

type zohoUserPage struct {
	Users       []zohoUser `json:"users"`
	PageContext struct {
		HasMoreRecords bool `json:"has_more_records"`
	} `json:"page_context"`
}

type zohoGroupPage struct {
	Groups []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"groups"`
	PageContext struct {
		HasMoreRecords bool `json:"has_more_records"`
	} `json:"page_context"`
}

func (c *zohoDirectoryClient) auth() string { return "Zoho-oauthtoken " + c.token }

func (c *zohoDirectoryClient) ListUsers(ctx context.Context) ([]DirectoryUser, error) {
	out := []DirectoryUser{}
	start := 1
	for page := 0; ; page++ {
		if page >= zohoMaxUserPages {
			return nil, fmt.Errorf("zoho list users exceeded %d pages; aborting rather than returning a truncated (off-boarding) snapshot", zohoMaxUserPages)
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(zohoPageLimit))
		q.Set("start", strconv.Itoa(start))
		u := c.base + "/api/v1/users?" + q.Encode()

		var pg zohoUserPage
		if err := getJSON(ctx, c.http, u, c.auth(), &pg); err != nil {
			return nil, fmt.Errorf("zoho list users: %w", err)
		}
		for _, zu := range pg.Users {
			email := zohoEmail(zu)
			groups, gerr := c.userGroups(ctx, string(zu.ZUID))
			if gerr != nil {
				return nil, fmt.Errorf("zoho groups for %s: %w", zu.ZUID, gerr)
			}
			out = append(out, DirectoryUser{
				ExternalID:  string(zu.ZUID),
				Email:       strings.ToLower(email),
				DisplayName: zohoDisplayName(zu),
				Active:      zohoActive(zu.Status),
				Groups:      groups,
			})
		}
		// The server's continuation flag is authoritative (as the cursor
		// is for the other connectors). An empty page that still claims
		// "more" would otherwise spin, so stop there too.
		if !pg.PageContext.HasMoreRecords || len(pg.Users) == 0 {
			return out, nil
		}
		start += len(pg.Users)
	}
}

func (c *zohoDirectoryClient) userGroups(ctx context.Context, zuid string) ([]string, error) {
	if zuid == "" {
		return nil, nil
	}
	var names []string
	start := 1
	for page := 0; ; page++ {
		if page >= zohoMaxUserPages {
			return nil, fmt.Errorf("zoho groups for %s exceeded %d pages", zuid, zohoMaxUserPages)
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(zohoPageLimit))
		q.Set("start", strconv.Itoa(start))
		u := fmt.Sprintf("%s/api/v1/users/%s/groups?%s", c.base, url.PathEscape(zuid), q.Encode())

		var pg zohoGroupPage
		if err := getJSON(ctx, c.http, u, c.auth(), &pg); err != nil {
			return nil, err
		}
		for _, g := range pg.Groups {
			switch {
			case g.Name != "":
				names = append(names, g.Name)
			case g.Email != "":
				names = append(names, g.Email)
			}
		}
		if !pg.PageContext.HasMoreRecords || len(pg.Groups) == 0 {
			return names, nil
		}
		start += len(pg.Groups)
	}
}

// zohoEmail resolves a Zoho user's primary email, tolerating the two
// documented attribute names (`email`, `primary_email_address`).
func zohoEmail(u zohoUser) string {
	if u.Email != "" {
		return u.Email
	}
	return u.PrimaryEmailAddress
}

// zohoActive reports whether a Zoho lifecycle status denotes an active
// account. It is intentionally lenient — active UNLESS the status is a
// recognised disabled value — so an empty or unexpected status never
// causes the reconcile to off-board a present user. Cutting access for a
// genuinely disabled user still happens, but only on a positively
// recognised disabled state; widening this vocabulary is a
// certification-time task against a live tenant.
func zohoActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "disabled", "inactive", "deactivated", "deleted", "suspended", "blocked":
		return false
	default:
		return true
	}
}

// zohoDisplayName prefers an explicit display/full name, falling back to
// the assembled first + last name.
func zohoDisplayName(u zohoUser) string {
	switch {
	case u.DisplayName != "":
		return u.DisplayName
	case u.FullName != "":
		return u.FullName
	default:
		return strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
}
