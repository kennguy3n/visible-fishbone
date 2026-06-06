package iamcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ManagementUser mirrors the iam-core Management API User resource
// (api/management/v1/management.proto). Only the fields ShieldNet's
// SCIM bridge reads/writes are modelled.
type ManagementUser struct {
	UserID        string `json:"user_id"`
	TenantID      string `json:"tenant_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Blocked       bool   `json:"blocked"`
}

// CreateManagementUser is the POST /api/v1/management/users body.
type CreateManagementUser struct {
	Email         string `json:"email"`
	Password      string `json:"password,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// UpdateManagementUser is the PATCH /api/v1/management/users/{id} body.
// Pointer fields distinguish "leave unchanged" (nil) from "set to
// empty".
type UpdateManagementUser struct {
	Name       *string `json:"name,omitempty"`
	GivenName  *string `json:"given_name,omitempty"`
	FamilyName *string `json:"family_name,omitempty"`
}

// CreateUser provisions a user in iam-core for the given iam-core
// tenant (sent as X-Tenant-ID, the Management API's tenant routing
// header). Authenticated with the cached client_credentials token.
func (c *Client) CreateUser(ctx context.Context, tenantID string, in CreateManagementUser) (ManagementUser, error) {
	var out ManagementUser
	if err := c.mgmtJSON(ctx, http.MethodPost, "/api/v1/management/users", tenantID, in, &out); err != nil {
		return ManagementUser{}, err
	}
	return out, nil
}

// GetUser reads a user by iam-core user_id.
func (c *Client) GetUser(ctx context.Context, tenantID, userID string) (ManagementUser, error) {
	var out ManagementUser
	path := "/api/v1/management/users/" + url.PathEscape(userID)
	if err := c.mgmtJSON(ctx, http.MethodGet, path, tenantID, nil, &out); err != nil {
		return ManagementUser{}, err
	}
	return out, nil
}

// FindUserByEmail looks up a user by email via the list endpoint's
// filter. Returns (user, true, nil) on a unique match, (_, false,
// nil) when none match, and an error on transport/ambiguity. Used by
// the SCIM bridge to reconcile a SNG user to its iam-core identity
// when no stored user_id is known yet.
func (c *Client) FindUserByEmail(ctx context.Context, tenantID, email string) (ManagementUser, bool, error) {
	q := url.Values{}
	q.Set("email", email)
	path := "/api/v1/management/users?" + q.Encode()
	var resp struct {
		Users []ManagementUser `json:"users"`
	}
	if err := c.mgmtJSON(ctx, http.MethodGet, path, tenantID, nil, &resp); err != nil {
		return ManagementUser{}, false, err
	}
	for _, u := range resp.Users {
		if u.Email == email {
			return u, true, nil
		}
	}
	return ManagementUser{}, false, nil
}

// UpdateUser patches a user's profile attributes.
func (c *Client) UpdateUser(ctx context.Context, tenantID, userID string, in UpdateManagementUser) (ManagementUser, error) {
	var out ManagementUser
	path := "/api/v1/management/users/" + url.PathEscape(userID)
	if err := c.mgmtJSON(ctx, http.MethodPatch, path, tenantID, in, &out); err != nil {
		return ManagementUser{}, err
	}
	return out, nil
}

// BlockUser deactivates a user (SCIM active=false).
func (c *Client) BlockUser(ctx context.Context, tenantID, userID string) error {
	path := "/api/v1/management/users/" + url.PathEscape(userID) + "/block"
	return c.mgmtJSON(ctx, http.MethodPost, path, tenantID, nil, nil)
}

// UnblockUser reactivates a previously blocked user (SCIM active=true).
func (c *Client) UnblockUser(ctx context.Context, tenantID, userID string) error {
	path := "/api/v1/management/users/" + url.PathEscape(userID) + "/unblock"
	return c.mgmtJSON(ctx, http.MethodPost, path, tenantID, nil, nil)
}

// DeleteUser permanently removes a user. A 404 is treated as success
// (idempotent delete) by the caller via StatusCode(err) == 404.
func (c *Client) DeleteUser(ctx context.Context, tenantID, userID string) error {
	path := "/api/v1/management/users/" + url.PathEscape(userID)
	return c.mgmtJSON(ctx, http.MethodDelete, path, tenantID, nil, nil)
}

// mgmtJSON performs an authenticated Management API call. It mints/
// reuses the client_credentials token, sets the X-Tenant-ID routing
// header, marshals body (when non-nil), and decodes the JSON response
// into out (when non-nil).
func (c *Client) mgmtJSON(ctx context.Context, method, path, tenantID string, body, out any) error {
	token, err := c.managementToken(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		buf, mErr := json.Marshal(body)
		if mErr != nil {
			return fmt.Errorf("iamcore: marshal %s %s: %w", method, path, mErr)
		}
		reader = bytes.NewReader(buf)
	}
	endpoint := c.cfg.ManagementBaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("iamcore: build %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if tenantID != "" {
		req.Header.Set("X-Tenant-ID", tenantID)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req, method+" "+path, out)
}
