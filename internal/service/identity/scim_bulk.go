package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SCIM Bulk schema URIs and limits (RFC 7644 §3.7).
const (
	SCIMSchemaBulkRequest  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SCIMSchemaBulkResponse = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

	// SCIMBulkMaxOperations bounds the operations a single bulk request
	// may carry. Advertised verbatim in ServiceProviderConfig so clients
	// chunk large syncs; it also caps the work one request can pin.
	SCIMBulkMaxOperations = 1000
	// SCIMBulkMaxPayloadBytes bounds the decoded bulk payload size.
	SCIMBulkMaxPayloadBytes = 1 << 20 // 1 MiB
)

// SCIMBulkOperation is one operation in a bulk request (RFC 7644 §3.7.1).
type SCIMBulkOperation struct {
	Method string `json:"method"`
	Path   string `json:"path,omitempty"`
	BulkID string `json:"bulkId,omitempty"`
	// Version carries an optional If-Match precondition for the target.
	Version string `json:"version,omitempty"`
	// Data is the resource/PatchOp payload, decoded lazily per method.
	Data json.RawMessage `json:"data,omitempty"`
}

// SCIMBulkRequest is the bulk request envelope.
type SCIMBulkRequest struct {
	Schemas []string `json:"schemas"`
	// FailOnErrors stops processing once this many operations have
	// failed. Zero (the default) means process every operation.
	FailOnErrors int                 `json:"failOnErrors,omitempty"`
	Operations   []SCIMBulkOperation `json:"Operations"`
}

// SCIMBulkOperationResult is one entry in the bulk response.
type SCIMBulkOperationResult struct {
	Method   string     `json:"method"`
	BulkID   string     `json:"bulkId,omitempty"`
	Location string     `json:"location,omitempty"`
	Status   string     `json:"status"`
	Response *SCIMError `json:"response,omitempty"`
}

// SCIMBulkResponse is the bulk response envelope.
type SCIMBulkResponse struct {
	Schemas    []string                  `json:"schemas"`
	Operations []SCIMBulkOperationResult `json:"Operations"`
}

// Bulk processes a SCIM bulk request (RFC 7644 §3.7). Operations are
// applied in request order against the caller's tenant. POST operations
// may carry a client-assigned bulkId; later operations reference the
// resulting server id via a "bulkId:<id>" token in their path or in
// member values, which is resolved before the operation runs. Each
// operation's outcome is reported independently; once FailOnErrors
// failures accrue, remaining operations are skipped (RFC 7644 §3.7.3).
//
// The bulk request is a tenant-scoped batch: every sub-operation runs
// through the same tenant-isolated service methods, so cross-tenant
// data can never be created or addressed from one bulk request.
func (s *SCIMService) Bulk(ctx context.Context, tenantID uuid.UUID, req SCIMBulkRequest) (SCIMBulkResponse, error) {
	if len(req.Operations) == 0 {
		return SCIMBulkResponse{}, fmt.Errorf("bulk request has no operations: %w", repository.ErrInvalidArgument)
	}
	if len(req.Operations) > SCIMBulkMaxOperations {
		return SCIMBulkResponse{}, fmt.Errorf("bulk request exceeds %d operations: %w", SCIMBulkMaxOperations, repository.ErrInvalidArgument)
	}

	resp := SCIMBulkResponse{
		Schemas:    []string{SCIMSchemaBulkResponse},
		Operations: make([]SCIMBulkOperationResult, 0, len(req.Operations)),
	}
	// bulkIDs maps a client bulkId to the server resource id created in
	// this batch, so later operations can reference earlier creations.
	bulkIDs := make(map[string]string)
	failures := 0

	for _, op := range req.Operations {
		res := s.runBulkOp(ctx, tenantID, op, bulkIDs)
		resp.Operations = append(resp.Operations, res)
		if !bulkStatusOK(res.Status) {
			failures++
			if req.FailOnErrors > 0 && failures >= req.FailOnErrors {
				break
			}
		}
	}
	return resp, nil
}

// runBulkOp executes a single bulk operation and maps its outcome to a
// result entry, recording any new bulkId mapping on success.
func (s *SCIMService) runBulkOp(ctx context.Context, tenantID uuid.UUID, op SCIMBulkOperation, bulkIDs map[string]string) SCIMBulkOperationResult {
	res := SCIMBulkOperationResult{Method: strings.ToUpper(op.Method), BulkID: op.BulkID}

	resourceType, rawID, err := parseBulkPath(op.Path)
	if err != nil {
		return bulkError(res, repository.ErrInvalidArgument, err.Error())
	}
	// Resolve a bulkId reference in the path's id segment (e.g.
	// "/Groups/bulkId:abc" once "abc" has been created).
	id, err := resolveBulkRef(rawID, bulkIDs)
	if err != nil {
		return bulkError(res, repository.ErrInvalidArgument, err.Error())
	}

	// Resolve bulkId references embedded in the data payload before the
	// operation runs (e.g. group members that point at just-created
	// users).
	data, err := resolveDataRefs(op.Data, bulkIDs)
	if err != nil {
		return bulkError(res, repository.ErrInvalidArgument, err.Error())
	}

	switch strings.ToUpper(op.Method) {
	case "POST":
		return s.bulkCreate(ctx, tenantID, resourceType, op, data, bulkIDs, res)
	case "PUT":
		return s.bulkReplace(ctx, tenantID, resourceType, id, data, res)
	case "PATCH":
		return s.bulkPatch(ctx, tenantID, resourceType, id, data, res)
	case "DELETE":
		return s.bulkDelete(ctx, tenantID, resourceType, id, res)
	default:
		return bulkError(res, repository.ErrInvalidArgument, fmt.Sprintf("unsupported bulk method %q", op.Method))
	}
}

func (s *SCIMService) bulkCreate(ctx context.Context, tenantID uuid.UUID, resourceType string, op SCIMBulkOperation, data []byte, bulkIDs map[string]string, res SCIMBulkOperationResult) SCIMBulkOperationResult {
	switch resourceType {
	case "Users":
		var su SCIMUser
		if err := json.Unmarshal(data, &su); err != nil {
			return bulkError(res, repository.ErrInvalidArgument, err.Error())
		}
		created, err := s.CreateUser(ctx, tenantID, su)
		if err != nil {
			return bulkRepoError(res, err)
		}
		if op.BulkID != "" {
			bulkIDs[op.BulkID] = created.ID
		}
		res.Location = bulkLocation(resourceType, created.ID)
		res.Status = strconv.Itoa(201)
		return res
	case "Groups":
		var sg SCIMGroup
		if err := json.Unmarshal(data, &sg); err != nil {
			return bulkError(res, repository.ErrInvalidArgument, err.Error())
		}
		created, err := s.CreateGroup(ctx, tenantID, sg)
		if err != nil {
			return bulkRepoError(res, err)
		}
		if op.BulkID != "" {
			bulkIDs[op.BulkID] = created.ID
		}
		// Apply any inline members as PATCH-add semantics so a single
		// bulk POST can both create the group and populate it.
		if len(sg.Members) > 0 {
			if _, err := s.PatchGroup(ctx, tenantID, uuidFromString(created.ID), []SCIMPatchOp{{
				Op:    "add",
				Path:  "members",
				Value: membersToValue(sg.Members),
			}}); err != nil {
				return bulkRepoError(res, err)
			}
		}
		res.Location = bulkLocation(resourceType, created.ID)
		res.Status = strconv.Itoa(201)
		return res
	default:
		return bulkError(res, repository.ErrInvalidArgument, "unsupported bulk resource type")
	}
}

func (s *SCIMService) bulkReplace(ctx context.Context, tenantID uuid.UUID, resourceType, id string, data []byte, res SCIMBulkOperationResult) SCIMBulkOperationResult {
	uid := uuidFromString(id)
	if uid == uuid.Nil {
		return bulkError(res, repository.ErrInvalidArgument, "PUT requires a valid resource id")
	}
	switch resourceType {
	case "Users":
		var su SCIMUser
		if err := json.Unmarshal(data, &su); err != nil {
			return bulkError(res, repository.ErrInvalidArgument, err.Error())
		}
		if _, err := s.UpdateUser(ctx, tenantID, uid, su); err != nil {
			return bulkRepoError(res, err)
		}
	case "Groups":
		var sg SCIMGroup
		if err := json.Unmarshal(data, &sg); err != nil {
			return bulkError(res, repository.ErrInvalidArgument, err.Error())
		}
		if _, err := s.UpdateGroup(ctx, tenantID, uid, sg); err != nil {
			return bulkRepoError(res, err)
		}
	default:
		return bulkError(res, repository.ErrInvalidArgument, "unsupported bulk resource type")
	}
	res.Location = bulkLocation(resourceType, id)
	res.Status = strconv.Itoa(200)
	return res
}

func (s *SCIMService) bulkPatch(ctx context.Context, tenantID uuid.UUID, resourceType, id string, data []byte, res SCIMBulkOperationResult) SCIMBulkOperationResult {
	uid := uuidFromString(id)
	if uid == uuid.Nil {
		return bulkError(res, repository.ErrInvalidArgument, "PATCH requires a valid resource id")
	}
	var patch SCIMPatchRequest
	if err := json.Unmarshal(data, &patch); err != nil {
		return bulkError(res, repository.ErrInvalidArgument, err.Error())
	}
	switch resourceType {
	case "Users":
		if _, err := s.PatchUser(ctx, tenantID, uid, patch.Operations); err != nil {
			return bulkRepoError(res, err)
		}
	case "Groups":
		if _, err := s.PatchGroup(ctx, tenantID, uid, patch.Operations); err != nil {
			return bulkRepoError(res, err)
		}
	default:
		return bulkError(res, repository.ErrInvalidArgument, "unsupported bulk resource type")
	}
	res.Location = bulkLocation(resourceType, id)
	res.Status = strconv.Itoa(200)
	return res
}

func (s *SCIMService) bulkDelete(ctx context.Context, tenantID uuid.UUID, resourceType, id string, res SCIMBulkOperationResult) SCIMBulkOperationResult {
	uid := uuidFromString(id)
	if uid == uuid.Nil {
		return bulkError(res, repository.ErrInvalidArgument, "DELETE requires a valid resource id")
	}
	switch resourceType {
	case "Users":
		if err := s.DeleteUser(ctx, tenantID, uid); err != nil {
			return bulkRepoError(res, err)
		}
	case "Groups":
		if err := s.DeleteGroup(ctx, tenantID, uid); err != nil {
			return bulkRepoError(res, err)
		}
	default:
		return bulkError(res, repository.ErrInvalidArgument, "unsupported bulk resource type")
	}
	res.Status = strconv.Itoa(204)
	return res
}

// --- bulk helpers ---------------------------------------------------------

// parseBulkPath splits a bulk operation path into its resource type and
// optional id segment. Accepted forms: "/Users", "/Users/{id}",
// "/Groups", "/Groups/{id}" (a leading "/scim/v2" prefix is tolerated).
func parseBulkPath(path string) (resourceType, id string, err error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", "", fmt.Errorf("bulk operation path is required")
	}
	p = strings.TrimPrefix(p, "/scim/v2")
	p = strings.Trim(p, "/")
	segments := strings.Split(p, "/")
	switch segments[0] {
	case "Users", "Groups":
		resourceType = segments[0]
	default:
		return "", "", fmt.Errorf("unsupported bulk path %q", path)
	}
	if len(segments) >= 2 {
		id = segments[1]
	}
	if len(segments) > 2 {
		return "", "", fmt.Errorf("malformed bulk path %q", path)
	}
	return resourceType, id, nil
}

// resolveBulkRef resolves a single "bulkId:<key>" token against the
// batch's bulkId map. Non-reference values pass through unchanged.
func resolveBulkRef(value string, bulkIDs map[string]string) (string, error) {
	const prefix = "bulkId:"
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	key := strings.TrimPrefix(value, prefix)
	resolved, ok := bulkIDs[key]
	if !ok {
		return "", fmt.Errorf("unresolved bulkId reference %q", value)
	}
	return resolved, nil
}

// resolveDataRefs walks a bulk operation's JSON data and replaces every
// "bulkId:<key>" string with the resolved server id. It returns the
// re-encoded payload; an unresolved reference is an error so a
// dependent operation fails loudly rather than writing a dangling id.
func resolveDataRefs(data json.RawMessage, bulkIDs map[string]string) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	walked, err := walkResolveRefs(decoded, bulkIDs)
	if err != nil {
		return nil, err
	}
	return json.Marshal(walked)
}

func walkResolveRefs(node any, bulkIDs map[string]string) (any, error) {
	switch v := node.(type) {
	case string:
		return resolveBulkRef(v, bulkIDs)
	case []any:
		for i, item := range v {
			resolved, err := walkResolveRefs(item, bulkIDs)
			if err != nil {
				return nil, err
			}
			v[i] = resolved
		}
		return v, nil
	case map[string]any:
		for k, item := range v {
			resolved, err := walkResolveRefs(item, bulkIDs)
			if err != nil {
				return nil, err
			}
			v[k] = resolved
		}
		return v, nil
	default:
		return node, nil
	}
}

// membersToValue converts typed members back to the generic []any shape
// extractMembers consumes, so a bulk group-create can reuse PatchGroup.
func membersToValue(members []SCIMGroupMember) []any {
	out := make([]any, 0, len(members))
	for _, m := range members {
		out = append(out, map[string]any{"value": m.Value, "display": m.Display})
	}
	return out
}

func bulkLocation(resourceType, id string) string {
	return "/scim/v2/" + resourceType + "/" + id
}

func bulkStatusOK(status string) bool {
	code, err := strconv.Atoi(status)
	if err != nil {
		return false
	}
	return code >= 200 && code < 300
}

// bulkError fills a result entry for a client/validation error.
func bulkError(res SCIMBulkOperationResult, sentinel error, detail string) SCIMBulkOperationResult {
	return bulkRepoError(res, fmt.Errorf("%s: %w", detail, sentinel))
}

// bulkRepoError maps a repository/service error to the SCIM HTTP status
// the standalone endpoints would return, embedding it in the result.
func bulkRepoError(res SCIMBulkOperationResult, err error) SCIMBulkOperationResult {
	status, scimType := bulkStatusForError(err)
	res.Status = strconv.Itoa(status)
	res.Response = &SCIMError{
		Schemas:  []string{SCIMSchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   err.Error(),
	}
	return res
}

func bulkStatusForError(err error) (int, string) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return 404, ""
	case errors.Is(err, repository.ErrConflict):
		return 409, "uniqueness"
	case errors.Is(err, repository.ErrForbidden):
		return 403, ""
	case errors.Is(err, repository.ErrInvalidArgument):
		return 400, "invalidValue"
	default:
		return 500, ""
	}
}
