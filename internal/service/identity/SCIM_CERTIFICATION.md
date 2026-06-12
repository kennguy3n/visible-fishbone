# SCIM 2.0 Certification Test Plan — Okta & Microsoft Entra ID

Status: **DEFERRED — requires live IdP credentials.** This document
enumerates exactly what must be executed against real Okta and Microsoft
Entra ID developer tenants once credentials are provisioned. Until then
the equivalent behaviours are pinned by the in-repo conformance vectors
(`scim_conformance_test.go`, `scim_hardening_test.go`, `scim_bulk_test.go`),
which derive from the published RFCs and IdP integration guides — **not**
from any live tenant.

- **Spec:** RFC 7643 (Core Schema), RFC 7644 (Protocol).
- **Service under test:** `internal/service/identity/scim*.go`
  (`SCIMService`), exposed over the tenant SCIM endpoints.
- **Tenancy:** every case is scoped to a single SME tenant; cross-tenant
  isolation is asserted explicitly (CERT-ISO-01). The platform targets
  ~5000 SME tenants, so all assertions must hold under per-tenant
  row-level isolation.

---

## 1. Prerequisites & setup

### 1.1 Credentials (request when ready to certify)

| Secret | Purpose | Scope |
| --- | --- | --- |
| `SCIM_BASE_URL` | Base URL of the deployed tenant SCIM endpoint | per-tenant |
| `SCIM_BEARER_TOKEN` | Tenant SCIM bearer token (provisioning credential) | per-tenant |
| `OKTA_ORG_URL`, `OKTA_API_TOKEN` | Okta dev org for driving the SCIM app | Okta dev tenant |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` | Entra dev tenant for the enterprise/gallery SCIM app | Entra dev tenant |

> Do NOT hardcode any of these. When certification is scheduled, request
> them as session/org secrets with descriptive names. No live IdP is
> contacted by the current test suite.

### 1.2 IdP-side configuration

- **Okta:** create a SCIM 2.0 application ("SCIM 2.0 Test App (Header
  Auth)" or a custom app), set the SCIM connector base URL to
  `SCIM_BASE_URL`, auth mode = HTTP Header (bearer), and enable
  *Create Users*, *Update User Attributes*, *Deactivate Users*, and
  *Push Groups*. Run Okta's built-in **"Test Connector Configuration"**
  and **SPEC test** (the Okta CRUD test suite).
- **Entra:** add an Enterprise Application → Provisioning → Automatic,
  tenant URL = `SCIM_BASE_URL`, secret token = `SCIM_BEARER_TOKEN`, run
  **"Test Connection"**, then **Provision on demand** for individual
  users/groups and a full initial cycle.

### 1.3 Service capabilities to advertise

Confirm `ServiceProviderConfig` reflects what this plan exercises:
`patch.supported=true`, `bulk.supported=true` (with `maxOperations` /
`maxPayloadSize`), `filter.supported=true` (with `maxResults`),
`etag.supported=true`. `sortBy` is **not** advertised and must not be
relied on.

---

## 2. Test matrix

Each row lists the IdP action, the expected SCIM result, and the
`scim*.go` behaviour it exercises (with the in-repo vector that already
pins the same logic). Status column to be filled during the live run:
PASS / FAIL / N/A.

### 2.1 User lifecycle (CRUD + JML)

| ID | IdP action | Expected result | scim* behaviour exercised | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-USR-01 | Push new user (create) | `201`, `id` returned, `userName` echoed, `meta.resourceType=User` | `SCIMService.CreateUser` | `TestSCIMCreateUser` | |
| CERT-USR-02 | Re-push same `userName` (dedup race) | No duplicate; existing user reused or `409` | `CreateUser` conflict handling | `TestCreateUserDuplicateRejected` | |
| CERT-USR-03 | Read user by id | `200`, full resource, stable `meta.version` ETag | `GetUser`, `scimUserVersion` | `TestSCIMGetUser` | |
| CERT-USR-04 | Full attribute update (PUT) | `200`, all attributes replaced | `UpdateUser` | `TestSCIMUpdateUser` | |
| CERT-USR-05 | Retried identical PUT (replay) | Convergent state; no error, no field drift | `UpdateUser` idempotency | `TestPutIsIdempotent` | |
| CERT-USR-06 | Deactivate user (PATCH `active=false`) | `200`, `active=false`; **sessions revoked before any bridge sync** | `PatchUser` → `patchActiveIntent` → `revokeOnDeactivation` | `TestPatchDeactivationRevokesSessions` | |
| CERT-USR-07 | Deactivate via PUT `active=false` | `200`, revocation published | `UpdateUser` deactivation path | `TestPutDeactivationRevokesSessions` | |
| CERT-USR-08 | Repeated deactivation (replay) | Each replay re-publishes revocation (retry-safe) | deactivation idempotency | `TestRepeatedDeactivationIsRetrySafe`, `TestPatchReplayConvergesToSameState` | |
| CERT-USR-09 | Delete user (`DELETE`) | `204`/`200`; user de-provisioned (inactive); sessions revoked **before** bridge delete | `DeleteUser` | `TestDeleteUserRevokesBeforeFailingBridgeDelete` | |
| CERT-USR-10 | Repeated delete (replay) | Idempotent (no error on already-deleted) | `DeleteUser` soft-delete | `TestBulkDeprovisionIdempotentDelete` | |

### 2.2 Okta / Entra payload quirks

| ID | IdP action | Expected result | scim* behaviour exercised | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-QRK-01 | Entra path-less PATCH (`{op:replace, value:{active:false}}`) | Deactivation detected | `patchActiveIntent` path-less branch | `TestPathlessAzureDeactivationRevokesSessions` | |
| CERT-QRK-02 | `active` sent as string `"false"` | Treated as boolean false | `patchActiveIntent` string coercion | `TestStringActiveDeactivationRevokesSessions` | |
| CERT-QRK-03 | URN-qualified path (`urn:...:User:active`) | Resolved to `active` | `canonicalAttr` URN stripping | `TestQualifiedActivePathDeactivationRevokesSessions` | |
| CERT-QRK-04 | Remove `externalId` (qualified path) | Field cleared | `applyUserRemove` / patch remove | `TestQualifiedExternalIDRemoveClearsField`, `TestSCIMPatchRemoveExternalID` | |
| CERT-QRK-05 | Atomic PATCH: replace one attr + remove another | Both applied atomically | `PatchUser` multi-op | `TestSCIMPatchRemoveExternalIDWithOtherUpdates` | |

### 2.3 Group push & membership de-provisioning

| ID | IdP action | Expected result | scim* behaviour exercised | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-GRP-01 | Push group (create) | `201`, group id returned | `CreateGroup` | `TestSCIMCreateGroup` | |
| CERT-GRP-02 | Rename group (PATCH `displayName`) | `200`, name updated | `PatchGroup` replace | `TestSCIMPatchGroupReplaceDisplayName` | |
| CERT-GRP-03 | Add members (Entra value-array `add`) | Members granted the group's role | `PatchGroup` add → `extractMembers` | `TestGroupMemberRemovalShapes` (add arm) | |
| CERT-GRP-04 | **Remove member — Okta `members[value eq "<id>"]`** | Member's role revoked (NOT silently dropped) | `PatchGroup` remove → `memberValuePathTarget` → `revokeGroupMember` | `TestGroupMemberRemovalShapes` (okta arm), `TestMemberValuePathTarget` | |
| CERT-GRP-05 | Remove member — Entra value-array `remove` | Member's role revoked | `PatchGroup` remove value-array | `TestGroupMemberRemovalShapes` (entra arm) | |
| CERT-GRP-06 | Repeated member removal (replay) | Idempotent (no error when already removed) | `revokeGroupMember` ErrNotFound tolerance | `TestGroupMemberRemovalShapes` (double-remove) | |
| CERT-GRP-07 | List groups | System/platform roles excluded | `ListGroups` filtering | `TestSCIMListGroupsExcludesSystemRoles` | |

> **CERT-GRP-04 is a security-critical de-provisioning case.** Okta
> removes a group member with a `valuePath` (no value body) rather than
> Entra's value-array. Before this hardening that PATCH was silently
> dropped, so an offboarded user kept the group's role. The live run
> must confirm the role is actually revoked.

### 2.4 Filter grammar (RFC 7644 §3.4.2.2)

Drive these by configuring IdP attribute mappings / scoping filters, or
by issuing raw `GET /Users?filter=...` with the bearer token.

| ID | Filter | Expected | scim* behaviour | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-FLT-01 | `userName eq "<known>"` | Exactly the one user (indexed fast path) | `ListUsers` pushdown → `GetByEmail` | `TestListUsersFilterParityAcrossPaths` | |
| CERT-FLT-02 | `userName co "<frag>"` / `sw` / `ew` | Substring/prefix/suffix matches | pushdown / in-memory | `TestSCIMListUsersFilterContainsAndPrefix` | |
| CERT-FLT-03 | **`active eq "true"` / `active eq "false"`** | Active/inactive users (NOT empty) | `userFilterPushdownable` gate → in-memory eval | `TestListUsersFilterParityAcrossPaths` | |
| CERT-FLT-04 | `emails eq "<addr>"` (bare path) | Matches user by primary email | in-memory `userAttr` | `TestListUsersFilterParityAcrossPaths` | |
| CERT-FLT-05 | `displayName co "<frag>"` (case-insensitive) | Case-insensitive matches | `evalCompare` | `TestSCIMListUsersFilterDisplayName` | |
| CERT-FLT-06 | `userName ne "<x>"` | All but the named user | in-memory `ne` | `TestFilterOperatorSemantics` | |
| CERT-FLT-07 | `<attr> pr` | All users with the attribute present | presence operator | `TestFilterEveryComparisonOperatorParses`, `TestFilterAbsentAttributeSemantics` | |
| CERT-FLT-08 | `gt`/`ge`/`lt`/`le` on a string attr | Lexicographic ordering | `evalCompare` ordering ops | `TestFilterOperatorSemantics` | |
| CERT-FLT-09 | `a eq "x" and b co "y"` / `or` / `not (...)` | Correct precedence (and binds tighter than or) | `parseFilterExpr` recursive descent | `TestFilterLogicalGrammarVectors`, `TestFilterPrecedenceEvaluation` | |
| CERT-FLT-10 | Parenthesised override `(a or b) and c` | Grouping respected | parser grouping | `TestFilterPrecedenceEvaluation` | |
| CERT-FLT-11 | URN-qualified attribute path | Prefix tolerated | `canonicalAttr` | `TestFilterLogicalGrammarVectors` | |
| CERT-FLT-12 | Malformed filter (unbalanced parens, trailing op, valuePath in filter) | `400` invalidFilter, no crash | parser errors | `TestFilterLogicalGrammarVectors` (malformed arm) | |
| CERT-FLT-13 | Unknown attribute (`nickName eq "x"`) | Empty result set, `200` | unbacked attr → no match | `TestSCIMListUsersUnknownAttributeMatchesNothing` | |

### 2.5 Pagination (RFC 7644 §3.4.2)

| ID | Request | Expected | scim* behaviour | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-PAG-01 | `startIndex=1&count=N` | First page, `startIndex=1`, full `totalResults` | `paginateResources` | `TestPaginationBoundaries` | |
| CERT-PAG-02 | Walk all pages in small windows | Each resource exactly once; stable total | indexed + in-memory paths | `TestPaginationCoversEverythingExactlyOnce` | |
| CERT-PAG-03 | `startIndex` past total | Empty `Resources`, total unchanged | window clamp | `TestPaginationBoundaries` | |
| CERT-PAG-04 | `startIndex=0` / negative | Normalised to 1 | startIndex normalisation | `TestPaginationBoundaries` | |
| CERT-PAG-05 | `count=0` / negative | Falls back to default page size | count normalisation | `TestPaginationBoundaries` | |
| CERT-PAG-06 | `count` > `MaxPageLimit` (200) | Clamped to `MaxPageLimit` | count clamp | `TestSCIMListUsersClampsCount`, `TestSCIMListGroupsClampsCount` | |
| CERT-PAG-07 | Small page over large match set | `totalResults` spans beyond the page | repo-side count | `TestSCIMListUsersTotalCountedBeyondPage` | |

### 2.6 Bulk operations (RFC 7644 §3.7)

| ID | Bulk request | Expected | scim* behaviour | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-BLK-01 | POST with `bulkId`, then PATCH referencing `bulkId:<k>` | Reference resolved to server id; both succeed | `Bulk`, `resolveDataRefs` | `TestBulkCreateResolvesBulkIDReferences` | |
| CERT-BLK-02 | Operations applied in request order | Create-then-deactivate leaves user inactive | `Bulk` sequential apply | `TestBulkOperationsAppliedInOrder` | |
| CERT-BLK-03 | Duplicate `bulkId` within one request | Rejected (uniqueness) | `runBulkOp` `seenBulkIDs` | `TestBulkDuplicateBulkIDRejected`, `TestBulkDuplicateBulkIDRejectedAfterFailedFirstPost` | |
| CERT-BLK-04 | Op with stale `version` (If-Match) | `412`, resource unchanged | `checkBulkVersion` | `TestBulkVersionPreconditionEnforced` | |
| CERT-BLK-05 | Op with current `version` | `200`, mutation applied | `checkBulkVersion` | `TestBulkVersionPreconditionEnforced` | |
| CERT-BLK-06 | `failOnErrors=N` with an early failure | Processing stops after N failures; later ops skipped | `Bulk` FailOnErrors | `TestBulkFailOnErrorsStops` | |
| CERT-BLK-07 | Bulk DELETE then replayed DELETE | Idempotent de-provisioning | `bulkDelete` | `TestBulkDeprovisionIdempotentDelete` | |

### 2.7 Multi-tenant isolation & security

| ID | Action | Expected | scim* behaviour | In-repo vector | Status |
| --- | --- | --- | --- | --- | --- |
| CERT-ISO-01 | List/Get/Patch using tenant A token for tenant B resource | No cross-tenant visibility or mutation | tenant-scoped repo calls | `TestSCIMTenantIsolation` | |
| CERT-ISO-02 | ETag `If-Match` precondition on PUT/PATCH | Stale ETag → `412` | `etagMatches` | `TestBulkVersionPreconditionEnforced` | |
| CERT-ISO-03 | `meta.version` injectivity | Distinct logical states → distinct versions | `scimUserVersion` / `scimGroupVersion` | `TestScimUserVersionNoSeparatorCollision`, `TestScimGroupVersionNoSeparatorCollision` | |

---

## 3. Execution procedure (when credentials are available)

1. Stand up a clean dev tenant; provision the bearer token.
2. Configure the Okta SCIM app (§1.2) and run Okta's connector + CRUD
   spec tests. Record pass/fail per CERT-* id.
3. Configure the Entra enterprise app (§1.2); run **Test Connection**,
   **Provision on demand** for each user/group case, and one full
   initial cycle. Inspect the Entra provisioning logs for each CERT-*.
4. For filter/pagination/bulk cases not directly drivable from the IdP
   UI, issue raw authenticated requests (curl/Postman collection) and
   compare against the Expected column.
5. For every deactivation/delete/member-removal case, independently
   confirm the **revocation side-effect** (session/role actually
   revoked) — not just the `2xx` status.
6. File any divergence as a hardening bug against `scim*.go`, add a
   regression vector to `scim_conformance_test.go`, and re-run.

## 4. Exit criteria

- All CERT-* rows PASS (or are justified N/A for an unconfigured
  capability).
- Okta connector + CRUD spec suite green.
- Entra initial cycle completes with zero provisioning errors for the
  configured users/groups.
- No cross-tenant leakage observed (CERT-ISO-01).
- Every de-provisioning case confirms the downstream revocation, not
  just the HTTP status.

## 5. Out of scope

- Live IdP calls from CI or from the in-repo test suite (the suite uses
  in-memory repositories and public RFC/guide-derived vectors only).
- `sortBy`/`sortOrder` (not advertised by `ServiceProviderConfig`).
- Password sync (not provisioned over SCIM here).
