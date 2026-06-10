// React Query hooks for the not-yet-in-OpenAPI control-plane handlers.
// They share the same axios mutator (`sngRequest`) as the generated
// client, so base URL, bearer auth and 401 handling are identical.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import { sngRequest } from "@/api/http-client";
import type {
  BudgetOverride,
  BudgetUpdateResponse,
  CasbApp,
  CasbConnector,
  CasbConnectorCreate,
  ComplianceReport,
  DlpClassifyResult,
  DlpPolicy,
  DlpPolicyCreate,
  DlpTemplate,
  GenerateReportRequest,
  InfraCostProjection,
  ListEnvelope,
  PlatformCostReport,
  Playbook,
  PlaybookApproval,
  PlaybookCreate,
  PlaybookExecution,
  SimulationRequest,
  SimulationResponse,
  TenantCostReport,
  UsageHistoryResponse,
  UsageResponse,
} from "./types";

const base = (tenantId: string) => `/tenants/${tenantId}`;

// --- CASB ------------------------------------------------------------------

export function useCasbConnectors(
  tenantId: string,
): UseQueryResult<ListEnvelope<CasbConnector>> {
  return useQuery({
    queryKey: ["casb", "connectors", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<CasbConnector>>({
        method: "GET",
        url: `${base(tenantId)}/casb/connectors`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useCasbApps(
  tenantId: string,
): UseQueryResult<ListEnvelope<CasbApp>> {
  return useQuery({
    queryKey: ["casb", "apps", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<CasbApp>>({
        method: "GET",
        url: `${base(tenantId)}/casb/apps`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useCreateCasbConnector(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CasbConnectorCreate) =>
      sngRequest<CasbConnector>({
        method: "POST",
        url: `${base(tenantId)}/casb/connectors`,
        data: body,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["casb", "connectors", tenantId] }),
  });
}

export function useSyncCasbConnector(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      sngRequest({
        method: "POST",
        url: `${base(tenantId)}/casb/connectors/${id}/sync`,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["casb", "connectors", tenantId] }),
  });
}

// --- DLP -------------------------------------------------------------------

export function useDlpPolicies(
  tenantId: string,
): UseQueryResult<ListEnvelope<DlpPolicy>> {
  return useQuery({
    queryKey: ["dlp", "policies", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<DlpPolicy>>({
        method: "GET",
        url: `${base(tenantId)}/dlp/policies`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useDlpTemplates(
  tenantId: string,
): UseQueryResult<ListEnvelope<DlpTemplate>> {
  return useQuery({
    queryKey: ["dlp", "templates", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<DlpTemplate>>({
        method: "GET",
        url: `${base(tenantId)}/dlp/templates`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useCreateDlpPolicy(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DlpPolicyCreate) =>
      sngRequest<DlpPolicy>({
        method: "POST",
        url: `${base(tenantId)}/dlp/policies`,
        data: body,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dlp", "policies", tenantId] }),
  });
}

export function useApplyDlpTemplate(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (templateId: string) =>
      sngRequest<DlpPolicy>({
        method: "POST",
        url: `${base(tenantId)}/dlp/templates/${templateId}/apply`,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dlp", "policies", tenantId] }),
  });
}

export function useClassifyText(tenantId: string) {
  return useMutation({
    mutationFn: (text: string) =>
      sngRequest<DlpClassifyResult>({
        method: "POST",
        url: `${base(tenantId)}/dlp/classify`,
        data: { content: text, content_type: "text/plain" },
      }),
  });
}

// --- Compliance ------------------------------------------------------------

export function useComplianceReports(
  tenantId: string,
): UseQueryResult<ListEnvelope<ComplianceReport>> {
  return useQuery({
    queryKey: ["compliance", "reports", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<ComplianceReport>>({
        method: "GET",
        url: `${base(tenantId)}/compliance/reports`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useGenerateComplianceReport(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: GenerateReportRequest) =>
      sngRequest<ComplianceReport>({
        method: "POST",
        url: `${base(tenantId)}/compliance/reports/generate`,
        data: body,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["compliance", "reports", tenantId] }),
  });
}

/** Absolute API path for the evidence-pack download link of a report. */
export function complianceEvidenceUrl(
  apiBaseUrl: string,
  tenantId: string,
  reportId: string,
): string {
  return `${apiBaseUrl}${base(tenantId)}/compliance/reports/${reportId}/evidence`;
}

// --- Metering --------------------------------------------------------------

export function useUsage(tenantId: string): UseQueryResult<UsageResponse> {
  return useQuery({
    queryKey: ["metering", "usage", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<UsageResponse>({
        method: "GET",
        url: `${base(tenantId)}/usage`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useUsageHistory(
  tenantId: string,
  months?: number,
): UseQueryResult<UsageHistoryResponse> {
  return useQuery({
    queryKey: ["metering", "usage-history", tenantId, months ?? null],
    queryFn: ({ signal }) =>
      sngRequest<UsageHistoryResponse>({
        method: "GET",
        url: `${base(tenantId)}/usage/history`,
        params: months ? { months } : undefined,
        signal,
      }),
    enabled: !!tenantId,
  });
}

// useCost reads the per-tenant infrastructure cost projection
// (ClickHouse / NATS / S3 monthly USD) for the infra-breakdown panel.
export function useCost(
  tenantId: string,
): UseQueryResult<InfraCostProjection> {
  return useQuery({
    queryKey: ["metering", "cost", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<InfraCostProjection>({
        method: "GET",
        url: `${base(tenantId)}/cost`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

// useCostReport reads the per-tenant per-meter cost report (projected
// monthly cost, per-meter cost + budget utilisation, margin). This is
// the source for the summary cards and the cost columns of the usage
// table.
export function useCostReport(
  tenantId: string,
): UseQueryResult<TenantCostReport> {
  return useQuery({
    queryKey: ["metering", "cost-report", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<TenantCostReport>({
        method: "GET",
        url: `${base(tenantId)}/cost-report`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

// usePlatformCostReport reads the fleet-wide cost + margin report. It is
// platform-admin only: the route 404s for tenant-scoped callers, which
// the MSP view treats as "not authorized" rather than a hard error
// (see retry guard below). `enabled` lets the caller gate the request on
// a permission check so non-platform users never even issue it.
export function usePlatformCostReport(
  enabled = true,
): UseQueryResult<PlatformCostReport> {
  return useQuery({
    queryKey: ["metering", "admin", "cost-report"],
    queryFn: ({ signal }) =>
      sngRequest<PlatformCostReport>({
        method: "GET",
        url: `/admin/cost-report`,
        signal,
      }),
    enabled,
    // A 404/403 here means "not a platform admin" — a terminal,
    // expected state for tenant users, so don't retry it.
    retry: false,
  });
}

// useUpdateBudgets PUTs a batch of per-meter budget overrides and
// refreshes the usage + cost views on success so the table and cards
// reflect the new limits immediately.
export function useUpdateBudgets(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (budgets: BudgetOverride[]) =>
      sngRequest<BudgetUpdateResponse>({
        method: "PUT",
        url: `${base(tenantId)}/budgets`,
        data: { budgets },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["metering", "usage", tenantId] });
      qc.invalidateQueries({ queryKey: ["metering", "cost-report", tenantId] });
      // A budget change moves this tenant's over-budget flag and margin in
      // the fleet-wide view too, so refresh the platform admin report when
      // an MSP admin edits budgets with the fleet table also mounted. The
      // query is gated on platform-admin access, so for tenant users this
      // key is unused and the invalidation is a no-op.
      qc.invalidateQueries({ queryKey: ["metering", "admin", "cost-report"] });
    },
  });
}

// --- Playbook --------------------------------------------------------------

export function usePlaybooks(
  tenantId: string,
): UseQueryResult<ListEnvelope<Playbook>> {
  return useQuery({
    queryKey: ["playbooks", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<Playbook>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function usePlaybookExecutions(
  tenantId: string,
): UseQueryResult<ListEnvelope<PlaybookExecution>> {
  return useQuery({
    queryKey: ["playbooks", "executions", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<PlaybookExecution>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks/executions`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function usePendingApprovals(
  tenantId: string,
): UseQueryResult<ListEnvelope<PlaybookApproval>> {
  return useQuery({
    queryKey: ["playbooks", "approvals", tenantId],
    queryFn: ({ signal }) =>
      sngRequest<ListEnvelope<PlaybookApproval>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks/approvals/pending`,
        signal,
      }),
    enabled: !!tenantId,
  });
}

export function useCreatePlaybook(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PlaybookCreate) =>
      sngRequest<Playbook>({
        method: "POST",
        url: `${base(tenantId)}/playbooks`,
        data: body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["playbooks", tenantId] }),
  });
}

// --- Policy simulation -----------------------------------------------------

export function useRunSimulation(tenantId: string) {
  return useMutation({
    mutationFn: (body: SimulationRequest) =>
      sngRequest<SimulationResponse>({
        method: "POST",
        url: `${base(tenantId)}/policy/simulations`,
        data: body,
      }),
  });
}

export function useDecideApproval(tenantId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "reject" }) =>
      sngRequest({
        method: "POST",
        url: `${base(tenantId)}/playbooks/approvals/${id}/${decision}`,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["playbooks", "approvals", tenantId] }),
  });
}
