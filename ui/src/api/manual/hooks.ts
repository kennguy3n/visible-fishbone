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
  CasbApp,
  CasbConnector,
  CasbConnectorCreate,
  ComplianceReport,
  DlpClassifyResult,
  DlpPolicy,
  DlpPolicyCreate,
  DlpTemplate,
  GenerateReportRequest,
  ListEnvelope,
  Playbook,
  PlaybookApproval,
  PlaybookCreate,
  PlaybookExecution,
  SimulationRequest,
  SimulationResponse,
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
    queryFn: () =>
      sngRequest<ListEnvelope<CasbConnector>>({
        method: "GET",
        url: `${base(tenantId)}/casb/connectors`,
      }),
    enabled: !!tenantId,
  });
}

export function useCasbApps(
  tenantId: string,
): UseQueryResult<ListEnvelope<CasbApp>> {
  return useQuery({
    queryKey: ["casb", "apps", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<CasbApp>>({
        method: "GET",
        url: `${base(tenantId)}/casb/apps`,
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
    queryFn: () =>
      sngRequest<ListEnvelope<DlpPolicy>>({
        method: "GET",
        url: `${base(tenantId)}/dlp/policies`,
      }),
    enabled: !!tenantId,
  });
}

export function useDlpTemplates(
  tenantId: string,
): UseQueryResult<ListEnvelope<DlpTemplate>> {
  return useQuery({
    queryKey: ["dlp", "templates", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<DlpTemplate>>({
        method: "GET",
        url: `${base(tenantId)}/dlp/templates`,
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
        data: { text },
      }),
  });
}

// --- Compliance ------------------------------------------------------------

export function useComplianceReports(
  tenantId: string,
): UseQueryResult<ListEnvelope<ComplianceReport>> {
  return useQuery({
    queryKey: ["compliance", "reports", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<ComplianceReport>>({
        method: "GET",
        url: `${base(tenantId)}/compliance/reports`,
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
    queryFn: () =>
      sngRequest<UsageResponse>({
        method: "GET",
        url: `${base(tenantId)}/usage`,
      }),
    enabled: !!tenantId,
  });
}

export function useUsageHistory(
  tenantId: string,
): UseQueryResult<UsageHistoryResponse> {
  return useQuery({
    queryKey: ["metering", "usage-history", tenantId],
    queryFn: () =>
      sngRequest<UsageHistoryResponse>({
        method: "GET",
        url: `${base(tenantId)}/usage/history`,
      }),
    enabled: !!tenantId,
  });
}

// --- Playbook --------------------------------------------------------------

export function usePlaybooks(
  tenantId: string,
): UseQueryResult<ListEnvelope<Playbook>> {
  return useQuery({
    queryKey: ["playbooks", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<Playbook>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks`,
      }),
    enabled: !!tenantId,
  });
}

export function usePlaybookExecutions(
  tenantId: string,
): UseQueryResult<ListEnvelope<PlaybookExecution>> {
  return useQuery({
    queryKey: ["playbooks", "executions", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<PlaybookExecution>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks/executions`,
      }),
    enabled: !!tenantId,
  });
}

export function usePendingApprovals(
  tenantId: string,
): UseQueryResult<ListEnvelope<PlaybookApproval>> {
  return useQuery({
    queryKey: ["playbooks", "approvals", tenantId],
    queryFn: () =>
      sngRequest<ListEnvelope<PlaybookApproval>>({
        method: "GET",
        url: `${base(tenantId)}/playbooks/approvals/pending`,
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
