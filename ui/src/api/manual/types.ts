// Hand-written types for control-plane handlers that are registered in
// `internal/handler/router.go` but not yet described in
// `api/openapi.yaml` (CASB, DLP, Compliance, Metering, Playbook). These
// mirror the Go wire structs so the corresponding pages are wired
// against the real routes rather than stubbed. When these endpoints are
// added to the OpenAPI document they should move to the generated
// client and these definitions can be deleted.

export interface ListEnvelope<T> {
  items: T[];
  next_cursor?: string;
  total?: number;
}

// --- CASB ------------------------------------------------------------------

export interface CasbConnector {
  id: string;
  tenant_id: string;
  type: string;
  name: string;
  status: string;
  secret_set: boolean;
  last_sync_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CasbConnectorCreate {
  type: string;
  name: string;
  config?: unknown;
  secret?: unknown;
}

export interface CasbApp {
  id: string;
  tenant_id: string;
  name: string;
  vendor: string;
  category: string;
  risk_score: number;
  users_count: number;
  first_seen: string;
  last_seen: string;
}

// --- DLP -------------------------------------------------------------------

export interface DlpRule {
  detector: string;
  threshold?: number;
  [k: string]: unknown;
}

export interface DlpPolicy {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  rules: DlpRule[];
  action: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
}

export interface DlpPolicyCreate {
  name: string;
  description?: string;
  rules: DlpRule[];
  action: string;
  enabled: boolean;
}

export interface DlpTemplate {
  id: string;
  name: string;
  description: string;
  taxonomy: string;
  rules: DlpRule[];
}

export interface DlpClassifyResult {
  classification: string;
  confidence: number;
  matched_detectors: string[];
}

// --- Compliance ------------------------------------------------------------

export interface ComplianceControlStatus {
  id: string;
  title: string;
  status: string;
  detail?: string;
}

export interface ComplianceReport {
  id: string;
  tenant_id: string;
  framework: string;
  score: number;
  max_score: number;
  controls: ComplianceControlStatus[];
  generated_at: string;
  created_at: string;
}

export interface GenerateReportRequest {
  framework: string;
  dlp?: boolean;
  browser?: boolean;
  casb?: boolean;
  policy?: boolean;
  access_control?: boolean;
}

// --- Metering --------------------------------------------------------------

export interface UsageLine {
  meter: string;
  period: string;
  used: number;
  soft_limit?: number;
  hard_limit?: number;
  soft_exceeded: boolean;
  hard_exceeded: boolean;
  // Elapsed-fraction extrapolation of `used` to the end of the period
  // (the steady-state run rate). The projected_* flags compare it
  // against the limits so the UI can warn of an on-track breach.
  projected: number;
  projected_soft_exceeded: boolean;
  projected_hard_exceeded: boolean;
}

export interface UsageResponse {
  tenant_id: string;
  generated_at: string;
  lines: UsageLine[];
}

export interface UsageHistoryLine {
  meter: string;
  period_start: string;
  period_end: string;
  value: number;
}

export interface UsageHistoryResponse {
  tenant_id: string;
  months: number;
  lines: UsageHistoryLine[];
}

export interface BudgetOverride {
  meter: string;
  soft_limit: number;
  hard_limit: number;
  period?: string;
}

// --- Playbook --------------------------------------------------------------

export interface Playbook {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  trigger_condition: string;
  steps: unknown;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PlaybookCreate {
  name: string;
  description?: string;
  trigger_condition: string;
  steps: unknown;
  enabled: boolean;
}

export interface PlaybookExecution {
  id: string;
  tenant_id: string;
  playbook_id: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
}

export interface PlaybookApproval {
  id: string;
  tenant_id: string;
  playbook_id: string;
  requested_by: string;
  status: string;
  requested_at: string;
}

// --- Policy simulation (change impact) -------------------------------------

export interface VerdictTransition {
  prev_verdict: string;
  next_verdict: string;
  count: number;
}

export interface SimulationRequest {
  proposed: unknown;
  since?: string;
  until?: string;
  max_events?: number;
}

export interface SimulationResponse {
  simulation_id: string;
  tenant_id: string;
  since: string;
  until: string;
  prev_graph_version: number;
  next_graph_version: number;
  total: number;
  changed: number;
  transitions: VerdictTransition[];
  affected_devices: string[];
  affected_sites: string[];
  prev_errors: number;
  next_errors: number;
  started_at: string;
  finished_at: string;
}
