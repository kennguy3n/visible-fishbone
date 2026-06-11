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

// CasbAppActionView is the latest shadow-IT NoOps action the engine
// decided for an app: what it would do (or did, when auto-applied).
export interface CasbAppActionView {
  enforcement: string;
  mode: string; // auto | recommend
  traffic_class?: string;
  applied: boolean;
  reason?: string;
  decided_at: string;
}

// CasbAppVerdict is the per-app shadow-IT decision: the classification
// the engine computed plus the most recent action it decided. Present
// only once the NoOps pipeline has classified the app.
export interface CasbAppVerdict {
  sanction: string; // sanctioned | tolerated | unsanctioned
  risk_score: number;
  confidence: number;
  source: string; // heuristic | ai_refined
  rationale: string;
  classified_at: string;
  action?: CasbAppActionView;
}

export interface CasbApp {
  id: string;
  tenant_id: string;
  name: string;
  vendor: string;
  category: string;
  risk_score: number;
  users_count: number;
  active_device_count: number;
  first_seen: string;
  last_seen: string;
  verdict?: CasbAppVerdict;
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

export interface DlpMatch {
  rule_type: string;
  pattern: string;
  offset: number;
  length: number;
  snippet: string;
  confidence: number;
}

export interface DlpClassifyResult {
  matches: DlpMatch[];
  policy_ids: string[];
  action: string;
  confidence: number;
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

// PUT /budgets request + response. The request mirrors the Go
// budgetUpdateRequest (a list of per-meter overrides); the response is
// the tenant's full resolved budget set after the write.
export interface BudgetUpdateRequest {
  budgets: BudgetOverride[];
}

export interface BudgetResponseLine {
  meter: string;
  period: string;
  soft_limit: number;
  hard_limit: number;
}

export interface BudgetUpdateResponse {
  tenant_id: string;
  budgets: BudgetResponseLine[];
}

// GET /tenants/{id}/cost — per-tenant infrastructure cost projection
// (InfraCostProjection). NATS/S3 are point-in-time storage gauges;
// ClickHouse is a projected write flow.
export interface InfraCostProjection {
  tenant_id: string;
  clickhouse_projected_rows: number;
  clickhouse_monthly_usd: number;
  nats_stream_bytes: number;
  nats_monthly_usd: number;
  s3_archive_bytes: number;
  s3_monthly_usd: number;
  total_monthly_usd: number;
}

// GET /tenants/{id}/cost-report — per-tenant per-meter cost report
// (TenantCostReport). The tenant-scoped counterpart to the platform
// /admin/cost-report.
export interface CostLine {
  meter: string;
  period: string;
  usage: number;
  cost_usd: number;
  projected_usage: number;
  projected_cost_usd: number;
  monthly_cost_usd: number;
  hard_limit: number;
  budget_utilization: number;
  over_budget: boolean;
}

export interface TenantCostReport {
  tenant_id: string;
  tier: string;
  generated_at: string;
  lines: CostLine[];
  total_cost_usd: number;
  projected_monthly_cost_usd: number;
  monthly_revenue_usd: number;
  margin_usd: number;
  margin_pct: number;
}

// GET /admin/cost-report — fleet-wide cost report (PlatformCostReport).
export interface PlatformCostReport {
  generated_at: string;
  tenant_count: number;
  tenants: TenantCostReport[];
  total_cost_usd: number;
  projected_monthly_cost_usd: number;
  total_revenue_usd: number;
  total_margin_usd: number;
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
