export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export type VendorCategory =
  | "software"
  | "cloud_hosting"
  | "professional_services"
  | "payment_processing"
  | "logistics"
  | "staffing"
  | "marketing"
  | "equipment_supplier"
  | "other";

export type Criticality = "low" | "medium" | "high" | "critical";
export type AccessLevel = "none" | "low" | "moderate" | "high" | "critical";
export type RiskTier = "low" | "medium" | "high" | "critical";
export type OwnershipConfidence = "confirmed" | "high" | "medium" | "low" | "unverified";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingConfidence = "confirmed" | "high" | "medium" | "low" | "informational";
export type FindingStatus = "open" | "investigating" | "accepted" | "remediated" | "false_positive";
export type ScanMode = "passive" | "authorized_active";
export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface Vendor {
  id: string;
  name: string;
  primary_domain: string;
  business_owner: string | null;
  vendor_category: VendorCategory;
  criticality: Criticality;
  data_access_level: AccessLevel;
  system_access_level: AccessLevel;
  risk_tier: RiskTier;
  active_scan_authorized: boolean;
  is_internal_brand: boolean;
  trust_center_url: string | null;
  security_page_url: string | null;
  status_page_url: string | null;
  compliance_notes: string | null;
  renewal_date: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  vendor_id: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  source: string;
  first_seen: string;
  last_seen: string;
  ownership_confidence: OwnershipConfidence;
  active: boolean;
  asset_metadata: Record<string, unknown>;
}

export interface Finding {
  id: string;
  vendor_id: string;
  asset_id: string | null;
  finding_type: string;
  title: string;
  description: string | null;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  evidence: Record<string, unknown>;
  remediation: string | null;
  detected_at: string;
  last_seen: string;
  status: FindingStatus;
  suppressed_until: string | null;
  analyst_notes: string | null;
  risk_points: number;
}

export interface Scan {
  id: string;
  vendor_id: string;
  scan_type: string;
  mode: ScanMode;
  started_at: string | null;
  completed_at: string | null;
  status: ScanStatus;
  findings_count: number;
  scan_metadata: Record<string, unknown>;
}

export interface RiskScoreDeduction {
  finding_id: string;
  finding_type: string;
  title: string;
  points: number;
}

export interface RiskScoreCategory {
  score: number;
  weight: number;
  deductions: RiskScoreDeduction[];
}

export interface RiskScore {
  id: string;
  vendor_id: string;
  score: number;
  grade: string;
  category_scores: Record<string, RiskScoreCategory>;
  calculated_at: string;
  scoring_version: string;
}

export interface VendorListItem extends Vendor {
  last_scanned_at: string | null;
}

export interface UptimeDay {
  day: string;
  checks: number;
  uptime_percent: number | null;
}

export interface UptimeIncident {
  started_at: string;
  ended_at: string;
  duration_minutes: number;
  failed_checks: number;
  error: string | null;
}

export type ReportedIndicator =
  | "operational"
  | "maintenance"
  | "degraded"
  | "partial_outage"
  | "major_outage";

export interface ReportedStatusComponent {
  name: string;
  indicator: ReportedIndicator;
}

export interface ReportedStatusIncident {
  name: string;
  impact: string | null;
  status: string | null;
  started_at: string | null;
  url: string | null;
}

export interface VendorReportedStatus {
  indicator: ReportedIndicator;
  description: string;
  platform: string;
  components: ReportedStatusComponent[];
  active_incidents: ReportedStatusIncident[];
  fetched_at: string;
}

export interface VendorUptime {
  vendor_id: string;
  vendor_name: string;
  primary_domain: string;
  is_internal_brand: boolean;
  status_page_url: string | null;
  checks: number;
  uptime_percent: number | null;
  avg_response_time_ms: number | null;
  currently_reachable: boolean | null;
  last_checked_at: string | null;
  daily: UptimeDay[];
  incidents: UptimeIncident[];
  reported_status: VendorReportedStatus | null;
}

export interface NewsMention {
  title: string;
  link: string;
  source: string;
  published_at: string | null;
  description: string | null;
}

export interface VendorNewsMention extends NewsMention {
  vendor_id: string;
  vendor_name: string;
}

export interface ExecutiveSummary {
  vendor_id: string;
  vendor_name: string;
  overall_risk_label: string;
  external_security_score: number | null;
  external_security_grade: string | null;
  business_criticality: string;
  key_concerns: string[];
  positive_indicators: string[];
  recommended_action: string;
  generated_at: string;
}

export interface RiskTierCounts {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface FindingSeverityCounts {
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface DashboardSummary {
  vendor_count: number;
  critical_vendor_count: number;
  high_risk_vendor_count: number;
  vendors_with_new_findings: number;
  vendors_with_kev_findings: number;
  vendors_with_typosquatting_findings: number;
  open_critical_findings: number;
  open_high_findings: number;
  recent_scan_count: number;
  vendor_risk_tier_counts: RiskTierCounts;
  open_finding_severity_counts: FindingSeverityCounts;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  listVendors: () => apiFetch<VendorListItem[]>("/vendors"),
  getVendor: (id: string) => apiFetch<Vendor>(`/vendors/${id}`),
  deleteVendor: (id: string) => apiFetch<void>(`/vendors/${id}`, { method: "DELETE" }),
  createVendor: (payload: Partial<Vendor>) =>
    apiFetch<Vendor>("/vendors", { method: "POST", body: JSON.stringify(payload) }),
  updateVendor: (id: string, payload: Partial<Vendor>) =>
    apiFetch<Vendor>(`/vendors/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  getExecutiveSummary: (id: string) => apiFetch<ExecutiveSummary>(`/vendors/${id}/executive-summary`),
  getVendorNews: (id: string) => apiFetch<NewsMention[]>(`/vendors/${id}/news`),
  listOrganizationDomains: () => apiFetch<Vendor[]>("/organization"),
  createOrganizationDomain: (payload: { name: string; primary_domain: string }) =>
    apiFetch<Vendor>("/organization", { method: "POST", body: JSON.stringify(payload) }),
  listAssets: (vendorId: string) => apiFetch<Asset[]>(`/vendors/${vendorId}/assets`),
  listFindings: (vendorId: string) => apiFetch<Finding[]>(`/vendors/${vendorId}/findings`),
  listScans: (vendorId: string) => apiFetch<Scan[]>(`/vendors/${vendorId}/scans`),
  listScores: (vendorId: string) => apiFetch<RiskScore[]>(`/vendors/${vendorId}/scores`),
  startScan: (vendorId: string, mode: ScanMode = "passive") =>
    apiFetch<Scan>(`/vendors/${vendorId}/scan`, {
      method: "POST",
      body: JSON.stringify({ scan_type: "full_passive", mode }),
    }),
  getDashboard: () => apiFetch<DashboardSummary>("/dashboard"),
  getDashboardNews: (days = 14) => apiFetch<VendorNewsMention[]>(`/dashboard/news?days=${days}`),
  getStatus: (days = 30) => apiFetch<VendorUptime[]>(`/status?days=${days}`),
  markFalsePositive: (findingId: string, analystNotes?: string) =>
    apiFetch<Finding>(`/findings/${findingId}/false-positive`, {
      method: "POST",
      body: JSON.stringify({ analyst_notes: analystNotes }),
    }),
  acceptRisk: (findingId: string, analystNotes?: string) =>
    apiFetch<Finding>(`/findings/${findingId}/accept-risk`, {
      method: "POST",
      body: JSON.stringify({ analyst_notes: analystNotes }),
    }),
  reopenFinding: (findingId: string, analystNotes?: string) =>
    apiFetch<Finding>(`/findings/${findingId}/reopen`, {
      method: "POST",
      body: JSON.stringify({ analyst_notes: analystNotes }),
    }),
};
