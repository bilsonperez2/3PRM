"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { VendorLogo } from "@/components/VendorLogo";
import {
  api,
  AccessLevel,
  Asset,
  Criticality,
  ExecutiveSummary,
  Finding,
  NewsMention,
  RiskScore,
  RiskTier,
  Scan,
  Vendor,
  VendorCategory,
} from "@/lib/api";

type Tab = "overview" | "assets" | "findings" | "scans" | "scores" | "summary" | "news";

const TABS: Array<[Tab, string]> = [
  ["overview", "Overview"],
  ["assets", "Assets"],
  ["findings", "Findings"],
  ["scans", "Scan History"],
  ["scores", "Score History"],
  ["summary", "Executive Summary"],
  ["news", "News"],
];

const VENDOR_CATEGORY_OPTIONS: VendorCategory[] = [
  "software", "cloud_hosting", "professional_services", "payment_processing",
  "logistics", "staffing", "marketing", "equipment_supplier", "other",
];
const CRITICALITY_OPTIONS: Criticality[] = ["low", "medium", "high", "critical"];
const RISK_TIER_OPTIONS: RiskTier[] = ["low", "medium", "high", "critical"];
const ACCESS_LEVEL_OPTIONS: AccessLevel[] = ["none", "low", "moderate", "high", "critical"];

export default function VendorDetailPage() {
  const params = useParams<{ id: string }>();
  const vendorId = params.id;

  const [vendor, setVendor] = useState<Vendor | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scores, setScores] = useState<RiskScore[]>([]);
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [news, setNews] = useState<NewsMention[] | null>(null);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [newsLoading, setNewsLoading] = useState(false);
  const [pollingScanId, setPollingScanId] = useState<string | null>(null);

  function reload() {
    if (!vendorId) return;
    Promise.all([
      api.getVendor(vendorId),
      api.listAssets(vendorId),
      api.listFindings(vendorId),
      api.listScans(vendorId),
      api.listScores(vendorId),
    ])
      .then(([v, a, f, s, sc]) => {
        setVendor(v);
        setAssets(a);
        setFindings(f);
        setScans(s);
        setScores(sc);
      })
      .catch((err) => setError(err.message));

    api
      .getExecutiveSummary(vendorId)
      .then(setSummary)
      .catch((err) => setSummaryError(err.message));
  }

  useEffect(reload, [vendorId]);

  // News is fetched from live RSS feeds — noticeably slower than the rest of
  // this page, so it's loaded lazily on first visit to the tab rather than
  // eagerly in reload(), which would slow down every vendor page load.
  useEffect(() => {
    if (tab !== "news" || news !== null || !vendorId) return;
    setNewsLoading(true);
    setNewsError(null);
    api
      .getVendorNews(vendorId)
      .then(setNews)
      .catch((err) => setNewsError(err.message))
      .finally(() => setNewsLoading(false));
  }, [tab, news, vendorId]);

  // Scans run asynchronously in a Celery worker — poll until the one we just
  // started finishes, then refresh everything (findings/assets/scores) so
  // the page updates itself instead of requiring a manual reload.
  useEffect(() => {
    if (!pollingScanId || !vendorId) return;

    let cancelled = false;
    const intervalId = setInterval(async () => {
      if (cancelled) return;
      try {
        const scans = await api.listScans(vendorId);
        const scan = scans.find((s) => s.id === pollingScanId);
        if (!scan || cancelled) return;
        if (scan.status === "completed" || scan.status === "failed") {
          setScanMessage(
            scan.status === "completed"
              ? `Scan completed — ${scan.findings_count} finding(s).`
              : "Scan failed — check the worker logs."
          );
          reload();
          setPollingScanId(null);
        }
      } catch {
        // Transient polling error — keep trying on the next tick.
      }
    }, 4000);

    // Safety net: stop polling after 5 minutes even if a scan never resolves.
    const timeoutId = setTimeout(() => setPollingScanId(null), 5 * 60 * 1000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
      clearTimeout(timeoutId);
    };
  }, [pollingScanId, vendorId]);

  async function handleScan() {
    setScanning(true);
    setScanMessage(null);
    try {
      const scan = await api.startScan(vendorId, "passive");
      setScanMessage(`Passive scan queued (status: ${scan.status})...`);
      reload();
      setPollingScanId(scan.id);
    } catch (err) {
      setScanMessage((err as Error).message);
    } finally {
      setScanning(false);
    }
  }

  if (error) {
    return (
      <div className="container">
        <p className="error-text">Could not load vendor: {error}</p>
      </div>
    );
  }

  if (!vendor) {
    return (
      <div className="container">
        <p>Loading vendor...</p>
      </div>
    );
  }

  return (
    <div className="container">
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        <VendorLogo domain={vendor.primary_domain} size={36} />
        <h1 style={{ margin: 0 }}>{vendor.name}</h1>
      </div>
      <p style={{ color: "var(--muted)" }}>{vendor.primary_domain}</p>

      <div className="grid">
        <div className="card">
          <div className="stat-value">{vendor.criticality}</div>
          <div className="stat-label">Business criticality</div>
        </div>
        <div className="card">
          <div className="stat-value">{vendor.risk_tier}</div>
          <div className="stat-label">Risk tier</div>
        </div>
        <div className="card">
          <div className="stat-value">{scores[0]?.score ?? "—"}</div>
          <div className="stat-label">External risk score</div>
        </div>
        <div className="card">
          <div className="stat-value">{vendor.active_scan_authorized ? "Authorized" : "Passive only"}</div>
          <div className="stat-label">Active scanning</div>
        </div>
      </div>

      <button className="primary" onClick={handleScan} disabled={scanning || pollingScanId !== null}>
        {scanning ? "Starting scan..." : pollingScanId ? "Scan running..." : "Run passive scan"}
      </button>
      {scanMessage && <p style={{ marginTop: "0.5rem" }}>{scanMessage}</p>}

      <div className="tabs" style={{ marginTop: "1.5rem" }}>
        {TABS.map(([key, label]) => (
          <button
            key={key}
            className={`tab ${tab === key ? "active" : ""}`}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && !editing && (
        <div className="card">
          <button className="primary" style={{ marginBottom: "1rem" }} onClick={() => setEditing(true)}>
            Edit vendor
          </button>
          <p>
            <strong>Business owner:</strong> {vendor.business_owner ?? "—"}
          </p>
          <p>
            <strong>Vendor category:</strong> {vendor.vendor_category}
          </p>
          <p>
            <strong>Data access level:</strong> {vendor.data_access_level}
          </p>
          <p>
            <strong>System access level:</strong> {vendor.system_access_level}
          </p>
          <p>
            <strong>Renewal date:</strong> {vendor.renewal_date ?? "—"}
          </p>
          <p>
            <strong>Notes:</strong> {vendor.notes ?? "—"}
          </p>

          <TrustCenterSection vendor={vendor} onEdit={() => setEditing(true)} />
        </div>
      )}

      {tab === "overview" && editing && (
        <VendorEditForm
          vendor={vendor}
          onCancel={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            reload();
          }}
        />
      )}

      {tab === "assets" && (
        <AssetsTable assets={assets} />
      )}

      {tab === "findings" && (
        <FindingsTable findings={findings} onChanged={reload} />
      )}

      {tab === "scans" && (
        <ScansTable scans={scans} />
      )}

      {tab === "scores" && (
        <ScoresTable scores={scores} />
      )}

      {tab === "summary" && (
        <ExecutiveSummaryView summary={summary} error={summaryError} />
      )}

      {tab === "news" && (
        <NewsList news={news} loading={newsLoading} error={newsError} />
      )}
    </div>
  );
}

function TrustCenterSection({ vendor, onEdit }: { vendor: Vendor; onEdit: () => void }) {
  const hasLinks = Boolean(
    vendor.trust_center_url || vendor.security_page_url || vendor.status_page_url
  );

  // When nothing's recorded yet, offer the places a trust center usually
  // lives rather than a dead end. These are starting points for an analyst to
  // check — the platform is not claiming any of them exist.
  const guesses = [
    { label: "Search the web", href: `https://www.google.com/search?q=${encodeURIComponent(`${vendor.name} trust center security compliance`)}` },
    { label: `trust.${vendor.primary_domain}`, href: `https://trust.${vendor.primary_domain}` },
    { label: `${vendor.primary_domain}/security`, href: `https://${vendor.primary_domain}/security` },
    { label: `status.${vendor.primary_domain}`, href: `https://status.${vendor.primary_domain}` },
    { label: "security.txt", href: `https://${vendor.primary_domain}/.well-known/security.txt` },
  ];

  return (
    <div style={{ marginTop: "1.25rem", borderTop: "1px solid var(--border)", paddingTop: "1rem" }}>
      <p style={{ fontWeight: 600, margin: "0 0 0.5rem 0" }}>Security &amp; compliance</p>

      {hasLinks ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
          {vendor.trust_center_url && (
            <p style={{ margin: 0 }}>
              <strong>Trust center:</strong>{" "}
              <a href={vendor.trust_center_url} target="_blank" rel="noopener noreferrer">
                {vendor.trust_center_url}
              </a>
            </p>
          )}
          {vendor.security_page_url && (
            <p style={{ margin: 0 }}>
              <strong>Security page:</strong>{" "}
              <a href={vendor.security_page_url} target="_blank" rel="noopener noreferrer">
                {vendor.security_page_url}
              </a>
            </p>
          )}
          {vendor.status_page_url && (
            <p style={{ margin: 0 }}>
              <strong>Status page:</strong>{" "}
              <a href={vendor.status_page_url} target="_blank" rel="noopener noreferrer">
                {vendor.status_page_url}
              </a>
            </p>
          )}
          {vendor.compliance_notes && (
            <p style={{ margin: "0.25rem 0 0 0" }}>
              <strong>Compliance notes:</strong> {vendor.compliance_notes}
            </p>
          )}
        </div>
      ) : (
        <>
          <p style={{ color: "var(--muted)", margin: "0 0 0.5rem 0" }}>
            No trust center recorded yet. These are common places to look — verify what you find,
            then save it via{" "}
            <button
              onClick={onEdit}
              style={{
                background: "none",
                border: "none",
                color: "var(--accent)",
                padding: 0,
                cursor: "pointer",
                textDecoration: "underline",
                font: "inherit",
              }}
            >
              Edit vendor
            </button>
            .
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {guesses.map((g) => (
              <a
                key={g.label}
                href={g.href}
                target="_blank"
                rel="noopener noreferrer"
                className="badge badge-info"
                style={{ textTransform: "none", padding: "0.3rem 0.6rem" }}
              >
                {g.label}
              </a>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function VendorEditForm({
  vendor,
  onCancel,
  onSaved,
}: {
  vendor: Vendor;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(vendor.name);
  const [domain, setDomain] = useState(vendor.primary_domain);
  const [businessOwner, setBusinessOwner] = useState(vendor.business_owner ?? "");
  const [vendorCategory, setVendorCategory] = useState<VendorCategory>(vendor.vendor_category);
  const [criticality, setCriticality] = useState<Criticality>(vendor.criticality);
  const [riskTier, setRiskTier] = useState<RiskTier>(vendor.risk_tier);
  const [dataAccessLevel, setDataAccessLevel] = useState<AccessLevel>(vendor.data_access_level);
  const [systemAccessLevel, setSystemAccessLevel] = useState<AccessLevel>(vendor.system_access_level);
  const [activeScanAuthorized, setActiveScanAuthorized] = useState(vendor.active_scan_authorized);
  const [trustCenterUrl, setTrustCenterUrl] = useState(vendor.trust_center_url ?? "");
  const [securityPageUrl, setSecurityPageUrl] = useState(vendor.security_page_url ?? "");
  const [statusPageUrl, setStatusPageUrl] = useState(vendor.status_page_url ?? "");
  const [complianceNotes, setComplianceNotes] = useState(vendor.compliance_notes ?? "");
  const [notes, setNotes] = useState(vendor.notes ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await api.updateVendor(vendor.id, {
        name,
        primary_domain: domain,
        business_owner: businessOwner || null,
        vendor_category: vendorCategory,
        criticality,
        risk_tier: riskTier,
        data_access_level: dataAccessLevel,
        system_access_level: systemAccessLevel,
        active_scan_authorized: activeScanAuthorized,
        trust_center_url: trustCenterUrl || null,
        security_page_url: securityPageUrl || null,
        status_page_url: statusPageUrl || null,
        compliance_notes: complianceNotes || null,
        notes: notes || null,
      });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="card" onSubmit={handleSubmit}>
      <div className="form-grid">
        <div className="form-field">
          <label htmlFor="edit-name">Vendor name</label>
          <input id="edit-name" required value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="form-field">
          <label htmlFor="edit-domain">Primary domain</label>
          <input id="edit-domain" required value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
        <div className="form-field">
          <label htmlFor="edit-owner">Business owner</label>
          <input
            id="edit-owner"
            value={businessOwner}
            onChange={(e) => setBusinessOwner(e.target.value)}
          />
        </div>
        <div className="form-field">
          <label htmlFor="edit-category">Vendor category</label>
          <select
            id="edit-category"
            value={vendorCategory}
            onChange={(e) => setVendorCategory(e.target.value as VendorCategory)}
          >
            {VENDOR_CATEGORY_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="edit-criticality">Criticality</label>
          <select
            id="edit-criticality"
            value={criticality}
            onChange={(e) => setCriticality(e.target.value as Criticality)}
          >
            {CRITICALITY_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="edit-risk-tier">Risk tier</label>
          <select
            id="edit-risk-tier"
            value={riskTier}
            onChange={(e) => setRiskTier(e.target.value as RiskTier)}
          >
            {RISK_TIER_OPTIONS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="edit-data-access">Data access level</label>
          <select
            id="edit-data-access"
            value={dataAccessLevel}
            onChange={(e) => setDataAccessLevel(e.target.value as AccessLevel)}
          >
            {ACCESS_LEVEL_OPTIONS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="edit-system-access">System access level</label>
          <select
            id="edit-system-access"
            value={systemAccessLevel}
            onChange={(e) => setSystemAccessLevel(e.target.value as AccessLevel)}
          >
            {ACCESS_LEVEL_OPTIONS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="form-field" style={{ marginBottom: "0.75rem" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <input
            type="checkbox"
            checked={activeScanAuthorized}
            onChange={(e) => setActiveScanAuthorized(e.target.checked)}
          />
          Active scan authorized
        </label>
      </div>

      <div className="form-grid">
        <div className="form-field">
          <label htmlFor="edit-trust-center">Trust center URL</label>
          <input
            id="edit-trust-center"
            type="url"
            placeholder="https://trust.vendor.com"
            value={trustCenterUrl}
            onChange={(e) => setTrustCenterUrl(e.target.value)}
          />
        </div>
        <div className="form-field">
          <label htmlFor="edit-security-page">Security page URL</label>
          <input
            id="edit-security-page"
            type="url"
            placeholder="https://vendor.com/security"
            value={securityPageUrl}
            onChange={(e) => setSecurityPageUrl(e.target.value)}
          />
        </div>
        <div className="form-field">
          <label htmlFor="edit-status-page">Status page URL</label>
          <input
            id="edit-status-page"
            type="url"
            placeholder="https://status.vendor.com"
            value={statusPageUrl}
            onChange={(e) => setStatusPageUrl(e.target.value)}
          />
        </div>
      </div>

      <div className="form-field" style={{ marginBottom: "0.75rem" }}>
        <label htmlFor="edit-compliance-notes">Compliance notes</label>
        <textarea
          id="edit-compliance-notes"
          rows={3}
          placeholder="Where the SOC 2 report lives, who to request it from, NDA status..."
          value={complianceNotes}
          onChange={(e) => setComplianceNotes(e.target.value)}
        />
      </div>

      <div className="form-field" style={{ marginBottom: "0.75rem" }}>
        <label htmlFor="edit-notes">Notes</label>
        <textarea
          id="edit-notes"
          rows={3}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </div>

      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", gap: "0.5rem" }}>
        <button className="primary" type="submit" disabled={saving}>
          {saving ? "Saving..." : "Save changes"}
        </button>
        <button type="button" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function ExecutiveSummaryView({
  summary,
  error,
}: {
  summary: ExecutiveSummary | null;
  error: string | null;
}) {
  if (error) {
    return <p className="error-text">Could not load executive summary: {error}</p>;
  }
  if (!summary) {
    return <p>Loading executive summary...</p>;
  }

  return (
    <div className="card">
      <p style={{ margin: 0, fontSize: "1.1rem" }}>
        <strong>{summary.vendor_name}</strong>
      </p>
      <p style={{ color: "var(--muted)", marginTop: "0.25rem" }}>
        Generated {new Date(summary.generated_at).toLocaleString()}
      </p>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
        <div className="card">
          <div className="stat-value">{summary.overall_risk_label}</div>
          <div className="stat-label">Overall risk</div>
        </div>
        <div className="card">
          <div className="stat-value">
            {summary.external_security_score ?? "—"}
            {summary.external_security_grade ? ` (${summary.external_security_grade})` : ""}
          </div>
          <div className="stat-label">External security</div>
        </div>
        <div className="card">
          <div className="stat-value">{summary.business_criticality}</div>
          <div className="stat-label">Business criticality</div>
        </div>
      </div>

      <div style={{ marginTop: "1rem" }}>
        <p style={{ fontWeight: 600, marginBottom: "0.4rem" }}>Key concerns</p>
        {summary.key_concerns.length === 0 ? (
          <p style={{ color: "var(--muted)" }}>None currently identified.</p>
        ) : (
          <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
            {summary.key_concerns.map((concern) => (
              <li key={concern}>{concern}</li>
            ))}
          </ul>
        )}
      </div>

      <div style={{ marginTop: "1rem" }}>
        <p style={{ fontWeight: 600, marginBottom: "0.4rem" }}>Positive indicators</p>
        <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
          {summary.positive_indicators.map((indicator) => (
            <li key={indicator}>{indicator}</li>
          ))}
        </ul>
      </div>

      <div style={{ marginTop: "1rem" }}>
        <p style={{ fontWeight: 600, marginBottom: "0.4rem" }}>Recommended action</p>
        <p style={{ margin: 0 }}>{summary.recommended_action}</p>
      </div>
    </div>
  );
}

function NewsList({
  news,
  loading,
  error,
}: {
  news: NewsMention[] | null;
  loading: boolean;
  error: string | null;
}) {
  if (error) {
    return <p className="error-text">Could not load news: {error}</p>;
  }
  if (loading || news === null) {
    return <p>Checking recent security news for mentions...</p>;
  }
  if (news.length === 0) {
    return (
      <p className="empty-state">
        No recent mentions found in cybersecurity news feeds. This checks a handful of security
        news sources for the vendor&apos;s name — absence of news is not the same as a clean bill
        of health.
      </p>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      {news.map((item) => {
        const parsed = item.published_at ? new Date(item.published_at) : null;
        const dateLabel = parsed && !isNaN(parsed.getTime()) ? parsed.toLocaleString() : item.published_at;
        return (
          <div className="card" key={item.link}>
            <a href={item.link} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 600 }}>
              {item.title}
            </a>
            <p style={{ color: "var(--muted)", fontSize: "0.85rem", margin: "0.25rem 0" }}>
              {item.source}
              {dateLabel ? ` — ${dateLabel}` : ""}
            </p>
            {item.description && <p style={{ margin: 0 }}>{item.description}</p>}
          </div>
        );
      })}
    </div>
  );
}

function AssetsTable({ assets }: { assets: Asset[] }) {
  if (assets.length === 0) {
    return <p className="empty-state">No assets discovered yet. Run a scan to populate this list.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Hostname</th>
          <th>IP</th>
          <th>Type</th>
          <th>Source</th>
          <th>Ownership confidence</th>
        </tr>
      </thead>
      <tbody>
        {assets.map((asset) => (
          <tr key={asset.id}>
            <td>{asset.hostname ?? "—"}</td>
            <td>{asset.ip_address ?? "—"}</td>
            <td>{asset.asset_type}</td>
            <td>{asset.source}</td>
            <td>{asset.ownership_confidence}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FindingsTable({ findings, onChanged }: { findings: Finding[]; onChanged: () => void }) {
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (findings.length === 0) {
    return <p className="empty-state">No findings yet.</p>;
  }

  async function handleAction(
    findingId: string,
    action: (id: string) => Promise<Finding>
  ) {
    setPendingId(findingId);
    setError(null);
    try {
      await action(findingId);
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPendingId(null);
    }
  }

  const triagedStatuses = new Set(["open", "investigating"]);

  return (
    <>
      {error && <p className="error-text">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>Risk points</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => {
            const isPending = pendingId === finding.id;
            const isTriageable = triagedStatuses.has(finding.status);
            return (
              <tr key={finding.id}>
                <td>{finding.title}</td>
                <td>
                  <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
                </td>
                <td>{finding.confidence}</td>
                <td>{finding.status}</td>
                <td>{finding.risk_points}</td>
                <td>
                  <div style={{ display: "flex", gap: "0.4rem" }}>
                    {isTriageable ? (
                      <>
                        <button
                          className="primary"
                          disabled={isPending}
                          onClick={() => handleAction(finding.id, api.markFalsePositive)}
                        >
                          False positive
                        </button>
                        <button
                          className="primary"
                          disabled={isPending}
                          onClick={() => handleAction(finding.id, api.acceptRisk)}
                        >
                          Accept risk
                        </button>
                      </>
                    ) : (
                      <button
                        className="primary"
                        disabled={isPending}
                        onClick={() => handleAction(finding.id, api.reopenFinding)}
                      >
                        Reopen
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function ScansTable({ scans }: { scans: Scan[] }) {
  if (scans.length === 0) {
    return <p className="empty-state">No scans run yet.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Mode</th>
          <th>Status</th>
          <th>Findings</th>
          <th>Started</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id}>
            <td>{scan.scan_type}</td>
            <td>{scan.mode}</td>
            <td>{scan.status}</td>
            <td>{scan.findings_count}</td>
            <td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ScoresTable({ scores }: { scores: RiskScore[] }) {
  if (scores.length === 0) {
    return <p className="empty-state">No score history yet — scores are recorded after a scan runs.</p>;
  }

  const latest = scores[0];
  const categories = Object.entries(latest.category_scores).filter(
    ([, category]) => category.deductions.length > 0
  );

  return (
    <>
      <div className="card" style={{ marginBottom: "1rem" }}>
        <p style={{ margin: 0 }}>
          <strong>External Risk Score: {latest.score}/100 (grade {latest.grade})</strong>
        </p>
        {categories.length === 0 ? (
          <p style={{ color: "var(--muted)", marginBottom: 0 }}>
            No point deductions on the current scan — every category scored 100.
          </p>
        ) : (
          <div style={{ marginTop: "0.75rem" }}>
            {categories.map(([categoryName, category]) => (
              <div key={categoryName} style={{ marginBottom: "0.6rem" }}>
                <p style={{ margin: "0 0 0.25rem 0", color: "var(--muted)" }}>
                  {categoryName.replace(/_/g, " ")} — {category.score}/100 (weight{" "}
                  {Math.round(category.weight * 100)}%)
                </p>
                <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
                  {category.deductions.map((deduction) => (
                    <li key={deduction.finding_id}>
                      {deduction.title}: -{deduction.points}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>

      <table>
        <thead>
          <tr>
            <th>Score</th>
            <th>Grade</th>
            <th>Version</th>
            <th>Calculated</th>
          </tr>
        </thead>
        <tbody>
          {scores.map((score) => (
            <tr key={score.id}>
              <td>{score.score}</td>
              <td>{score.grade}</td>
              <td>{score.scoring_version}</td>
              <td>{new Date(score.calculated_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
