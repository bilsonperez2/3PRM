"use client";

import { useEffect, useState } from "react";
import { api, DashboardSummary, VendorNewsMention } from "@/lib/api";

const CHART_HEIGHT = 110;

interface Bar {
  label: string;
  value: number;
  colorVar: string;
}

function BarChart({ title, bars }: { title: string; bars: Bar[] }) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const max = Math.max(1, ...bars.map((b) => b.value));

  return (
    <div className="card">
      <p style={{ margin: "0 0 1rem 0", fontWeight: 600 }}>{title}</p>
      <div className="bar-chart-bars" style={{ height: CHART_HEIGHT }}>
        {bars.map((bar, i) => {
          const barHeight = bar.value === 0 ? 2 : Math.max(6, Math.round((bar.value / max) * CHART_HEIGHT));
          return (
            <div
              key={bar.label}
              className="bar-chart-column"
              style={{ height: CHART_HEIGHT }}
              onMouseEnter={() => setHoveredIndex(i)}
              onMouseLeave={() => setHoveredIndex(null)}
              onFocus={() => setHoveredIndex(i)}
              onBlur={() => setHoveredIndex(null)}
              tabIndex={0}
            >
              {hoveredIndex === i && (
                <div className="chart-tooltip">
                  {bar.label}: {bar.value}
                </div>
              )}
              <div className="bar-chart-value">{bar.value}</div>
              <div
                className="bar-chart-bar"
                style={{ height: barHeight, background: `var(${bar.colorVar})` }}
              />
              <div className="bar-chart-label">{bar.label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [news, setNews] = useState<VendorNewsMention[] | null>(null);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [newsLoading, setNewsLoading] = useState(true);
  const [newsSearch, setNewsSearch] = useState("");

  useEffect(() => {
    api
      .getDashboard()
      .then(setSummary)
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    // Loaded independently from the rest of the dashboard — this fetches
    // RSS/Google News per vendor and is noticeably slower than the stat
    // tiles/charts above, which come straight from the database.
    setNewsLoading(true);
    setNewsError(null);
    api
      .getDashboardNews(14)
      .then(setNews)
      .catch((err) => setNewsError(err.message))
      .finally(() => setNewsLoading(false));
  }, []);

  if (error) {
    return (
      <div className="container">
        <p className="error-text">Could not load dashboard: {error}</p>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="container">
        <p>Loading dashboard...</p>
      </div>
    );
  }

  const stats: Array<[string, number]> = [
    ["Vendors", summary.vendor_count],
    ["Critical vendors", summary.critical_vendor_count],
    ["High-risk vendors", summary.high_risk_vendor_count],
    ["Vendors with new findings (7d)", summary.vendors_with_new_findings],
    ["Vendors with CISA KEV exposure", summary.vendors_with_kev_findings],
    ["Vendors with typosquat findings", summary.vendors_with_typosquatting_findings],
    ["Open critical findings", summary.open_critical_findings],
    ["Open high findings", summary.open_high_findings],
    ["Scans in last 7 days", summary.recent_scan_count],
  ];

  const riskTierBars: Bar[] = [
    { label: "Low", value: summary.vendor_risk_tier_counts.low, colorVar: "--low" },
    { label: "Medium", value: summary.vendor_risk_tier_counts.medium, colorVar: "--medium" },
    { label: "High", value: summary.vendor_risk_tier_counts.high, colorVar: "--high" },
    { label: "Critical", value: summary.vendor_risk_tier_counts.critical, colorVar: "--critical" },
  ];

  const findingSeverityBars: Bar[] = [
    { label: "Info", value: summary.open_finding_severity_counts.info, colorVar: "--info" },
    { label: "Low", value: summary.open_finding_severity_counts.low, colorVar: "--low" },
    { label: "Medium", value: summary.open_finding_severity_counts.medium, colorVar: "--medium" },
    { label: "High", value: summary.open_finding_severity_counts.high, colorVar: "--high" },
    { label: "Critical", value: summary.open_finding_severity_counts.critical, colorVar: "--critical" },
  ];

  return (
    <div className="container">
      <h1>Dashboard</h1>
      <div className="grid">
        {stats.map(([label, value]) => (
          <div className="card" key={label}>
            <div className="stat-value">{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
        <BarChart title="Vendors by risk tier" bars={riskTierBars} />
        <BarChart title="Open findings by severity" bars={findingSeverityBars} />
      </div>

      <VendorNewsSection
        news={news}
        loading={newsLoading}
        error={newsError}
        search={newsSearch}
        onSearchChange={setNewsSearch}
      />
    </div>
  );
}

const NEWS_PAGE_SIZE = 10;

function VendorNewsSection({
  news,
  loading,
  error,
  search,
  onSearchChange,
}: {
  news: VendorNewsMention[] | null;
  loading: boolean;
  error: string | null;
  search: string;
  onSearchChange: (value: string) => void;
}) {
  const [page, setPage] = useState(0);

  const filtered = (news ?? []).filter((item) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      item.title.toLowerCase().includes(q) ||
      item.vendor_name.toLowerCase().includes(q) ||
      item.source.toLowerCase().includes(q) ||
      (item.description ?? "").toLowerCase().includes(q)
    );
  });

  // Reset to the first page whenever the search narrows/widens the result set.
  useEffect(() => {
    setPage(0);
  }, [search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / NEWS_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages - 1);
  const pageItems = filtered.slice(currentPage * NEWS_PAGE_SIZE, (currentPage + 1) * NEWS_PAGE_SIZE);

  return (
    <div className="card" style={{ marginTop: "1.5rem" }}>
      <p style={{ margin: "0 0 0.75rem 0", fontWeight: 600 }}>Vendor news (last 14 days)</p>
      <input
        placeholder="Search by vendor, title, or source..."
        value={search}
        onChange={(e) => onSearchChange(e.target.value)}
        style={{ width: "100%", marginBottom: "1rem" }}
      />

      {error && <p className="error-text">Could not load vendor news: {error}</p>}
      {!error && loading && <p>Checking recent news across all vendors...</p>}
      {!error && !loading && news !== null && news.length === 0 && (
        <p className="empty-state">
          No vendor mentions found in the last 14 days. Absence of news is not the same as a
          clean bill of health.
        </p>
      )}
      {!error && !loading && news !== null && news.length > 0 && filtered.length === 0 && (
        <p className="empty-state">No results match &quot;{search}&quot;.</p>
      )}

      {filtered.length > 0 && (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {pageItems.map((item) => {
              const parsed = item.published_at ? new Date(item.published_at) : null;
              const dateLabel =
                parsed && !isNaN(parsed.getTime()) ? parsed.toLocaleString() : item.published_at;
              return (
                <div className="card" key={item.link}>
                  <span className="badge badge-low" style={{ marginBottom: "0.4rem", display: "inline-block" }}>
                    {item.vendor_name}
                  </span>
                  <a
                    href={item.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ display: "block", fontWeight: 600 }}
                  >
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

          {totalPages > 1 && (
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "1rem" }}>
              <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={currentPage === 0}>
                Previous
              </button>
              <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                Page {currentPage + 1} of {totalPages} ({filtered.length} result
                {filtered.length === 1 ? "" : "s"})
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={currentPage >= totalPages - 1}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
