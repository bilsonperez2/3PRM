"use client";

import { useEffect, useState } from "react";
import { StatusPageLink } from "@/components/StatusPageLink";
import { VendorLogo } from "@/components/VendorLogo";
import {
  api,
  ReportedIndicator,
  UptimeDay,
  VendorReportedStatus,
  VendorUptime,
} from "@/lib/api";

const INDICATOR_STYLE: Record<ReportedIndicator, { color: string; label: string }> = {
  operational: { color: "var(--low)", label: "Operational" },
  maintenance: { color: "var(--info)", label: "Maintenance" },
  degraded: { color: "var(--medium)", label: "Degraded" },
  partial_outage: { color: "var(--high)", label: "Partial outage" },
  major_outage: { color: "var(--critical)", label: "Major outage" },
};

/** The vendor's own reported health. Shown alongside our probe rather than
 *  merged with it — they answer different questions, and a healthy root
 *  domain alongside a vendor-reported API outage is precisely the case worth
 *  surfacing. */
function ReportedStatusBlock({ reported }: { reported: VendorReportedStatus }) {
  const style = INDICATOR_STYLE[reported.indicator] ?? INDICATOR_STYLE.operational;
  const impaired = reported.components.filter((c) => c.indicator !== "operational");

  return (
    <div
      style={{
        marginTop: "0.6rem",
        paddingTop: "0.6rem",
        borderTop: "1px solid var(--border)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
        <span
          aria-hidden="true"
          style={{ width: 9, height: 9, borderRadius: "50%", background: style.color, flexShrink: 0 }}
        />
        {/* Colour never carries meaning alone — the label is always present. */}
        <strong style={{ fontSize: "0.85rem" }}>Vendor reports: {style.label}</strong>
        <span style={{ color: "var(--muted)", fontSize: "0.8rem" }}>{reported.description}</span>
      </div>

      {impaired.length > 0 && (
        <ul style={{ margin: "0.4rem 0 0 0", paddingLeft: "1.1rem", fontSize: "0.8rem" }}>
          {impaired.slice(0, 6).map((component) => (
            <li key={component.name}>
              {component.name} —{" "}
              {(INDICATOR_STYLE[component.indicator] ?? INDICATOR_STYLE.operational).label}
            </li>
          ))}
          {impaired.length > 6 && <li>+{impaired.length - 6} more</li>}
        </ul>
      )}

      {reported.active_incidents.length > 0 && (
        <ul style={{ margin: "0.4rem 0 0 0", paddingLeft: "1.1rem", fontSize: "0.8rem" }}>
          {reported.active_incidents.slice(0, 3).map((incident) => (
            <li key={incident.name}>
              {incident.url ? (
                <a href={incident.url} target="_blank" rel="noopener noreferrer">
                  {incident.name}
                </a>
              ) : (
                incident.name
              )}
              {incident.impact ? ` (${incident.impact})` : ""}
            </li>
          ))}
        </ul>
      )}

      <p style={{ color: "var(--muted)", fontSize: "0.7rem", margin: "0.35rem 0 0 0" }}>
        via {reported.platform} · {reported.components.length} components tracked
      </p>
    </div>
  );
}

const WINDOW_OPTIONS = [7, 30, 90];

/** Uptime is a magnitude on a fixed 0-100 scale, so the bars use one hue with
 *  severity thresholds rather than a categorical palette. "No data" is its own
 *  muted state — never rendered as if it were an outage. */
function dayColor(day: UptimeDay): string {
  if (day.uptime_percent === null) return "var(--info)";
  if (day.uptime_percent >= 99.5) return "var(--low)";
  if (day.uptime_percent >= 95) return "var(--medium)";
  if (day.uptime_percent >= 80) return "var(--high)";
  return "var(--critical)";
}

function StatusDot({ reachable }: { reachable: boolean | null }) {
  const color =
    reachable === null ? "var(--info)" : reachable ? "var(--low)" : "var(--critical)";
  const label = reachable === null ? "No data yet" : reachable ? "Up" : "Down";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem" }}>
      <span
        aria-hidden="true"
        style={{
          width: 9,
          height: 9,
          borderRadius: "50%",
          background: color,
          flexShrink: 0,
        }}
      />
      {/* Colour never carries the state alone — the word is always present. */}
      <span style={{ fontSize: "0.85rem" }}>{label}</span>
    </span>
  );
}

function DailyStrip({ daily, days }: { daily: UptimeDay[]; days: number }) {
  const [hovered, setHovered] = useState<number | null>(null);

  if (daily.length === 0) {
    return (
      <p style={{ color: "var(--muted)", fontSize: "0.85rem", margin: 0 }}>
        No checks recorded yet — the first probe runs within a few minutes.
      </p>
    );
  }

  return (
    <div style={{ position: "relative" }}>
      <div style={{ display: "flex", gap: 2, alignItems: "flex-end", height: 34 }}>
        {daily.map((day, i) => (
          <div
            key={day.day}
            onMouseEnter={() => setHovered(i)}
            onMouseLeave={() => setHovered(null)}
            onFocus={() => setHovered(i)}
            onBlur={() => setHovered(null)}
            tabIndex={0}
            title={`${day.day}: ${
              day.uptime_percent === null ? "no data" : `${day.uptime_percent}% up`
            } (${day.checks} checks)`}
            style={{
              flex: 1,
              minWidth: 3,
              height: "100%",
              background: dayColor(day),
              borderRadius: 2,
              cursor: "default",
            }}
          />
        ))}
      </div>
      {hovered !== null && (
        <div className="chart-tooltip" style={{ bottom: "auto", top: "100%", marginTop: "0.3rem" }}>
          {daily[hovered].day}:{" "}
          {daily[hovered].uptime_percent === null
            ? "no data"
            : `${daily[hovered].uptime_percent}% up`}{" "}
          ({daily[hovered].checks} checks)
        </div>
      )}
      <p style={{ color: "var(--muted)", fontSize: "0.72rem", margin: "0.3rem 0 0 0" }}>
        {daily.length} day{daily.length === 1 ? "" : "s"} of data · window {days}d
      </p>
    </div>
  );
}

function VendorRow({ vendor, days }: { vendor: VendorUptime; days: number }) {
  return (
    <div className="card" style={{ marginBottom: "0.75rem" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "0.75rem",
          flexWrap: "wrap",
          marginBottom: "0.6rem",
        }}
      >
        <VendorLogo domain={vendor.primary_domain} />
        <strong>{vendor.vendor_name}</strong>
        {vendor.is_internal_brand && (
          <span className="badge badge-info" style={{ textTransform: "none" }}>
            Us
          </span>
        )}
        <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>{vendor.primary_domain}</span>
        <span style={{ marginLeft: "auto" }}>
          <StatusDot reachable={vendor.currently_reachable} />
        </span>
        <span style={{ fontVariantNumeric: "tabular-nums", minWidth: 70, textAlign: "right" }}>
          {vendor.uptime_percent === null ? "—" : `${vendor.uptime_percent}%`}
        </span>
      </div>

      <DailyStrip daily={vendor.daily} days={days} />

      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "1rem",
          flexWrap: "wrap",
          marginTop: "0.5rem",
        }}
      >
        {vendor.avg_response_time_ms !== null ? (
          <p style={{ color: "var(--muted)", fontSize: "0.78rem", margin: 0 }}>
            Avg response {vendor.avg_response_time_ms}ms · {vendor.checks} checks
          </p>
        ) : (
          <span />
        )}
        <StatusPageLink
          statusPageUrl={vendor.status_page_url}
          domain={vendor.primary_domain}
          compact
        />
      </div>

      {vendor.reported_status ? (
        <ReportedStatusBlock reported={vendor.reported_status} />
      ) : (
        vendor.status_page_url && (
          <p style={{ color: "var(--muted)", fontSize: "0.75rem", margin: "0.5rem 0 0 0" }}>
            Their status page isn&apos;t on a platform we can read automatically — open the link
            above to check it.
          </p>
        )
      )}

      {vendor.incidents.length > 0 && (
        <div style={{ marginTop: "0.6rem" }}>
          <p style={{ fontSize: "0.8rem", fontWeight: 600, margin: "0 0 0.25rem 0" }}>
            Incidents ({vendor.incidents.length})
          </p>
          <ul style={{ margin: 0, paddingLeft: "1.1rem", fontSize: "0.82rem" }}>
            {vendor.incidents.slice(0, 5).map((incident) => (
              <li key={incident.started_at}>
                {new Date(incident.started_at).toLocaleString()} — {incident.duration_minutes}m
                {incident.error ? ` (${incident.error})` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function StatusPage() {
  const [status, setStatus] = useState<VendorUptime[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);

  useEffect(() => {
    setStatus(null);
    setError(null);
    api
      .getStatus(days)
      .then(setStatus)
      .catch((err) => setError(err.message));
  }, [days]);

  const down = (status ?? []).filter((v) => v.currently_reachable === false);

  return (
    <div className="container">
      <h1>Status</h1>
      <p style={{ color: "var(--muted)", marginTop: "-0.5rem" }}>
        Availability of every monitored domain, probed every few minutes. This reflects whether
        the site answered <em>us</em> from one location — treat sustained failures as signal and
        isolated blips as noise.
      </p>

      <div style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}>
        {WINDOW_OPTIONS.map((option) => (
          <button
            key={option}
            className={days === option ? "primary" : ""}
            onClick={() => setDays(option)}
          >
            {option} days
          </button>
        ))}
      </div>

      {error && <p className="error-text">Could not load status: {error}</p>}
      {!error && status === null && <p>Loading availability...</p>}

      {status !== null && status.length === 0 && (
        <p className="empty-state">No vendors to monitor yet.</p>
      )}

      {status !== null && status.length > 0 && (
        <>
          <div className="card" style={{ marginBottom: "1rem" }}>
            {down.length === 0 ? (
              <strong style={{ color: "var(--low)" }}>
                All {status.length} monitored domains are currently reachable.
              </strong>
            ) : (
              <strong style={{ color: "var(--critical)" }}>
                {down.length} of {status.length} domains currently unreachable:{" "}
                {down.map((v) => v.vendor_name).join(", ")}
              </strong>
            )}
          </div>

          {status.map((vendor) => (
            <VendorRow key={vendor.vendor_id} vendor={vendor} days={days} />
          ))}
        </>
      )}
    </div>
  );
}
