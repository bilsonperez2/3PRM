"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { VendorLogo } from "@/components/VendorLogo";
import {
  api,
  AccessLevel,
  Criticality,
  RiskTier,
  Vendor,
  VendorCategory,
  VendorListItem,
} from "@/lib/api";

const CRITICALITY_OPTIONS: Criticality[] = ["low", "medium", "high", "critical"];
const RISK_TIER_OPTIONS: RiskTier[] = ["low", "medium", "high", "critical"];
const ACCESS_LEVEL_OPTIONS: AccessLevel[] = ["none", "low", "moderate", "high", "critical"];
const VENDOR_CATEGORY_OPTIONS: VendorCategory[] = [
  "software", "cloud_hosting", "professional_services", "payment_processing",
  "logistics", "staffing", "marketing", "equipment_supplier", "other",
];

function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function tierBadgeClass(tier: string): string {
  return `badge badge-${tier}`;
}

function formatLastScanned(value: string | null): string {
  if (!value) return "Never";
  const scanned = new Date(value);
  if (isNaN(scanned.getTime())) return "Never";

  const minutes = Math.floor((Date.now() - scanned.getTime()) / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return scanned.toLocaleDateString();
}

export default function VendorsPage() {
  const [vendors, setVendors] = useState<VendorListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [businessOwner, setBusinessOwner] = useState("");
  const [vendorCategory, setVendorCategory] = useState<VendorCategory>("other");
  const [criticality, setCriticality] = useState<Criticality>("medium");
  const [riskTier, setRiskTier] = useState<RiskTier>("medium");
  const [dataAccessLevel, setDataAccessLevel] = useState<AccessLevel>("none");
  const [systemAccessLevel, setSystemAccessLevel] = useState<AccessLevel>("none");
  const [renewalDate, setRenewalDate] = useState("");
  const [notes, setNotes] = useState("");
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  function reload() {
    api
      .listVendors()
      .then(setVendors)
      .catch((err) => setError(err.message));
  }

  useEffect(reload, []);

  async function handleDelete(vendor: Vendor) {
    if (!window.confirm(`Remove ${vendor.name}? This deletes all its assets, findings, scans, and score history.`)) {
      return;
    }
    setDeletingId(vendor.id);
    setDeleteError(null);
    try {
      await api.deleteVendor(vendor.id);
      reload();
    } catch (err) {
      setDeleteError((err as Error).message);
    } finally {
      setDeletingId(null);
    }
  }

  function resetForm() {
    setName("");
    setDomain("");
    setBusinessOwner("");
    setVendorCategory("other");
    setCriticality("medium");
    setRiskTier("medium");
    setDataAccessLevel("none");
    setSystemAccessLevel("none");
    setRenewalDate("");
    setNotes("");
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    setSuccessMessage(null);
    try {
      const created = await api.createVendor({
        name,
        primary_domain: domain,
        business_owner: businessOwner || null,
        vendor_category: vendorCategory,
        criticality,
        risk_tier: riskTier,
        data_access_level: dataAccessLevel,
        system_access_level: systemAccessLevel,
        renewal_date: renewalDate || null,
        notes: notes || null,
      });
      resetForm();
      setShowForm(false);
      setSuccessMessage(`${created.name} added — initial passive scan queued.`);
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  // Onboarding the same domain twice is a common slip when several people
  // maintain the vendor list — warn before submit rather than silently
  // creating a duplicate that then gets scanned separately.
  const normalizedDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  const duplicateVendor =
    normalizedDomain.length > 0
      ? vendors?.find((v) => v.primary_domain.toLowerCase() === normalizedDomain)
      : undefined;

  return (
    <div className="container">
      <h1>Vendors</h1>

      <button
        className="primary"
        onClick={() => {
          if (showForm) {
            // Cancelling should discard what was typed, not leave it staged
            // to reappear the next time the form is opened.
            resetForm();
            setFormError(null);
          }
          setShowForm((v) => !v);
        }}
      >
        {showForm ? "Cancel" : "Add vendor"}
      </button>

      {showForm && (
        <form className="card" style={{ marginTop: "1rem" }} onSubmit={handleSubmit}>
          <p className="form-section-heading">Vendor details</p>
          <div className="form-grid">
            <div className="form-field">
              <label htmlFor="name">Vendor name *</label>
              <input
                id="name"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="form-field">
              <label htmlFor="domain">Primary domain *</label>
              <input
                id="domain"
                required
                placeholder="vendor.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
            </div>
            <div className="form-field">
              <label htmlFor="businessOwner">Business owner</label>
              <input
                id="businessOwner"
                placeholder="Who owns this relationship?"
                value={businessOwner}
                onChange={(e) => setBusinessOwner(e.target.value)}
              />
            </div>
            <div className="form-field">
              <label htmlFor="vendorCategory">Vendor category</label>
              <select
                id="vendorCategory"
                value={vendorCategory}
                onChange={(e) => setVendorCategory(e.target.value as VendorCategory)}
              >
                {VENDOR_CATEGORY_OPTIONS.map((c) => (
                  <option key={c} value={c}>
                    {titleCase(c)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <p className="form-section-heading">Risk classification</p>
          <div className="form-grid">
            <div className="form-field">
              <label htmlFor="criticality">Business criticality</label>
              <select
                id="criticality"
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as Criticality)}
              >
                {CRITICALITY_OPTIONS.map((c) => (
                  <option key={c} value={c}>
                    {titleCase(c)}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="riskTier">Risk tier</label>
              <select
                id="riskTier"
                value={riskTier}
                onChange={(e) => setRiskTier(e.target.value as RiskTier)}
              >
                {RISK_TIER_OPTIONS.map((t) => (
                  <option key={t} value={t}>
                    {titleCase(t)}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="dataAccess">Data access level</label>
              <select
                id="dataAccess"
                value={dataAccessLevel}
                onChange={(e) => setDataAccessLevel(e.target.value as AccessLevel)}
              >
                {ACCESS_LEVEL_OPTIONS.map((l) => (
                  <option key={l} value={l}>
                    {titleCase(l)}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="systemAccess">System access level</label>
              <select
                id="systemAccess"
                value={systemAccessLevel}
                onChange={(e) => setSystemAccessLevel(e.target.value as AccessLevel)}
              >
                {ACCESS_LEVEL_OPTIONS.map((l) => (
                  <option key={l} value={l}>
                    {titleCase(l)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <p className="form-section-heading">Contract &amp; notes</p>
          <div className="form-grid">
            <div className="form-field">
              <label htmlFor="renewalDate">Renewal date</label>
              <input
                id="renewalDate"
                type="date"
                value={renewalDate}
                onChange={(e) => setRenewalDate(e.target.value)}
              />
            </div>
          </div>
          <div className="form-field" style={{ marginBottom: "0.75rem" }}>
            <label htmlFor="notes">Notes</label>
            <textarea
              id="notes"
              rows={3}
              placeholder="What this vendor does for us, anything relevant to risk..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>

          <p style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
            A passive scan starts automatically once the vendor is saved. Active scanning stays
            off and can only be enabled per-vendor from the Edit screen, since it requires
            written authorization from the vendor. Trust center and compliance links can be
            added there too.
          </p>

          {duplicateVendor && (
            <p style={{ color: "var(--high)" }}>
              Heads up: <strong>{duplicateVendor.name}</strong> already uses {normalizedDomain}.
            </p>
          )}
          {formError && <p className="error-text">{formError}</p>}
          <button className="primary" type="submit" disabled={submitting}>
            {submitting ? "Saving..." : "Save vendor"}
          </button>
        </form>
      )}

      {successMessage && <p style={{ color: "var(--low)" }}>{successMessage}</p>}
      {error && <p className="error-text">Could not load vendors: {error}</p>}
      {deleteError && <p className="error-text">Could not remove vendor: {deleteError}</p>}

      {vendors && vendors.length === 0 && (
        <p className="empty-state">No vendors yet. Add your first vendor above.</p>
      )}

      {vendors && vendors.length > 0 && (
        <table style={{ marginTop: "1rem" }}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Domain</th>
              <th>Criticality</th>
              <th>Risk tier</th>
              <th>Last scanned</th>
              <th>Active scan authorized</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {vendors.map((vendor) => (
              <tr key={vendor.id}>
                <td>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <VendorLogo domain={vendor.primary_domain} />
                    <Link href={`/vendors/${vendor.id}`}>{vendor.name}</Link>
                  </div>
                </td>
                <td>{vendor.primary_domain}</td>
                <td>
                  <span className={tierBadgeClass(vendor.criticality)}>{vendor.criticality}</span>
                </td>
                <td>
                  <span className={tierBadgeClass(vendor.risk_tier)}>{vendor.risk_tier}</span>
                </td>
                <td
                  title={
                    vendor.last_scanned_at
                      ? new Date(vendor.last_scanned_at).toLocaleString()
                      : "This vendor has never completed a scan"
                  }
                  style={{ color: vendor.last_scanned_at ? undefined : "var(--muted)" }}
                >
                  {formatLastScanned(vendor.last_scanned_at)}
                </td>
                <td>{vendor.active_scan_authorized ? "Yes" : "No"}</td>
                <td>
                  <button
                    className="primary"
                    style={{ background: "var(--critical)" }}
                    disabled={deletingId === vendor.id}
                    onClick={() => handleDelete(vendor)}
                  >
                    {deletingId === vendor.id ? "Removing..." : "Remove"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
