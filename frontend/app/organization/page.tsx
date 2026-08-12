"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { VendorLogo } from "@/components/VendorLogo";
import { api, Vendor } from "@/lib/api";

export default function OrganizationPage() {
  const [domains, setDomains] = useState<Vendor[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  function reload() {
    api
      .listOrganizationDomains()
      .then(setDomains)
      .catch((err) => setError(err.message));
  }

  useEffect(reload, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    setSuccessMessage(null);
    try {
      const created = await api.createOrganizationDomain({ name, primary_domain: domain });
      setName("");
      setDomain("");
      setShowForm(false);
      setSuccessMessage(`${created.name} added — initial passive scan queued.`);
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="container">
      <h1>Organization</h1>
      <p style={{ color: "var(--muted)", marginTop: "-0.5rem" }}>
        4Wall&apos;s own domain(s) — brand protection and typosquat monitoring, kept separate
        from third-party vendors. Scans, findings, and scores work exactly the same as they do
        for a vendor; this is just a different list.
      </p>

      <button className="primary" onClick={() => setShowForm((v) => !v)}>
        {showForm ? "Cancel" : "Add organization domain"}
      </button>

      {showForm && (
        <form className="card" style={{ marginTop: "1rem" }} onSubmit={handleSubmit}>
          <div className="form-grid">
            <div className="form-field">
              <label htmlFor="org-name">Name</label>
              <input
                id="org-name"
                required
                placeholder="4Wall Entertainment"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="form-field">
              <label htmlFor="org-domain">Domain</label>
              <input
                id="org-domain"
                required
                placeholder="4wall.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
            </div>
          </div>
          {formError && <p className="error-text">{formError}</p>}
          <button className="primary" type="submit" disabled={submitting}>
            {submitting ? "Saving..." : "Save"}
          </button>
        </form>
      )}

      {successMessage && <p style={{ color: "var(--low)" }}>{successMessage}</p>}
      {error && <p className="error-text">Could not load organization domains: {error}</p>}

      {domains && domains.length === 0 && (
        <p className="empty-state">
          No organization domains yet. Add 4Wall&apos;s domain above to start monitoring it for
          typosquatting and DNS/email security posture.
        </p>
      )}

      {domains && domains.length > 0 && (
        <table style={{ marginTop: "1rem" }}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Domain</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((d) => (
              <tr key={d.id}>
                <td>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <VendorLogo domain={d.primary_domain} />
                    <Link href={`/vendors/${d.id}`}>{d.name}</Link>
                  </div>
                </td>
                <td>{d.primary_domain}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
