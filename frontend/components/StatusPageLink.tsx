"use client";

/**
 * A vendor's own published status page.
 *
 * When recorded, this is the authoritative source — it's what the vendor
 * reports about their own services, versus our probe which only knows whether
 * their domain answered us from one location.
 *
 * When not recorded, we offer the common hosting patterns as one-click
 * shortcuts rather than guessing. Status pages have no standard location and
 * are spread across Statuspage.io, Instatus, Better Stack, and vendor
 * trust-page products, so auto-linking would produce confident-looking dead
 * links. These are labelled as places to check.
 */
export function statusPageGuesses(domain: string): Array<{ label: string; href: string }> {
  return [
    { label: `status.${domain}`, href: `https://status.${domain}` },
    { label: `trust.${domain}`, href: `https://trust.${domain}` },
    { label: `${domain}/status`, href: `https://${domain}/status` },
    {
      label: "Search",
      href: `https://www.google.com/search?q=${encodeURIComponent(`${domain} status page`)}`,
    },
  ];
}

export function StatusPageLink({
  statusPageUrl,
  domain,
  compact = false,
}: {
  statusPageUrl: string | null;
  domain: string;
  compact?: boolean;
}) {
  if (statusPageUrl) {
    return (
      <a href={statusPageUrl} target="_blank" rel="noopener noreferrer">
        Vendor status page ↗
      </a>
    );
  }

  if (compact) {
    return <span style={{ color: "var(--muted)", fontSize: "0.8rem" }}>No status page recorded</span>;
  }

  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem", alignItems: "center" }}>
      <span style={{ color: "var(--muted)", fontSize: "0.8rem" }}>
        No status page recorded — common locations:
      </span>
      {statusPageGuesses(domain).map((guess) => (
        <a
          key={guess.label}
          href={guess.href}
          target="_blank"
          rel="noopener noreferrer"
          className="badge badge-info"
          style={{ textTransform: "none", padding: "0.25rem 0.5rem" }}
        >
          {guess.label}
        </a>
      ))}
    </div>
  );
}
