"use client";

/**
 * Pulls a small icon for a vendor's domain via Google's public favicon
 * service — no API key, no scraping, just an image URL derived from the
 * domain already on the Vendor record. This is a favicon, not necessarily a
 * full company logo, but it's a stable, keyless way to put *some* visual
 * brand identity next to a vendor's name. Decorative (alt=""), since the
 * vendor name text beside it already conveys identity — and it hides itself
 * on load failure rather than showing a broken-image icon.
 */
export function VendorLogo({ domain, size = 24 }: { domain: string; size?: number }) {
  if (!domain) return null;
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={`https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=64`}
      alt=""
      width={size}
      height={size}
      style={{ borderRadius: "4px", flexShrink: 0 }}
      onError={(e) => {
        (e.currentTarget as HTMLImageElement).style.visibility = "hidden";
      }}
    />
  );
}
