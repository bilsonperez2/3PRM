import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "TPRM Platform",
  description: "Third-party cyber risk management and external attack surface monitoring",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav className="nav">
          <div className="nav-inner">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/4wall-logo.png" alt="4Wall Entertainment" style={{ height: "48px", width: "auto" }} />
            <Link href="/">Dashboard</Link>
            <Link href="/vendors">Vendors</Link>
            <Link href="/organization">Organization</Link>
            <Link href="/status">Status</Link>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
