"""One-off maintenance script: remove typosquat findings from non-internal-
brand vendors, then rescore them.

Context: typosquat/lookalike-domain monitoring was scoped to Organization
(is_internal_brand=True) entries only — see
app/services/scan_ingest.py::gather_intelligence. Existing typosquat findings
created for regular vendors before that change aren't touched by future scans
(the auto-remediate sweep only covers DNS/email check types), so this is a
one-time cleanup to bring current data in line with the new policy — not
something that needs to run again after this.

Run via:
    docker compose exec backend python -m app.scripts.cleanup_typosquat_findings
"""

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.finding import Finding
from app.models.vendor import Vendor
from app.services.risk_engine.config import NoActiveScoringConfigError
from app.services.risk_engine.scorer import score_vendor


def main() -> None:
    db = SessionLocal()
    try:
        vendor_ids = list(db.scalars(select(Vendor.id).where(Vendor.is_internal_brand.is_(False))))

        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.vendor_id.in_(vendor_ids),
                    Finding.finding_type.like("typosquat%"),
                )
            )
        )

        affected_vendor_ids = {f.vendor_id for f in findings}
        count = len(findings)

        for finding in findings:
            db.delete(finding)
        db.commit()

        print(f"Deleted {count} typosquat finding(s) across {len(affected_vendor_ids)} vendor(s).")

        for vendor_id in affected_vendor_ids:
            try:
                score = score_vendor(db, vendor_id)
                print(f"  vendor {vendor_id}: rescored -> {score.score}/100 ({score.grade})")
            except NoActiveScoringConfigError:
                print(f"  vendor {vendor_id}: no active scoring config, skipped rescore")
    finally:
        db.close()


if __name__ == "__main__":
    main()
