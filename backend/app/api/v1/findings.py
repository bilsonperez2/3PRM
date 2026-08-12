import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.logging import get_logger
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.schemas.finding import (
    FindingAcceptRiskRequest,
    FindingFalsePositiveRequest,
    FindingRead,
    FindingReopenRequest,
    FindingSuppressRequest,
)
from app.services.risk_engine.config import NoActiveScoringConfigError
from app.services.risk_engine.scorer import score_vendor

router = APIRouter(tags=["findings"])
logger = get_logger(__name__)


def _get_finding_or_404(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


def _rescore(db: Session, vendor_id: uuid.UUID) -> None:
    """Triage actions (false-positive/accept-risk/suppress/reopen) change what
    counts toward a vendor's score immediately — recompute right away rather
    than waiting for the next scan, so the Score History tab reflects the
    triage decision the moment it's made.
    """
    try:
        score_vendor(db, vendor_id)
    except NoActiveScoringConfigError:
        logger.warning("no active risk_scoring_config — skipping rescore after finding triage")


@router.get("/vendors/{vendor_id}/findings", response_model=list[FindingRead])
def list_findings(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Finding]:
    get_vendor_or_404(db, vendor_id)
    return list(
        db.scalars(
            select(Finding).where(Finding.vendor_id == vendor_id).order_by(Finding.detected_at.desc())
        )
    )


@router.post("/findings/{finding_id}/false-positive", response_model=FindingRead)
def mark_false_positive(
    finding_id: uuid.UUID,
    payload: FindingFalsePositiveRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Finding:
    finding = _get_finding_or_404(db, finding_id)
    finding.status = FindingStatus.FALSE_POSITIVE
    finding.risk_points = 0
    if payload.analyst_notes:
        finding.analyst_notes = payload.analyst_notes
    db.commit()
    _rescore(db, finding.vendor_id)
    db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/accept-risk", response_model=FindingRead)
def accept_risk(
    finding_id: uuid.UUID,
    payload: FindingAcceptRiskRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Finding:
    finding = _get_finding_or_404(db, finding_id)
    finding.status = FindingStatus.ACCEPTED
    if payload.analyst_notes:
        finding.analyst_notes = payload.analyst_notes
    db.commit()
    _rescore(db, finding.vendor_id)
    db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/suppress", response_model=FindingRead)
def suppress_finding(
    finding_id: uuid.UUID,
    payload: FindingSuppressRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Finding:
    finding = _get_finding_or_404(db, finding_id)
    finding.suppressed_until = payload.suppressed_until
    if payload.analyst_notes:
        finding.analyst_notes = payload.analyst_notes
    db.commit()
    _rescore(db, finding.vendor_id)
    db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/reopen", response_model=FindingRead)
def reopen_finding(
    finding_id: uuid.UUID,
    payload: FindingReopenRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Finding:
    finding = _get_finding_or_404(db, finding_id)
    finding.status = FindingStatus.OPEN
    finding.suppressed_until = None
    if payload.analyst_notes:
        finding.analyst_notes = payload.analyst_notes
    db.commit()
    _rescore(db, finding.vendor_id)
    db.refresh(finding)
    return finding
