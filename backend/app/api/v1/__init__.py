from fastapi import APIRouter

from app.api.v1 import (
    assets,
    dashboard,
    findings,
    organization,
    scans,
    scores,
    uptime,
    vendors,
)

api_router = APIRouter()
api_router.include_router(vendors.router)
api_router.include_router(organization.router)
api_router.include_router(assets.router)
api_router.include_router(findings.router)
api_router.include_router(scans.router)
api_router.include_router(scores.router)
api_router.include_router(uptime.router)
api_router.include_router(dashboard.router)
