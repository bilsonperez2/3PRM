from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import api_router
from app.core.logging import configure_logging

configure_logging()

app = FastAPI(
    title="TPRM Platform API",
    description="Internal third-party cyber risk management and external attack surface monitoring platform.",
    version="0.1.0",
)

# Frontend dev server origin only — this API is not exposed publicly (see
# docker-compose.yml, all ports bound to 127.0.0.1).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}
