FROM python:3.11-slim

WORKDIR /srv/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Subfinder (passive subdomain enumeration) — pinned static release binary.
# It's an optional discovery source (app/providers/subfinder_provider.py logs
# a warning and skips itself if this binary is missing), so a failed/blocked
# download here shouldn't be treated as a fatal build error in restricted
# network environments; bump SUBFINDER_VERSION periodically against
# https://github.com/projectdiscovery/subfinder/releases.
ARG SUBFINDER_VERSION=2.6.6
RUN (curl -sSL -o /tmp/subfinder.zip \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
     && unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder \
     && chmod +x /usr/local/bin/subfinder \
     && rm /tmp/subfinder.zip) \
    || echo "WARNING: could not download subfinder ${SUBFINDER_VERSION} — continuing without it; subfinder_provider.py skips itself gracefully at runtime when the binary is missing"

COPY pyproject.toml ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

RUN pip install --no-cache-dir -e ".[dev]"

# No default CMD: docker-compose sets the command per service (api server vs worker),
# since both share this image.
