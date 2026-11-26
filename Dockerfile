FROM python:3.11-slim

# Optional Playwright Chromium browser installation.
# Defaults to false for fast, lightweight builds; pass:
#   --build-arg INSTALL_PLAYWRIGHT_BROWSERS=true
# to bundle headless Chromium for js-discover / xss-dom.
ARG INSTALL_PLAYWRIGHT_BROWSERS=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Minimal OS certs for HTTPS API/target requests; cleaned to keep image small.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN if [ "$INSTALL_PLAYWRIGHT_BROWSERS" = "true" ]; then \
        mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" && \
        python -m playwright install --with-deps chromium && \
        chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}"; \
    fi

# Create dedicated non-root runtime user and group (UID/GID 1000 for bind-mount compatibility).
RUN groupadd --gid 1000 moros && \
    useradd --uid 1000 --gid 1000 --create-home --home-dir /home/moros moros

COPY --chown=moros:moros . .

RUN mkdir -p /app/targets /app/learning_engine/memory && \
    chown -R moros:moros /app/targets /app/learning_engine/memory

USER moros

EXPOSE 8080

CMD ["python", "run.py", "--help"]
