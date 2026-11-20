FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
WORKDIR /opt/aegis
COPY requirements-claude.txt .
ARG WITH_CLAUDE=0
RUN if [ "$WITH_CLAUDE" = 1 ]; then pip install --no-cache-dir -r requirements-claude.txt; fi
COPY aegis aegis
COPY scenarios scenarios
COPY LICENSE .
RUN mkdir -p /data && chown 65532:65532 /data && mkdir -p /tmp/aegis-home && chown 65532:65532 /tmp/aegis-home
ENV AEGIS_DB=/data/aegis.sqlite AEGIS_HOST=0.0.0.0 HOME=/tmp/aegis-home PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import os,urllib.request; urllib.request.urlopen('http://localhost:'+os.getenv('AEGIS_PORT','8765')+'/api/v1/health', timeout=2)"
CMD ["python","-m","aegis","serve"]
