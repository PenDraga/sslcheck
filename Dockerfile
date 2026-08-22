# TLS- & Zertifikats-Check (abgespecktes SSL-Labs) – Web + API
#
# Build:  docker build -t tlscheck .
# Run:    docker run -d --name tlscheck --restart unless-stopped \
#              -p 8765:8765 tlscheck
#
# Im Container: Web-Frontend auf http://<host>:8765
#               API:       http://<host>:8765/api/check?host=example.com&ocsp=1
#               CLI:       docker run --rm tlscheck tlscheck.py example.com

FROM python:3.11-slim

# openssl CLI + System-CA-Bundle (Beide werden von tlscheck.py gebraucht)
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY tlscheck.py tlscheck_web.py /app/

# Ohne Root: Port 8765 > 1024, CA-Bundle ist world-readable
RUN useradd -m -u 10001 tlscheck \
    && chown -R tlscheck:tlscheck /app
USER tlscheck

ENV PYTHONUNBUFFERED=1
EXPOSE 8765

# Healthcheck ohne curl (slim-Image): Python-urllib-Probe gegen /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=4).status==200 else 1)"

# Standard: Web-Server. Für reine CLI-Prüfung:
#   docker run --rm tlscheck python3 /app/tlscheck.py example.com
CMD ["python3", "/app/tlscheck_web.py", "--bind", "0.0.0.0", "--port", "8765"]
