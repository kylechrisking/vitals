FROM python:3.13-alpine

LABEL org.opencontainers.image.title="brock" \
      org.opencontainers.image.description="A small uptime and alert agent for homelabs and small offices" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BROCK_PORT=8098
WORKDIR /app
COPY brock ./brock
# Runs unprivileged. For ping checks, allow unprivileged ICMP with the sysctl in compose.example.yaml.
RUN adduser -D -H -u 1000 brock && mkdir -p /data && chown brock /data
USER brock
EXPOSE 8098
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${BROCK_PORT}/healthz || exit 1
CMD ["python", "-m", "brock"]
