FROM cgr.dev/chainguard/python:latest@sha256:e5322b9d32064a645225b8b2419f11127bcf2d8b9927f9514f0acee1e1d25751

WORKDIR /app
COPY --chown=65532:65532 adapter.py server.py /app/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["python", "/app/server.py"]
