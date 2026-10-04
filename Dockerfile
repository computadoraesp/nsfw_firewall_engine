# =============================================================================
# NSFW Firewall Engine - multi-stage image
# -----------------------------------------------------------------------------
# Build:  docker build -t nsfw-firewall-engine .
# Run:    docker run --rm -p 50051:50051 -p 1344:1344 -p 8080:8080 \
#                 -v $PWD/models_onnx:/app/models_onnx nsfw-firewall-engine
# =============================================================================

# --- Stage 1: build ONNX runtime + generate gRPC stubs ----------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip \
    && pip install "numpy==2.2.1" "grpcio-tools==1.69.0" "protobuf==5.29.2"

COPY proto/ ./proto/
# Generate the Python protobuf/gRPC bindings into the proto package.
RUN python -m grpc_tools.protoc -I proto \
        --python_out=proto --grpc_python_out=proto proto/nsfw_engine.proto

# --- Stage 2: runtime -------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NSFW_ENGINE_CONFIG=/app/config/engine_config.yaml \
    NSFW_LOGGING_CONFIG=/app/config/logging_config.yaml

WORKDIR /app

# Only the CPU onnxruntime is installed in the slim image. For GPU deployments
# swap in onnxruntime-gpu (and use an nvidia/cuda base image).
RUN pip install --upgrade pip \
    && pip install "fastapi==0.115.6" "uvicorn[standard]==0.34.0" \
        "pydantic==2.10.4" "pydantic-settings==2.7.0" "PyYAML==6.0.2" \
        "numpy==2.2.1" "onnxruntime==1.20.1" "onnx==1.17.0" \
        "grpcio==1.69.0" "protobuf==5.29.2" \
        "prometheus-client==0.21.1"

COPY --from=builder /app/proto ./proto
COPY app/ ./app/
COPY config/ ./config/
COPY scripts/ ./scripts/
# The content inspector is imported by app.services.content_inspector.
COPY content/ ./content/

# Model artifacts are mounted at runtime (see README); keep an empty dir.
RUN mkdir -p /app/models_onnx /app/logs

# Non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# gRPC, ICAP and REST respectively.
EXPOSE 50051 1344 8080

# Default: start the REST API. Override the command to run the gRPC or ICAP
# servers instead, e.g. `docker run ... python -m app.api.grpc.server`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

CMD ["python", "-m", "app.api.rest.router"]
