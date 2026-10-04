# Third-Party Notices

Required by `pront.md` §4 (License & Provenance). This file covers **runtime and
build-time software dependencies**. Model weights and datasets are covered
separately in [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md).

> ⚠️ Licenses are recorded as believed correct at the time of writing.
> **LEGAL_REVIEW_REQUIRED** before commercial redistribution — in particular the
> optional media stack, any model artifacts added under `models_onnx/`, and
> Grafana (AGPL-3.0).

## Runtime dependencies (actually installed by `requirements.txt` / Dockerfile)

| Component | Project | Version | License | Usage |
|-----------|---------|---------|---------|-------|
| `fastapi` | encode/fastapi | 0.115.6 | MIT | REST API framework |
| `uvicorn[standard]` | encode/uvicorn | 0.34.0 | BSD-3-Clause | ASGI server |
| `pydantic` | pydantic/pydantic | 2.10.4 | MIT | Typed config + schemas |
| `pydantic-settings` | pydantic/pydantic-settings | 2.7.0 | MIT | Settings helpers |
| `PyYAML` | yaml/pyyaml | 6.0.2 | MIT | Config parsing |
| `numpy` | numpy/numpy | 2.2.1 | BSD-3-Clause | Tensor / preprocessing math |
| `onnxruntime` | microsoft/onnxruntime | 1.20.1 | MIT | Inference runtime (CPU build) |
| `onnx` | onnx/onnx | 1.17.0 | Apache-2.0 | Graph format, quantization |
| `grpcio` | grpc/grpc | 1.69.0 | Apache-2.0 | gRPC transport |
| `protobuf` | protocolbuffers/protobuf | 5.29.2 | BSD-3-Clause | Wire contract |
| `prometheus-client` | prometheus/client_python | 0.21.1 | Apache-2.0 | Metrics exposition |

> Note: `onnxruntime` is pinned with a marker so the CPU wheel is skipped on
> Linux by default; the Dockerfile installs it explicitly.

## Optional dependencies — guarded by import checks, engine degrades gracefully

| Component | Project | License | Used for | Fallback when absent |
|-----------|---------|---------|----------|----------------------|
| `opencv-python-headless` | opencv/opencv | **Apache-2.0** | Fast image decode, video validation | Pillow → built-in PPM decoder |
| `pillow` | python-pillow/Pillow | **MIT-CMU** | Image decode, decompression-bomb checks | OpenCV → built-in PPM decoder |
| `python-magic` | ahupp/python-magic | MIT | Deep MIME sniffing | Built-in magic-number table |
| `PyAV` (`av`) | PyAV-Org/PyAV | BSD-3-Clause | Video container decoding | Caller supplies decoded frames |
| `transformers` | huggingface/transformers | Apache-2.0 | DistilBERT tokenizer | Keyword/URL text signal |
| `torch` / `torchvision` | pytorch/pytorch | BSD-3-Clause | ONNX export (build-time) | n/a |
| `onnxconverter-common` | microsoft/onnxconverter-common | Apache-2.0 | FP16 conversion (build-time) | n/a |

> **Corrections to the previous revision of this file:** OpenCV is **Apache-2.0**
> (not BSD-3-Clause) and Pillow is **MIT-CMU** (not HPND). Both are Python
> bindings of larger upstream projects whose own licenses must also be checked if
> you redistribute binaries.

## Development-only dependencies

| Component | Project | License | Purpose |
|-----------|---------|---------|---------|
| `pytest` | pytest-dev/pytest | MIT | Optional test runner (unittest works without it) |
| `httpx` | encode/httpx | BSD-3-Clause | FastAPI `TestClient` transport |

## Infrastructure images (deployed, not redistributed in the engine image)

| Component | License |
|-----------|---------|
| `prom/prometheus` | Apache-2.0 |
| `grafana/grafana` | **AGPL-3.0** ⚠️ |
| `python:3.12-slim` | Python Software Foundation License |

> ⚠️ **LEGAL_REVIEW_REQUIRED — Grafana.** Grafana is **AGPL-3.0**. It is run as a
> separate container and is *not* linked into or distributed with the engine,
> which is the normal way to discharge AGPL obligations. Obtain advice before
> re-licensing, embedding or redistributing it.

> Note: `opentelemetry-sdk` (Apache-2.0) and `redis-py` (MIT) appeared in an
> earlier revision of this file but are **not** dependencies of this repository.
> They are legitimate options for the future tracing (§31) and cache backends
> (§29) and are only listed here should they be adopted.

## Apache-2.0 attribution

`onnx`, the `onnxruntime` binaries, `grpcio` (partially Apache-2.0) and
`prometheus-client` are Apache-2.0. Retain this file plus the upstream
`LICENSE`/`NOTICE` files in any image or binary you distribute.

## Project code

The engine's own source is released under **Apache-2.0**, matching the dependency
stack and the licence of the only clean-licence model candidate
(`premium_vit`, code *and* weights — see [`MODEL_PROVENANCE.md`](MODEL_PROVENANCE.md)).

> ⚠️ This file previously stated *"internally unlicensed — all rights reserved"*.
> That was wrong and contradicted `README.md`, which declares Apache-2.0. A
> licence file that contradicts the README is the kind of ambiguity that turns
> into a legal argument later, so the declaration now lives in exactly one place:
> `LICENSE` at the repository root. If your organisation has a different policy,
> change it there — not here.