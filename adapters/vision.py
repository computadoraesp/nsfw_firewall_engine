"""Concrete adapters for the third-party detectors evaluated in §2/§41.

Each adapter owns exactly one upstream project. None of them ship weights; all
degrade to ``available == False`` until an artifact is mounted, at which point
they transparently reuse the engine's ONNX session manager (provider negotiation
included) and the shared preprocessor.

License status mirrors ``docs/MODEL_PROVENANCE.md``:
* NSFWJS - MIT (code); weights ambiguous, see the provenance doc.
* HuggingFace ViT classifiers - **Apache-2.0 code and weights: cleared**.
* OpenNSFW2 - Apache-2.0 code; **weights LEGAL_REVIEW_REQUIRED**.
* Nudita - **AGPL-3.0**: must be executed out-of-process, never vendored.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import numpy as np

from adapters.base import AdapterCategory, AdapterResult, BaseAdapter, ModelStatus
from adapters.labels import LabelSidecarError
from adapters.labels import load as load_labels

logger = logging.getLogger("nsfw_engine.adapters.vision")


class _OnnxVisionAdapter(BaseAdapter):
    """Shared implementation for adapters backed by an ONNX image classifier."""

    accepts = "image"
    default_model_path = ""

    def __init__(self, model_path: Optional[str] = None, session_manager: Any = None) -> None:
        super().__init__(model_path or self.default_model_path, session_manager)
        self._session = None

    @property
    def available(self) -> bool:
        if self._session is None and self.model_path and self.session_manager is not None:
            try:
                session = self.session_manager.load(self.name, self.model_path)
                if not session.is_stub:
                    self._session = session
                    self._loaded = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("adapter %s could not load %s: %s", self.name, self.model_path, exc)
        return self._session is not None

    def predict(self, payload: Any) -> Optional[AdapterResult]:
        """Score an encoded image (``bytes``) or a decoded ``HWC`` array."""
        if not self._guard() or not self.available:
            return None
        started = time.perf_counter()
        try:
            image = self._to_image(payload)
            if image is None:
                return None
            logits = self._session.run(self._to_tensor(image))
        except Exception as exc:  # noqa: BLE001 - never break the cascade
            logger.warning("adapter %s inference failed: %s", self.name, exc)
            return None
        score = self.normalize(np.asarray(logits).reshape(-1))
        return AdapterResult(
            score=score,
            adapter=self.name,
            category=self.categorise(score),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    # -- input handling ------------------------------------------------------
    def _to_image(self, payload: Any):
        from app.core.preprocessor import Preprocessor

        if isinstance(payload, np.ndarray):
            return payload
        if isinstance(payload, (bytes, bytearray)):
            return Preprocessor().decode(bytes(payload))
        return None

    def _to_tensor(self, image: np.ndarray) -> np.ndarray:
        from app.core.preprocessor import Preprocessor

        return Preprocessor().array_to_tensor(image, (224, 224))


class NSFWJSAdapter(_OnnxVisionAdapter):
    """NSFWJS (``@nsfwjs/nsfwjs``, MIT) - 6-class head, fast.

    Class order is ``[porn, hentai, sexy, neutral, drawing, other]``; the NSFW
    probability is the summed score of the explicit classes.
    """

    name = "nsfwjs"
    license = "MIT"
    # §22. The weights are trained on a third-party corpus whose terms are not
    #: clearly permissive for redistribution, so this stays a candidate until
    #: provenance is settled, and it has been benchmarked (§49).
    status = ModelStatus.CANDIDATE
    default_model_path = "models_onnx/nsfwjs_mobilenetv2.onnx"
    #: (start, end) slice of the class vector treated as explicit.
    explicit_slice = (0, 3)

    def normalize(self, logits: Any) -> float:
        values = np.asarray(logits, dtype=np.float32).reshape(-1)
        if values.size <= 2:
            return super().normalize(values)
        probs = 1.0 / (1.0 + np.exp(-np.clip(values, -60.0, 60.0)))
        start, end = self.explicit_slice
        return float(np.clip(probs[start:end].sum(), 0.0, 1.0))


class OpenNSFW2Adapter(_OnnxVisionAdapter):
    """OpenNSFW2 (Apache-2.0 code) - single sigmoid output, ~50 ms.

    ⚠️ Weights are **LEGAL_REVIEW_REQUIRED**; see ``docs/MODEL_PROVENANCE.md``.
    """

    name = "opennsfw2"
    license = "Apache-2.0 (weights: LEGAL_REVIEW_REQUIRED)"
    # §22. Upstream Yahoo/tensorflow weight terms are not clearly permissive for
    #: commercial redistribution, so this is *blocked* rather than merely
    #: deprecated: blocked models have no path back, which is what stops someone
    #: "just enabling" it to route around the license review (§4).
    status = ModelStatus.BLOCKED
    default_model_path = "models_onnx/opennsfw2_resnet50.onnx"


class HuggingFaceViTAdapter(_OnnxVisionAdapter):
    """Apache-2.0 ViT image classifiers (§10 Premium Path) - **license cleared**.

    This adapter exists because the two historically-cited NSFW sources are
    license-ambiguous, which had stalled the whole engine. They are not the only
    option: several Hugging Face ViT classifiers state an explicit **Apache-2.0**
    license covering *both* code and weights, which is unambiguous for
    commercial use and redistribution.

    Verified candidates (see ``docs/MODEL_PROVENANCE.md``):

    * ``AdamCodd/vit-base-nsfw-detector`` - Apache-2.0, ships ONNX directly.
    * ``Falconsai/nsfw_image_detection`` - Apache-2.0, 224px, 85M+ downloads.
    * ``Marqo/nsfw-image-detection-384`` - Apache-2.0, 384px input.

    The class head differs between them (``normal``/``safe`` vs ``nsfw``), so
    the label mapping is explicit per instance rather than guessed. Getting that
    mapping wrong would invert the detector, so :meth:`categorize` refuses to
    score when the expected labels are absent instead of silently guessing -
    a model that cannot be mapped must not be trusted to block traffic.
    """

    name = "hf_vit_nsfw"
    license = "Apache-2.0"
    # §22. Explicit Apache-2.0 for both code and weights, so this is the one
    #: candidate that can be promoted to `validated` once benchmarked, with no
    #: license review outstanding. It stays `candidate` rather than `production`
    #: purely because it has not been measured yet - §49 forbids the promotion
    #: without numbers.
    status = ModelStatus.CANDIDATE
    #: Mount the exported graph here (Helm mounts ``models.mountPath`` here).
    default_model_path = "models_onnx/vit_nsfw.onnx"
    #: ViT-base uses a 224px input; override for the 384px Marqo variant.
    default_input_size = (224, 224)

    def __init__(
        self,
        model_path: Optional[str] = None,
        session_manager: Any = None,
        input_size: Optional[tuple] = None,
        positive_labels: Optional[tuple] = None,
    ) -> None:
        super().__init__(model_path or self.default_model_path, session_manager)
        # Explicit *class indices*, resolved from the label sidecar. This is the
        #: property that was previously read off an attribute that existed
        #: nowhere in the codebase, so every call silently fell through to
        #: max() - which cannot tell 'normal' from 'nsfw' and can invert the
        #: detector. When no sidecar is mounted the adapter stays undecided
        #: rather than guessing (§49).
        self.sidecar = None
        try:
            self.sidecar = load_labels(self.model_path)
        except LabelSidecarError as exc:
            # A present-but-broken sidecar must not be ignored: it means the
            # class order is unknown, so no score may be produced.
            logger.error("adapter %s: unusable label sidecar: %s", self.name, exc)
            self.sidecar = None
            self._sidecar_error = str(exc)

        if input_size is None and self.sidecar is not None:
            # The sidecar records the resolution the checkpoint was trained at.
            # Defaulting to 224px regardless is what silently degraded the
            # 384px Marqo variant.
            input_size = self.sidecar.input_size
        self.input_size = tuple(input_size or self.default_input_size)

        # Label names that count as "explicit". Configured per checkpoint
        #: because the class order is a property of the export, not the adapter.
        self.positive_labels = tuple(
            positive_labels or ("nsfw", "porn", "pornographic", "hentai", "sexy")
        )

    def _to_tensor(self, image: np.ndarray) -> np.ndarray:
        from app.core.preprocessor import Preprocessor

        mean = self.sidecar.mean if self.sidecar is not None else (0.485, 0.456, 0.406)
        std = self.sidecar.std if self.sidecar is not None else (0.229, 0.224, 0.225)
        return Preprocessor(mean=mean, std=std).array_to_tensor(image, self.input_size)

    def sidecar_for_width(self, width: int):
        """Return the sidecar only if it describes a graph of *width* classes.

        A sidecar whose class count disagrees with the graph's output width is
        describing a different artifact, so its indices point at the wrong
        classes and no score may be produced.
        """
        if self.sidecar is None:
            return None
        if len(self.sidecar.labels) != int(width):
            logger.error(
                "adapter %s: sidecar declares %d classes but the graph emitted %d; "
                "the sidecar does not match this artifact",
                self.name, len(self.sidecar.labels), width,
            )
            return None
        return self.sidecar

    def predict(self, payload: Any) -> Optional[AdapterResult]:
        """Run the ViT head and sum the explicit-class probabilities.

        Falls back to the shared single-score behavior only when the export
        exposes one output; a multi-class head with unrecognized labels returns
        ``None`` (no score) so the cascade escalates rather than acting on a
        possibly-inverted reading. The fetch exporter preserves logits, so the
        multi-class head is softmaxed here before the sidecar indices are used.
        """
        if not self._guard() or not self.available:
            return None
        started = time.perf_counter()
        try:
            image = self._to_image(payload)
            if image is None:
                return None
            outputs = np.asarray(self._session.run(self._to_tensor(image))).reshape(-1)
        except Exception as exc:  # noqa: BLE001 - never break the cascade
            logger.warning("adapter %s inference failed: %s", self.name, exc)
            return None

        sidecar = self.sidecar_for_width(outputs.shape[0])
        if sidecar is None:
            # Either there is no sidecar, or it does not describe this graph.
            # In both cases the class order is unknown, so the outputs cannot be
            # mapped to "NSFW" without guessing. Returning no score lets the
            # cascade escalate - the only safe answer when a 2-class head might
            # be inverted.
            logger.warning(
                "adapter %s: no usable label sidecar for %s; refusing to score "
                "rather than guessing the class order (mount a .labels.json next "
                "to the artifact, see scripts/fetch_pretrained.py)",
                self.name,
                self.model_path,
            )
            return None

        explicit = [i for i in sidecar.positive_indices if i < outputs.shape[0]]
        if not explicit:
            logger.warning(
                "adapter %s: no explicit class among the sidecar labels %s; "
                "refusing to score",
                self.name, list(sidecar.labels),
            )
            return None
        if not np.all(np.isfinite(outputs)):
            logger.error("adapter %s: model emitted non-finite logits", self.name)
            return None
        shifted = outputs.astype(np.float64) - float(np.max(outputs))
        exponentials = np.exp(shifted)
        probabilities = exponentials / exponentials.sum()
        score = float(np.clip(sum(float(probabilities[i]) for i in explicit), 0.0, 1.0))

        return AdapterResult(
            score=score,
            adapter=self.name,
            category=self.categorise(score),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

class NuditaAdapter(_OnnxVisionAdapter):
    """Nudita - **AGPL-3.0**.

    The license makes this code copy-incompatible with a proprietary engine, so
    this adapter deliberately does **not** load Nudita in-process. It is a
    documented boundary marker: deploy Nudita as its own service and reach it
    over gRPC/HTTP if you need it, keeping the AGPL obligations separate.
    """

    name = "nudita"
    license = "AGPL-3.0 (out-of-process only)"
    # §22. AGPL-3.0 is copyleft: loading it in-process would impose its terms on
    #: this engine. `blocked` is the accurate status - it is not "not yet
    #: evaluated", it must never run here.
    status = ModelStatus.BLOCKED
    default_model_path = ""

    @property
    def available(self) -> bool:
        return False

    def predict(self, payload: Any) -> Optional[AdapterResult]:  # noqa: ARG002
        logger.debug("nudita adapter is intentionally inert (AGPL-3.0 isolation)")
        return None


class CLIPZeroShotAdapter(BaseAdapter):
    """CLIP zero-shot classifier (MIT) for the multimodal path.

    Compares an embedding against positive/negative prompt sets and turns the
    softmax into an NSFW probability.
    """

    name = "clip_zeroshot"
    license = "MIT"
    # §22. MIT code and MIT weights, but still unbenchmarked on this corpus.
    status = ModelStatus.CANDIDATE
    accepts = "image+text"
    default_model_path = "models_onnx/clip_zeroshot.onnx"

    positive_prompts = ("a nude photograph", "explicit sexual content", "pornographic image")
    negative_prompts = ("a safe photograph", "a landscape", "a document screenshot")

    def __init__(self, model_path: Optional[str] = None, session_manager: Any = None) -> None:
        super().__init__(model_path or self.default_model_path, session_manager)
        self._session = None

    @property
    def available(self) -> bool:
        if self._session is None and self.model_path and self.session_manager is not None:
            try:
                session = self.session_manager.load(self.name, self.model_path)
                if not session.is_stub:
                    self._session = session
                    self._loaded = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("adapter %s unavailable: %s", self.name, exc)
        return self._session is not None

    def predict(self, payload: Any) -> Optional[AdapterResult]:
        if not self._guard() or not self.available:
            return None
        started = time.perf_counter()
        try:
            # A production deployment supplies prompt embeddings from the graph;
            # this keeps the contract uniform even when it cannot run yet.
            tensor = payload if isinstance(payload, np.ndarray) else None
            if tensor is None:
                return None
            score = self.normalize(np.asarray(self._session.run(tensor)).reshape(-1))
        except Exception as exc:  # noqa: BLE001
            logger.warning("adapter %s inference failed: %s", self.name, exc)
            return None
        return AdapterResult(
            score=score,
            adapter=self.name,
            category=AdapterCategory.NEUTRAL if score < 0.5 else AdapterCategory.PORN,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )


__all__ = [
    "CLIPZeroShotAdapter",
    "HuggingFaceViTAdapter",
    "NSFWJSAdapter",
    "NuditaAdapter",
    "OpenNSFW2Adapter",
]