"""NsfwEngine - the triage orchestrator (Fast -> Deep -> Multimodal).

The engine implements a cost-aware cascade: the overwhelming majority of
requests are decided by the cheap Fast-Path model, borderline content escalates
to the Deep-Path, and only genuinely ambiguous cases reach the expensive
Multimodal (CLIP) model. Text signals (page copy, alt text, URLs) are fused at
the multimodal stage and can independently raise a REVIEW floor.

All public entry points return a :class:`ClassificationResult` regardless of
failures, so callers (gRPC / ICAP / REST) never have to guard against
exceptions; transport errors are reported via ``result.error``.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, replace
from typing import List, Optional

import numpy as np

from app.core.cache import PREPROCESS_VERSION, DecisionCache, cache_key, payload_hash
from app.core.calibration import CalibrationRegistry
from app.core.config import EngineConfig, get_config
from app.core.deadline import Deadline, build_deadline
from app.core.fusion import fuse_scores
from app.core.metrics import (
    init_tracing,
    record_classification,
    record_error,
    record_stage,
    traced,
    tracing_status,
)
from app.core.onnx_runtime import OnnxSessionManager
from app.core.policy import PolicyEngine
from app.core.resilience import DeadLetterQueue, IdempotencyStore
from app.core.resilience import DeadLetterQueue, IdempotencyStore
from app.core.security import SecurityContext
from adapters.registry import describe_all
from app.core.preprocessor import Preprocessor, PreprocessingError
from app.models.base import DecisionPath, MediaType, StageResult, Verdict
from app.models.deep_path import DeepPathEvaluator
from app.models.fast_path import FastPathEvaluator
from app.models.multimodal_path import MultimodalPathEvaluator
from app.models.premium_path import PremiumPathEvaluator
from app.models.text_path import TextPathEvaluator
from app.services.text_analyzer import TextAnalyzer, TextAnalysisResult

logger = logging.getLogger("nsfw_engine.core.engine")

#: Text score above which a REVIEW floor is applied even if the image looks safe.
TEXT_REVIEW_FLOOR = 0.85


@dataclass
class ClassificationResult:
    """Outcome of a classification request."""

    verdict: Verdict = Verdict.UNKNOWN
    decided_by: DecisionPath = DecisionPath.UNKNOWN
    score: float = 0.0
    total_latency_ms: float = 0.0
    media_type: MediaType = MediaType.UNKNOWN
    request_id: str = ""
    stages: List[StageResult] = field(default_factory=list)
    text: Optional[dict] = None
    error: str = ""
    #: Enforcement action applied by the policy engine (ALLOW/BLOCK/...).
    action: str = ""
    policy_id: str = ""
    #: True when the result was served from the content-addressed cache.
    from_cache: bool = False
    #: True when the request breached its latency budget (§ timeouts).
    timed_out: bool = False
    #: Deadline diagnostics when a breach occurred.
    deadline: Optional[dict] = None

    @property
    def is_nsfw(self) -> bool:
        return self.verdict is Verdict.NSFW

    @property
    def should_block(self) -> bool:
        # The policy engine is authoritative when it has run; otherwise fall
        # back to the verdict so pre-policy callers keep their old behavior.
        if self.action:
            return self.action in ("BLOCK", "QUARANTINE")
        return self.verdict in (Verdict.NSFW, Verdict.REVIEW)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "decided_by": self.decided_by.value,
            "score": round(float(self.score), 6),
            "total_latency_ms": round(float(self.total_latency_ms), 3),
            "media_type": self.media_type.value,
            "request_id": self.request_id,
            "action": self.action,
            "policy_id": self.policy_id,
            "from_cache": self.from_cache,
            "timed_out": self.timed_out,
            "stages": [s.as_dict() for s in self.stages],
            "text": self.text,
            "error": self.error,
        }


class NsfwEngine:
    """The triage orchestrator."""

    def __init__(
        self,
        config: Optional[EngineConfig] = None,
        session_manager: Optional[OnnxSessionManager] = None,
        preprocessor: Optional[Preprocessor] = None,
        text_analyzer: Optional[TextAnalyzer] = None,
    ) -> None:
        self.config = config or get_config()
        self._started_at = time.time()
        init_tracing(
            service_name=f"{self.config.engine.name}-{self.config.engine.version}",
            enabled=bool(self.config.observability.enable_tracing),
        )
        pp = self.config.preprocessing
        self.preprocessor = preprocessor or Preprocessor(
            mean=tuple(pp.mean),
            std=tuple(pp.std),
            max_image_bytes=pp.max_image_bytes,
            max_image_dim=pp.max_image_dim,
        )
        self.manager = session_manager or OnnxSessionManager(self.config.onnx)

        self.fast = FastPathEvaluator.from_config(self.manager, self.preprocessor, self.config)
        self.deep = DeepPathEvaluator.from_config(self.manager, self.preprocessor, self.config)
        self.multimodal = MultimodalPathEvaluator.from_config(
            self.manager, self.preprocessor, self.config
        )
        #: §10 Premium Path. Opt-in and off by default; see PremiumThresholds.
        self.premium = PremiumPathEvaluator.from_config(
            self.manager, self.preprocessor, self.config
        )
        self.text_analyzer = text_analyzer or TextAnalyzer(
            weight=self.config.thresholds.text.weight,
            keyword_score_cap=self.config.thresholds.text.keyword_score_cap,
        )
        self.text_path = TextPathEvaluator.from_config(
            self.manager, self.config, self.text_analyzer
        )
        self.policy = PolicyEngine(self.config.policy, self.config.firewall)
        self.security = SecurityContext(self.config.security)
        self.cache = DecisionCache(self.config.cache)
        # Idempotency (§33). Absent from the attribute when disabled, which the
        # REST layer reads as "no replay", so the common path costs nothing.
        self.idempotency = (
            IdempotencyStore(
                ttl_seconds=self.config.resilience.idempotency_ttl_seconds,
                max_entries=self.config.resilience.idempotency_max_entries,
            )
            if self.config.resilience.idempotency_enabled
            else None
        )
        # Dead-letter queue (§33). Unlike the breaker and the rate limiter this
        # is on by default: those are optional throttles, whereas failing to
        # capture an undecidable request means losing it outright.
        self.dead_letters = (
            DeadLetterQueue(
                max_entries=self.config.resilience.dead_letter_max_entries,
                ttl_seconds=self.config.resilience.dead_letter_ttl_seconds,
            )
            if self.config.resilience.dead_letter_enabled
            else None
        )
        # Score calibration (§26). Off by default and loaded from a file an
        # operator must fit explicitly with scripts/calibrate.py; when disabled
        # or absent this registry is inert and every score passes through.
        self.calibration = (
            CalibrationRegistry.load(self.config.calibration.path)
            if self.config.calibration.enabled
            else CalibrationRegistry()
        )
        #: True when at least one real model is loaded. Per-stage latency budgets
        #: describe model SLOs, so they are only enforced against real models.
        self._models_loaded = any(
            not evaluator.is_stub
            for evaluator in (self.fast, self.deep, self.multimodal)
        ) or bool(
            self.config.thresholds.premium.enabled
            and self.premium.adapter
            and self.premium.adapter.available
        )
        #: Bumped whenever the pipeline changes; part of every cache key.
        self.model_version = self.config.engine.version
        self._video_pipeline = None
        logger.info(
            "NsfwEngine initialized (mode=%s, runtime=%s, providers=%s)",
            self.config.engine.mode,
            "onnxruntime" if self.manager.runtime_available else "heuristic-fallback",
            self.manager.available_providers or ["(none)"],
        )

    # -- lazy video pipeline (avoids an import cycle) ------------------------
    @property
    def video_pipeline(self):
        if self._video_pipeline is None:
            from app.services.video_pipeline import VideoPipeline

            self._video_pipeline = VideoPipeline(self, self.config.video)
        return self._video_pipeline

    # -- decision helpers ----------------------------------------------------
    @staticmethod
    def _decide_stage(
        score: float, hard_nsfw: float, hard_sfw: float
    ) -> Optional[Verdict]:
        if score >= hard_nsfw:
            return Verdict.NSFW
        if score <= hard_sfw:
            return Verdict.SFW
        return None  # inconclusive -> escalate

    def _fast_only_verdict(self, score: float, overrides: Optional[dict]) -> Verdict:
        hard_nsfw = self._override(overrides, "fast_hard_nsfw", self.config.thresholds.fast_path.hard_nsfw)
        return Verdict.NSFW if score >= hard_nsfw else Verdict.SFW

    @staticmethod
    def _override(overrides: Optional[dict], key: str, default: float) -> float:
        if not overrides:
            return default
        value = overrides.get(key)
        return float(value) if value is not None else default

    # -- policy, metrics and cache -------------------------------------------
    def _finalise(
        self, result: ClassificationResult, started: float, deadline: Optional["Deadline"] = None
    ) -> ClassificationResult:
        """Apply policy, publish metrics and stamp latency on a result."""
        result.total_latency_ms = (time.perf_counter() - started) * 1000.0

        # A budget breach is a *failure*: record it so the policy engine applies
        # fail_action rather than silently enforcing a half-computed verdict.
        if deadline is not None and deadline.timed_out:
            result.timed_out = True
            result.deadline = deadline.as_dict()
            if not result.error:
                result.error = (
                    f"latency budget exceeded at {deadline.breached_at} "
                    f"(budget {deadline.budget_ms:.0f}ms)"
                )

        try:
            decision = self.policy.decide(result)
            result.action = decision.action.value
            result.policy_id = decision.policy_id
        except Exception:  # noqa: BLE001 - policy must never break a request
            logger.exception("policy evaluation failed")
            record_error("policy")
            result.action = self.config.policy.fail_action
            result.policy_id = self.config.policy.default_policy_id

        if result.error:
            record_error("classify")
        for stage in result.stages:
            record_stage(stage.path.value, stage.latency_ms / 1000.0)
        record_classification(
            result.verdict.value,
            result.action,
            result.total_latency_ms / 1000.0,
            result.score,
        )
        return result

    def _cache_key_for(
        self,
        raw: bytes,
        media_type: MediaType,
        text: Optional[str],
        url: str,
        domain: str,
        tenant_id: str = "",
    ) -> str:
        """Key decisions by payload and every input that can affect inference.

        SECURITY: the tenant is part of the key. It was not, which made the
        cache a single shared namespace across the whole estate: two tenants
        submitting identical bytes addressed the same entry, and because the
        stored result carries ``action`` and ``policy_id``, the second tenant
        was served the *first* tenant's enforcement decision on the legacy
        ``/classify`` path, which returns the engine result without re-running
        the policy engine. A per-tenant entry space costs one hash component
        and removes the leak entirely.
        """
        salt = (
            self.config.privacy.hash_salt
            if self.config.privacy.log_content_hashes
            else ""
        )
        context = json.dumps(
            {
                "media_type": media_type.value,
                "text": text,
                "url": url,
                "domain": domain,
                "tenant": tenant_id or "",
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return cache_key(
            payload_hash(len(context).to_bytes(8, "big") + context + raw, salt),
            self.model_version,
            PREPROCESS_VERSION,
        )

    @staticmethod
    def _result_from_cache(cached) -> ClassificationResult:
        """Rebuild a result from a cache entry.

        Cache entries are JSON-safe dicts so the same payload works for both the
        in-process and the Redis backend (§29). Corrupt or unknown enum values
        degrade to UNKNOWN rather than raising on the hot path.
        """
        if isinstance(cached, ClassificationResult):
            return replace(cached)

        def enum(factory, value, default):
            try:
                return factory(value)
            except (ValueError, KeyError):
                return default

        return ClassificationResult(
            verdict=enum(Verdict, cached.get("verdict"), Verdict.UNKNOWN),
            decided_by=enum(DecisionPath, cached.get("decided_by"), DecisionPath.UNKNOWN),
            media_type=enum(MediaType, cached.get("media_type"), MediaType.UNKNOWN),
            score=float(cached.get("score", 0.0) or 0.0),
            action=str(cached.get("action", "") or ""),
            policy_id=str(cached.get("policy_id", "") or ""),
            text=cached.get("text") if isinstance(cached.get("text"), dict) else None,
            error=str(cached.get("error", "") or ""),
        )

    # -- cascade -------------------------------------------------------------
    def _run_cascade(
        self,
        image: np.ndarray,
        text_analysis: Optional[TextAnalysisResult],
        overrides: Optional[dict],
        deadline: Optional["Deadline"] = None,
    ):
        thr = self.config.thresholds
        stages: List[StageResult] = []

        def run(evaluator, path_value: str):
            """Execute one stage, calibrate its score and record budget usage.

            Calibration happens here, on the raw model output and *before* the
            score is compared against a threshold or fused with another model -
            which is exactly the §26 pipeline order:
            ``RAW OUTPUT -> CALIBRATION -> NORMALIZED SCORE -> FUSION``.
            Fusing first would mix scores from different, incomparable scales.
            """
            if deadline is not None:
                deadline.check(path_value)
            stage = evaluator.evaluate(image)
            self._calibrate_stage(stage)
            stages.append(stage)
            if deadline is not None:
                deadline.check_stage(path_value, stage.latency_ms)
            return stage

        # Phase 1 - Fast-Path -------------------------------------------------
        fast = run(self.fast, DecisionPath.FAST.value)
        if self.config.engine.mode == "fast_only":
            if not fast.executed or fast.fallback:
                return Verdict.REVIEW, DecisionPath.FAST, fast.score, stages
            return self._fast_only_verdict(fast.score, overrides), DecisionPath.FAST, fast.score, stages

        verdict = (
            self._decide_stage(
                fast.score,
                self._override(overrides, "fast_hard_nsfw", thr.fast_path.hard_nsfw),
                thr.fast_path.hard_sfw,
            )
            if fast.executed and not fast.fallback
            else None
        )
        if verdict is not None or not thr.fast_path.escalate:
            return verdict or Verdict.REVIEW, DecisionPath.FAST, fast.score, stages

        # Phase 2 - Deep-Path -------------------------------------------------
        deep = run(self.deep, DecisionPath.DEEP.value)
        verdict = (
            self._decide_stage(
                deep.score,
                self._override(overrides, "deep_hard_nsfw", thr.deep_path.hard_nsfw),
                thr.deep_path.hard_sfw,
            )
            if deep.executed and not deep.fallback
            else None
        )
        if verdict is not None or not thr.deep_path.escalate:
            return verdict or Verdict.REVIEW, DecisionPath.DEEP, deep.score, stages

        # Phase 3 - Multimodal (final arbiter) --------------------------------
        if deadline is not None:
            deadline.check(DecisionPath.MULTIMODAL.value)
        text_score = text_analysis.score if text_analysis is not None else None
        mm = self.multimodal.evaluate_multimodal(image, text_score)
        # The multimodal stage fuses a visual and a text signal, so it is
        # calibrated on its own model id like any other stage (§26).
        self._calibrate_stage(mm)
        stages.append(mm)
        if deadline is not None:
            deadline.check_stage(DecisionPath.MULTIMODAL.value, mm.latency_ms)

        # Phase 4 - Premium Path (§10, optional final arbiter) ----------------
        # Only consulted when the cheaper stages were inconclusive, and only
        # when an operator enabled it: it is the most expensive model in the
        # cascade and ships unbenchmarked (§49). When it does not run, the
        # multimodal verdict stands unchanged.
        premium_stage = self._maybe_run_premium(image, overrides, deadline)
        if premium_stage is not None:
            stages.append(premium_stage)
            if premium_stage.executed:
                verdict = self._premium_verdict(premium_stage.score, overrides)
                return verdict, DecisionPath.PREMIUM, premium_stage.score, stages

        if not mm.executed or mm.fallback:
            if deep.executed and not deep.fallback:
                return Verdict.REVIEW, DecisionPath.DEEP, deep.score, stages
            return Verdict.REVIEW, DecisionPath.UNKNOWN, 0.5, stages

        return (
            self._multimodal_verdict(mm.score, overrides),
            DecisionPath.MULTIMODAL,
            mm.score,
            stages,
        )

    def _maybe_run_premium(
        self,
        image: np.ndarray,
        overrides: Optional[dict],
        deadline: Optional["Deadline"],
    ) -> Optional[StageResult]:
        """Run the §10 premium stage if enabled and mounted; else return None.

        ``None`` means "this stage did not apply", which keeps it out of the
        stage list entirely rather than recording a misleading zero score.
        """
        if not self.config.thresholds.premium.enabled:
            return None
        if deadline is not None:
            deadline.check(DecisionPath.PREMIUM.value)
        stage = self.premium.evaluate(image)
        self._calibrate_stage(stage)
        if deadline is not None:
            deadline.check_stage(DecisionPath.PREMIUM.value, stage.latency_ms)
        return stage

    def _calibrate_stage(self, stage: StageResult) -> StageResult:
        """Apply this stage's calibrator, in place, and report whether it did.

        Inert when calibration is disabled or no calibrator is registered for the
        model, so the hot path costs one dict lookup per stage. The stage's
        ``model`` field is the key: that is what §22 identifies in the registry,
        and it is what ``scripts/calibrate.py`` fits against.
        """
        if not self.config.calibration.enabled:
            return stage
        model_id = stage.model or stage.path.value
        if not self.calibration.is_calibrated(model_id):
            return stage
        calibrated = self.calibration.apply(model_id, stage.score)
        if abs(calibrated - stage.score) > 1e-9:
            logger.debug(
                "calibrated %s score %.4f -> %.4f", model_id, stage.score, calibrated
            )
        stage.score = calibrated
        return stage

    def _premium_verdict(self, score: float, overrides: Optional[dict]) -> Verdict:
        """Map a premium-stage score to a verdict (§10).

        Deliberately mirrors the multimodal shape: the premium model is an
        arbiter with its own REVIEW band, not another escalate link.
        """
        thr = self.config.thresholds.premium
        hard_nsfw = self._override(overrides, "premium_hard_nsfw", thr.hard_nsfw)
        if score >= hard_nsfw:
            return Verdict.NSFW
        if score >= thr.review:
            return Verdict.REVIEW
        return Verdict.SFW

    def _multimodal_verdict(self, score: float, overrides: Optional[dict]) -> Verdict:
        thr = self.config.thresholds.multimodal
        hard_nsfw = self._override(overrides, "multimodal_hard_nsfw", thr.hard_nsfw)
        if score >= hard_nsfw:
            return Verdict.NSFW
        if score >= thr.review:
            return Verdict.REVIEW
        return Verdict.SFW

    # -- public entry points -------------------------------------------------
    def classify_image(
        self,
        image: np.ndarray,
        text: Optional[str] = None,
        request_id: str = "",
        media_type: MediaType = MediaType.IMAGE,
        overrides: Optional[dict] = None,
        url: str = "",
        domain: str = "",
    ) -> ClassificationResult:
        """Classify an already-decoded ``HWC`` uint8 RGB image.

        ``url`` and ``domain`` are the §12 context. They are passed explicitly
        rather than stashed on the instance: the engine is shared by every
        worker thread, so per-request state on ``self`` would let one request's
        URL leak into another's classification.
        """
        started = time.perf_counter()
        result = ClassificationResult(media_type=media_type, request_id=request_id)
        deadline = build_deadline(self.config)
        deadline.enforce_stage_budgets = self._models_loaded
        try:
            text_analysis = (
                self.text_analyzer.analyze(text, url=url, domain=domain)
                if (text or url or domain)
                else None
            )
            text_stage = None
            if text_analysis is not None:
                result.text = text_analysis.as_dict()
                # DistilBERT path (falls back to the keyword signal when the
                # ONNX graph/color is absent).
                text_stage = self.text_path.evaluate(text)
                if text_stage.score > text_analysis.score:
                    text_analysis = replace(
                        text_analysis, score=float(text_stage.score)
                    )

            verdict, decided_by, score, stages = self._run_cascade(
                image, text_analysis, overrides, deadline
            )
            # Keep the text signal visible alongside the vision stages.
            if text_stage is not None:
                stages = [text_stage] + list(stages)

            # Text can only ever raise the floor, never downgrade an NSFW call.
            if (
                verdict is not Verdict.NSFW
                and text_analysis is not None
                and text_analysis.score >= TEXT_REVIEW_FLOOR
            ):
                verdict = Verdict.REVIEW
                decided_by = DecisionPath.TEXT

            result.verdict = verdict
            result.decided_by = decided_by
            result.score = float(score)
            result.stages = stages
        except Exception as exc:  # noqa: BLE001
            logger.exception("classify_image failed")
            result.error = f"{type(exc).__name__}: {exc}"
        return self._finalise(result, started, deadline)

    def classify_text(
        self,
        text: str,
        request_id: str = "",
        media_type: MediaType = MediaType.TEXT,
        overrides: Optional[dict] = None,
    ) -> ClassificationResult:
        """Classify a text / HTML payload using the text signal alone."""
        started = time.perf_counter()
        result = ClassificationResult(media_type=media_type, request_id=request_id)
        try:
            analysis = self.text_analyzer.analyze(text or "")
            result.text = analysis.as_dict()
            score = analysis.score
            thr = self.config.thresholds.multimodal
            if score >= self._override(overrides, "multimodal_hard_nsfw", thr.hard_nsfw):
                verdict = Verdict.NSFW
            elif score >= thr.review:
                verdict = Verdict.REVIEW
            else:
                verdict = Verdict.SFW
            result.verdict = verdict
            result.decided_by = DecisionPath.TEXT
            result.score = score
        except Exception as exc:  # noqa: BLE001
            logger.exception("classify_text failed")
            result.error = f"{type(exc).__name__}: {exc}"
        return self._finalise(result, started)

    @traced("nsfw.classify")
    def classify(
        self,
        payload: bytes | str,
        media_type: MediaType = MediaType.UNKNOWN,
        request_id: str = "",
        text: Optional[str] = None,
        overrides: Optional[dict] = None,
        url: str = "",
        domain: str = "",
        tenant_id: str = "",
    ) -> ClassificationResult:
        """Auto-dispatching entry point used by the transport adapters.

        Results are served from the content-addressed cache when enabled. The
        media type, the contextual text/URL/domain signals **and the tenant**
        are part of the cache key; requests carrying threshold overrides bypass
        the cache.

        ``url`` / ``domain`` are the §12 context; they only affect the text
        signal, never the cache key, because they are advisory evidence about
        the *page*, not about the payload bytes.

        SECURITY: a cache hit restores only the *classification* - verdict,
        score, stages. ``action`` and ``policy_id`` are deliberately blanked,
        because they are the product of a tenant-specific policy evaluation and
        must be re-derived for whoever is asking. Keeping them would let one
        tenant's enforcement decision ride along on another's cached result.
        """
        started = time.perf_counter()
        raw = payload.encode("utf-8") if isinstance(payload, str) else (payload or b"")
        use_cache = self.cache.enabled and not overrides
        key = (
            self._cache_key_for(raw, media_type, text, url, domain, tenant_id)
            if use_cache
            else ""
        )

        if use_cache:
            cached = self.cache.get(key)
            if cached is not None:
                result = self._result_from_cache(cached)
                result.request_id = request_id
                result.from_cache = True
                # The classification is cacheable; the *decision* is not.
                result.action = ""
                result.policy_id = ""
                result.total_latency_ms = (time.perf_counter() - started) * 1000.0
                record_classification(
                    result.verdict.value,
                    result.action,
                    result.total_latency_ms / 1000.0,
                    result.score,
                )
                return result

        try:
            if media_type in (MediaType.TEXT, MediaType.HTML):
                content = raw.decode("utf-8", errors="replace")
                result = self.classify_text(
                    content, request_id=request_id, media_type=media_type, overrides=overrides
                )
            else:
                image = self.preprocessor.decode(raw)
                resolved_type = MediaType.IMAGE if media_type is MediaType.UNKNOWN else media_type
                result = self.classify_image(
                    image,
                    text=text,
                    request_id=request_id,
                    media_type=resolved_type,
                    overrides=overrides,
                    url=url,
                    domain=domain,
                )
        except PreprocessingError as exc:
            result = self._finalise(
                ClassificationResult(
                    verdict=Verdict.UNKNOWN,
                    request_id=request_id,
                    media_type=media_type,
                    error=str(exc),
                ),
                started,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("classify failed")
            result = self._finalise(
                ClassificationResult(
                    verdict=Verdict.UNKNOWN,
                    request_id=request_id,
                    media_type=media_type,
                    error=f"{type(exc).__name__}: {exc}",
                ),
                started,
            )

        if use_cache and not result.error and not result.timed_out:
            # Store a JSON-safe payload so the in-process and Redis backends
            # share one format (§29) and only successful metadata is persisted.
            self.cache.put(key, result.as_dict())
        return result

    def classify_with_context(
        self,
        payload: bytes | str,
        media_type: MediaType = MediaType.UNKNOWN,
        request_id: str = "",
        text: Optional[str] = None,
        overrides: Optional[dict] = None,
        url: str = "",
        domain: str = "",
        title: str = "",
        tenant_id: str = "",
    ) -> ClassificationResult:
        """Classify with §12 HTML/URL context attached to the request.

        The context is threaded into the text analyzer as *structured* fields
        rather than being concatenated into the prompt text. Concatenating
        would make a page title indistinguishable from body copy, and the
        weights in :class:`TextAnalyzer` deliberately treat authored metadata as
        the stronger signal.

        ``title`` is prepended to any HTML body so a caller that only has the
        separate fields still gets the authored-copy signal.
        """
        body = text
        if title:
            body = f"<title>{title}</title>\n{text or ''}"
        return self.classify(
            payload,
            media_type,
            request_id,
            body,
            overrides,
            url=url,
            domain=domain,
            tenant_id=tenant_id,
        )

    # -- capabilities --------------------------------------------------------
    def health(self, *, redact_security: bool = True) -> dict:
        """Readiness / health report.

        ``redact_security`` defaults to True because the only caller that
        matters - ``GET /health``, which Kubernetes and every load balancer
        probe unauthenticated - must not learn whether the deployment is
        authenticated or how many credentials it has. Authenticated operators
        call ``health(redact_security=False)`` for the full picture.
        """
        """Report whether the runtime and at least one model stage are usable."""
        models_loaded = {
            "fast_path": not self.fast.is_stub,
            "deep_path": not self.deep.is_stub,
            "multimodal": not self.multimodal.is_stub,
            # The premium stage wraps an adapter, so readiness is the adapter's
            # availability gated by opt-in, rather than an is_stub flag on a
            # missing session. A mounted but disabled stage cannot serve traffic.
            "premium_vit": bool(
                self.config.thresholds.premium.enabled
                and self.premium.adapter
                and self.premium.adapter.available
            ),
        }
        return {
            "healthy": bool(
                self.manager.runtime_available and any(models_loaded.values())
            ),
            "version": self.config.engine.version,
            "mode": self.config.engine.mode,
            "active_providers": self.manager.active_providers(),
            "runtime_available": self.manager.runtime_available,
            "uptime_seconds": int(max(0.0, time.time() - self._started_at)),
            "loaded_models_count": sum(1 for loaded in models_loaded.values() if loaded),
            "models_loaded": models_loaded,
            "cache": self.cache.snapshot(),
            # §33. Exposed so a growing queue is visible before somebody asks
            # where the undelivered requests went. `None` when disabled.
            "dead_letters": (
                self.dead_letters.stats() if self.dead_letters is not None else None
            ),
            "policy": {
                "policy_id": self.config.policy.default_policy_id,
                "nsfw_action": self.config.policy.nsfw_action,
                "review_action": self.config.policy.review_action,
                "fail_action": self.config.policy.fail_action,
            },
            "firewall_mode": self.config.firewall.mode,
            "text_model_loaded": not self.text_path.is_stub,
            "security": {
                **self.security.status(redact=redact_security),
                "ip_filtering_enabled": bool(
                    getattr(self.config.security, "ip_allowlist", [])
                    or getattr(self.config.security, "ip_denylist", [])
                ),
                "api_key_expiration_enabled": bool(
                    getattr(self.config.security, "key_expires", {})
                ),
            },
            # Calibration (§26): which models are actually recalibrated, so an
            # operator can tell a calibrated deployment from an honest one.
            "calibration": {
                "enabled": bool(self.config.calibration.enabled),
                "path": self.config.calibration.path,
                "calibrated_models": self.calibration.calibrated_models,
            },
            # External adapter introspection (§41) - never includes weights.
            "adapters": describe_all(self.manager),
            "tracing": tracing_status(),
        }
