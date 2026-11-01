"""Text / HTML signal extraction for the NSFW Firewall Engine.

The analyzer strips markup, tokenizes visible copy and scans it for explicit
keywords and suspicious link targets. The resulting score is fused into the
multimodal stage and is used on its own for pure text/HTML payloads.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Iterable, List, Optional, Sequence

logger = logging.getLogger("nsfw_engine.services.text_analyzer")

# Curated baseline lexicon. Deployments are expected to extend this with a
# locale-specific list (passed via ``TextAnalyzer(keywords=...)``).
_DEFAULT_KEYWORDS: tuple[str, ...] = (
    "porn",
    "porno",
    "xxx",
    "nsfw",
    "explicit",
    "hardcore",
    "fetish",
    "bdsm",
    "nude",
    "nudes",
    "naked",
    "erotic",
    "escort",
    "camgirl",
    "onlyfans",
    "hentai",
    "milf",
    "orgy",
    "sexcam",
    "sexting",
)

#: Matches a ``<script>``/``<style>`` block **and its body**.
#:
#: SECURITY: the previous pattern was ``<(script|style)[^>]*>.*?</\\1>`` with
#: ``DOTALL``. With no closing tag present, the lazy ``.*?`` is retried at every
#: offset, once for every opening tag, so the cost is quadratic in the document
#: size. Measured before the rewrite: 2000 unclosed tags 0.16 s, 4000 tags
#: 0.62 s, 8000 tags 2.46 s - four times the work for twice the input at every
#: step.
#:
#: This is the standard "unrolled loop" formulation: ``[^<]*`` cannot match the
#: ``<`` that begins a nested tag, so the alternation cannot overlap itself and
#: every character is consumed exactly once. Linear, with no nested quantifier
#: over the same character class. The body ends at ``</script`` or ``</style``.
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)\b[^>]*>[^<]*(?:<(?!/\1\b)[^<]*)*",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]+")

#: Hard cap on the text any single analysis will scan.
#:
#: ``html_context`` bounds its own parse, but two entry points did not:
#: :meth:`TextAnalyzer.strip_html` and the ``_URL_RE.findall`` call, both of
#: which ran over the whole caller-supplied document. Combined with
#: ``_SCRIPT_STYLE_RE`` - ``.*?`` with ``DOTALL`` and no closing tag means the
#: lazy quantizer is retried at every offset once per opening tag - the cost
#: is quadratic. Measured before this cap: 2000 unclosed ``<script>`` tags
#: 0.16 s, 4000 tags 0.62 s, 8000 tags 2.46 s. Four times the work for twice
#: the input, at every step, which extrapolates to many minutes of CPU held by
#: a single worker for a 1 MB document.
#:
#: 256 KB keeps every realistic title, meta tag and article body intact while
#: capping the worst case at roughly linear cost.
MAX_ANALYZE_CHARS = 256 * 1024

#: Domains/adults markers frequently seen in explicit URL slugs.
_SUSPICIOUS_TOKENS: tuple[str, ...] = ("porn", "xxx", "sex", "nude", "nsfw", "cam", "hentai")


@dataclass
class TextAnalysisResult:
    """Outcome of analyzing a text / HTML payload."""

    score: float = 0.0
    matches: List[str] = field(default_factory=list)
    url_count: int = 0
    suspicious_urls: int = 0
    token_count: int = 0
    is_html: bool = False
    #: §12 context signals that contributed to ``score``.
    domain: str = ""
    domain_signal: float = 0.0
    explicit_flag: bool = False
    title: str = ""
    #: Set when the page's own copy - not an embedded URL - matched. Tracked
    #: separately because it is a materially stronger signal than a link.
    title_or_meta_matched: bool = False

    def as_dict(self) -> dict:
        return {
            "score": round(float(self.score), 6),
            "matches": list(self.matches),
            "url_count": self.url_count,
            "suspicious_urls": self.suspicious_urls,
            "token_count": self.token_count,
            "is_html": self.is_html,
            "domain": self.domain,
            "domain_signal": round(float(self.domain_signal), 6),
            "explicit_flag": self.explicit_flag,
            "title": self.title[:256],
            "title_or_meta_matched": self.title_or_meta_matched,
        }


class TextAnalyzer:
    """Extracts an NSFW text signal from raw text or HTML."""

    #: Score contributed per distinct keyword hit (before capping).
    PER_KEYWORD_WEIGHT = 0.34
    #: Score per suspicious URL found anywhere in the payload.
    URL_WEIGHT = 0.15
    #: Multiplier on the domain signal from `app.services.html_context`. The
    #: domain signal is already capped at 0.30, so the most this can contribute
    #: is 0.03 - deliberately far too small to cross any threshold alone.
    DOMAIN_WEIGHT = 0.10
    #: A page that explicitly declares itself (RTA/rating tag, known adult
    #: host). Capped low: a self-declaration warrants REVIEW, not conviction,
    #: because plenty of legitimate pages carry a rating tag.
    EXPLICIT_FLAG_WEIGHT = 0.12
    #: Per distinct keyword found in the page's *authored* copy (title, meta,
    #: alt). Weighted above a body keyword because the author chose those words
    #: to describe the page.
    AUTHORED_WEIGHT = 0.30

    def __init__(
        self,
        weight: float = 0.30,
        keyword_score_cap: float = 1.0,
        keywords: Optional[Sequence[str]] = None,
    ) -> None:
        self.weight = float(weight)
        self.keyword_score_cap = float(keyword_score_cap)
        self.keywords = tuple(k.lower() for k in (keywords or _DEFAULT_KEYWORDS))

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def strip_html(text: str) -> str:
        """Strip markup from *text*, bounded to :data:`MAX_ANALYZE_CHARS`.

        The truncation happens *before* the regexes run, which is what removes
        the quadratic blow-up: the backtracking cost is a function of the slice
        size, not of the document the caller submitted.
        """
        bounded = text[:MAX_ANALYZE_CHARS]
        without_scripts = _SCRIPT_STYLE_RE.sub(" ", bounded)
        without_tags = _TAG_RE.sub(" ", without_scripts)
        return unescape(without_tags)

    def _tokens(self, text: str) -> List[str]:
        return _WORD_RE.findall(text.lower())

    # -- public API ----------------------------------------------------------
    def analyze(
        self,
        text: Optional[str],
        url: str = "",
        domain: str = "",
    ) -> TextAnalysisResult:
        """Analyze *text* and return a :class:`TextAnalysisResult`.

        When *text* is markup, the §12 context signals (title, meta, alt,
        visible copy) are extracted and scored separately from the raw keyword
        scan. Keeping them distinct matters: a page that *describes* itself as
        explicit is far stronger evidence than one that merely links out, and
        the weights reflect that.
        """
        result = TextAnalysisResult()
        if not text:
            # A URL-only request still carries domain evidence (§12), and it
            # must contribute to the score - otherwise the whole domain signal
            # would be inert for callers that send just an ICAP request line.
            if url or domain:
                context = self._context_for(None, url, domain)
                result.score = float(min(self.keyword_score_cap, self._context_score(context, result)))
            return result

        # Bound once, up front, so every later scan works on the same slice.
        text = text[:MAX_ANALYZE_CHARS]

        result.is_html = bool(_TAG_RE.search(text)) or "<html" in text.lower()
        context = None
        if result.is_html:
            from app.services.html_context import extract_context

            context = extract_context(text, url=url, domain=domain)
            visible = context.visible_text or self.strip_html(text)
        else:
            visible = text

        tokens = self._tokens(visible)
        result.token_count = len(tokens)

        lowered = visible.lower()
        matches = [kw for kw in self.keywords if kw in lowered]
        result.matches = sorted(set(matches))

        urls = _URL_RE.findall(text)
        result.url_count = len(urls)
        result.suspicious_urls = sum(
            1 for url in urls if any(tok in url.lower() for tok in _SUSPICIOUS_TOKENS)
        )

        score = self.PER_KEYWORD_WEIGHT * len(result.matches)
        score += self.URL_WEIGHT * result.suspicious_urls
        if context is not None:
            score += self._context_score(context, result)
        result.score = float(min(self.keyword_score_cap, score))
        logger.debug(
            "text analysis tokens=%d matches=%d context_domain=%s score=%.3f",
            result.token_count,
            len(result.matches),
            result.domain or "-",
            result.score,
        )
        return result

    def _apply_context(
        self, result: TextAnalysisResult, context, url: str, domain: str
    ) -> None:
        """Populate the context fields on *result* (used when there is no body)."""
        if context is None:
            context = self._context_for(None, url, domain)
        result.domain = context.domain
        result.domain_signal = context.domain_signal
        result.explicit_flag = context.explicit_flag
        result.title = context.title

    @staticmethod
    def _context_for(html: Optional[str], url: str, domain: str):
        from app.services.html_context import extract_context

        return extract_context(html, url=url, domain=domain)

    def _context_score(self, context, result: TextAnalysisResult) -> float:
        """Score the §12 signals and copy the summary onto *result*.

        Weights are intentionally small. The strongest single case - a page that
        declares itself with an RTA/rating tag *and* has an explicit title -
        tops out well below the block threshold on its own, so context can never
        become sole evidence (§12). It is meant to tip an ambiguous image
        toward REVIEW, not to convict it.
        """
        self._apply_context(result, context, "", "")
        score = self.DOMAIN_WEIGHT * context.domain_signal
        if context.explicit_flag:
            score += self.EXPLICIT_FLAG_WEIGHT

        # The page's own descriptive copy, excluding the visible body: this is
        # the author declaring what the page is.
        authored = "\n".join(
            part
            for part in (
                context.title,
                context.og_title,
                context.meta_description,
                context.og_description,
                context.meta_keywords,
                " ".join(context.alt_values),
            )
            if part
        ).lower()
        authored_matches = [kw for kw in self.keywords if kw in authored]
        if authored_matches:
            result.title_or_meta_matched = True
            for keyword in sorted(set(authored_matches)):
                if keyword not in result.matches:
                    result.matches.append(keyword)
            result.matches.sort()
            score += self.AUTHORED_WEIGHT * len(set(authored_matches))
        return score

    def analyze_many(self, texts: Iterable[str]) -> TextAnalysisResult:
        """Analyze several fragments as a single logical document."""
        joined = "\n".join(t for t in texts if t)
        return self.analyze(joined)
