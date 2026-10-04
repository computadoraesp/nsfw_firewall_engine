"""HTML / URL context extraction (``pront.md`` §12).

§12 asks the engine to look at the *surroundings* of an image, not just the
pixels: the URL, the domain, the ``<title>``, ``<meta>`` tags, ``alt`` text and
the visible copy. Adult sites habitually label themselves, and a page whose
title is "Free XXX videos" is strong evidence even when the single sampled image
is ambiguous.

Two rules shape this module:

**Context is never sole evidence.** Every signal here is *advisory*: it raises
the text score, which feeds fusion, which the policy engine thresholds. A URL
alone can therefore never escalate to BLOCK on its own - the model output still
has to agree. That is §12's "context only, not sole evidence", enforced
structurally: this module produces a bounded score contribution and has no
access to the verdict.

**Untrusted input, aggressively bounded.** The HTML arrives from the internet.
Scans are capped, attribute collection is bounded, and malformed markup degrades
to "no context found" rather than raising. A context extractor is an easy place
to accidentally ship a ReDoS or a memory bomb, so the caps are part of the
design rather than an afterthought.

The stdlib ``html.parser`` is used rather than BeautifulSoup: §3/§48 say reuse
what exists, but also do not take on a dependency for a well-understood
200-line job. ``html.parser`` is C-accelerated, never executes anything, and
ships with Python.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger("nsfw_engine.services.html_context")

#: Hard caps on how much input is inspected. A 50 MB HTML page must not turn a
#: context lookup into a CPU sink; the first slice is what matters for the
#: title/meta, which live in <head>.
MAX_INPUT_CHARS = 512 * 1024
#: Upper bound on the number of attributes collected from any one element.
MAX_ATTRS_PER_TAG = 32
#: Upper bound on collected <img alt> values, to bound memory on a page with a
#: gallery of 10,000 thumbnails.
MAX_ALT_VALUES = 200
#: Upper bound on the visible text kept for keyword scanning.
MAX_TEXT_CHARS = 64 * 1024

#: <meta> values that carry descriptive text worth scanning. OpenGraph tags are
#: duplicated metadata but are often the only description a scraper-friendly page
#: keeps on an otherwise obfuscated document.
_META_INTERESTING = ("description", "keywords", "og:title", "og:description")

#: Tokens disproportionately associated with adult-only sites. A small
#: contributor to the domain signal - never a decision on its own.
_ADULT_TOKENS = ("xxx", "porn", "nsfw", "sex", "cam", "hentai", "escort", "fetish", "nude")

#: Registrable labels of well-known adult platforms. Matched on the label so
#: subdomains are covered too.
_ADULT_HOSTS = frozenset({"xhamster", "xvideos", "pornhub", "redtube", "youporn", "onlyfans"})

#: Comment/metadata markers adult sites use in <head> (Preroll="RTA-5042-1996-1400").
_RTA_MARKERS = ("rta-5042-1996-1400", "rta/5042-1996-1400")

#: Longest title/attribute value retained.
_MAX_TAG_TEXT = 512

#: A syntactically valid, bounded hostname.
_HOST_RE = re.compile(r"[a-z0-9.\-]+")


class _ContextParser(HTMLParser):
    """Collects the §12 signals while streaming, without building a DOM tree.

    ``convert_charrefs=True`` makes the parser decode entities itself, which is
    both faster and safer than unescaping a concatenated string afterwards.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: List[str] = []
        self.meta: Dict[str, str] = {}
        self.alt_values: List[str] = []
        self.text_parts: List[str] = []
        self.has_nsfw_flag = False
        self.image_count = 0
        self.link_count = 0
        self._in_title = False
        self._skip_depth = 0
        self._text_length = 0
        self._attr_count = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        self._attr_count = 0
        if self._skip_depth:
            self._skip_depth += 1
            return
        name = tag.lower()
        if name in ("script", "style", "noscript", "svg", "iframe"):
            # These can hold megabytes of noise. Skipping them is also a
            # correctness win: a keyword inside a script is not page copy.
            self._skip_depth = 1
            return
        if name == "title":
            self._in_title = True
        elif name == "meta":
            self._handle_meta(attrs)
        elif name == "img":
            self.image_count += 1
            self._handle_img(attrs)
        elif name == "a":
            self.link_count += 1

    def handle_endtag(self, tag: str) -> None:
        if self._skip_depth:
            self._skip_depth -= 1
            return
        if tag.lower() == "title":
            self._in_title = False

    def handle_startendtag(self, tag, attrs) -> None:
        # <img ... /> - self-closing, must not open a skip region.
        if not self._skip_depth:
            self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data or not data.strip():
            return
        # A page labelling itself in a comment is exactly the §12 signal.
        lowered = data.lower()
        if any(marker in lowered for marker in _RTA_MARKERS):
            self.has_nsfw_flag = True
        if self._in_title:
            if sum(len(part) for part in self.title_parts) < _MAX_TAG_TEXT:
                self.title_parts.append(data[:_MAX_TAG_TEXT])
            return
        if self._text_length >= MAX_TEXT_CHARS:
            return
        snippet = data[:MAX_TEXT_CHARS - self._text_length]
        self.text_parts.append(snippet)
        self._text_length += len(snippet)

    def _handle_meta(self, attrs) -> None:
        """Record ``<meta>`` tags that describe the page.

        Three shapes have to be handled, and getting the second one wrong is
        easy: the value lives in ``content``, while the *key* is either the
        ``name`` attribute (``<meta name="description" content="...">``) or
        ``property`` for OpenGraph (``<meta property="og:title" ...>``). A
        naive ``attrs["name"]`` lookup silently drops every description.
        """
        mapping: Dict[str, str] = {}
        for name, value in attrs:
            if self._attr_count >= MAX_ATTRS_PER_TAG:
                break
            self._attr_count += 1
            if name and value:
                mapping[name.lower()] = value[:_MAX_TAG_TEXT]

        # An explicit rating declaration is the page labelling itself. The
        # standard marker is `<meta http-equiv="Preroll"
        # content="RTA-5042-1996-1400">`, so `Preroll` must be recognised as
        # well as the older `Rating`/`RTA` forms - missing it would mean the
        # single most common self-declaration on the web went unnoticed.
        equiv = mapping.get("http-equiv", "").lower()
        content = mapping.get("content", "")
        if equiv in ("preroll", "rating", "rta", "porn-rating"):
            if any(marker in content.lower() for marker in _RTA_MARKERS) or "adult" in content.lower():
                self.has_nsfw_flag = True
        declared = mapping.get("rta", mapping.get("rating", "")).lower()
        if declared and ("adult" in declared or declared.startswith("rta")):
            self.has_nsfw_flag = True

        # OpenGraph keys off `property`; everything else off `name`.
        key = mapping.get("property", "").lower() or mapping.get("name", "").lower()
        if not key or not content:
            return
        if key in _META_INTERESTING:
            self.meta.setdefault(key, content)

    def _handle_img(self, attrs) -> None:
        if len(self.alt_values) >= MAX_ALT_VALUES:
            return
        for name, value in attrs:
            if self._attr_count >= MAX_ATTRS_PER_TAG:
                break
            self._attr_count += 1
            if name and name.lower() == "alt" and value:
                text = value.strip()
                if text:
                    self.alt_values.append(text[:_MAX_TAG_TEXT])


@dataclass
class HtmlContext:
    """The §12 signals extracted from one page or request."""

    title: str = ""
    meta_description: str = ""
    meta_keywords: str = ""
    og_title: str = ""
    og_description: str = ""
    alt_values: List[str] = field(default_factory=list)
    visible_text: str = ""
    url: str = ""
    domain: str = ""
    domain_signal: float = 0.0
    explicit_flag: bool = False
    image_count: int = 0
    link_count: int = 0
    truncated: bool = False

    def as_dict(self) -> dict:
        """Audit-safe summary (§18).

        ``visible_text`` is deliberately omitted: this dict is meant to be
        logged, and echoing the page copy into the audit log would retain
        content that ``privacy.retain_raw_payloads: false`` forbids.
        """
        return {
            "title": self.title[:_MAX_TAG_TEXT],
            "meta_description": self.meta_description[:_MAX_TAG_TEXT],
            "meta_keywords": self.meta_keywords[:_MAX_TAG_TEXT],
            "og_title": self.og_title[:_MAX_TAG_TEXT],
            "og_description": self.og_description[:_MAX_TAG_TEXT],
            "alt_count": len(self.alt_values),
            "url": self.url[:1024],
            "domain": self.domain,
            "domain_signal": round(float(self.domain_signal), 6),
            "explicit_flag": self.explicit_flag,
            "image_count": self.image_count,
            "link_count": self.link_count,
            "truncated": self.truncated,
        }

    @property
    def descriptive_text(self) -> str:
        """Everything worth keyword-scanning, joined.

        Title and meta come first: they are what the page author chose to say
        about itself, so they carry more signal per character than body copy.
        """
        parts = [
            self.title,
            self.og_title,
            self.meta_description,
            self.og_description,
            self.meta_keywords,
            " ".join(self.alt_values),
            self.visible_text,
        ]
        return "\n".join(part for part in parts if part)


def analyse_domain(url_or_host: str) -> Tuple[str, float, bool]:
    """Return ``(domain, signal, explicit_flag)`` for a URL or bare host.

    ``signal`` is in ``[0, 1]`` and is a *minor* contributor: an adult-sounding
    hostname raises suspicion, but shared hosting means a legitimate site may
    match nothing and a token may appear by accident. It is capped well below
    the weight of an explicit text match, and cannot by itself cross a block
    threshold.

    The URL *path* is scored as well as the host. §12 lists "URL", not merely
    "domain", and in practice the path carries the most descriptive part:
    ``https://a.shared-host.example/free-porn-videos`` is far more informative
    than its registrable domain alone.
    """
    if not url_or_host:
        return "", 0.0, False
    candidate = url_or_host.strip()
    if "://" in candidate:
        parts = urlsplit(candidate)
        host = parts.hostname or ""
        path = parts.path or ""
    else:
        host = candidate.split("/", 1)[0]
        path = "/" + candidate.split("/", 1)[1] if "/" in candidate else ""
        if "@" in host:
            host = host.split("@", 1)[1]
        host = host.split(":", 1)[0]
    host = host.strip().lower().rstrip(".")
    path = path.lower()

    if not host or len(host) > 253 or not _HOST_RE.fullmatch(host):
        # Not host-shaped input: report what we saw but contribute no signal.
        return host[:253], 0.0, False

    labels = host.split(".")
    registrable = labels[-2] if len(labels) >= 2 else host
    if registrable in _ADULT_HOSTS:
        return host, 0.30, True

    signal = 0.0
    if any(token in host for token in _ADULT_TOKENS):
        # A host hit is weaker than a known host: cap it so a page containing
        # the word in a subdomain cannot dominate the score on its own.
        signal = 0.18
    if any(token in path for token in _ADULT_TOKENS):
        # A token in the path is at least as strong as one in the host, and the
        # two together stay bounded.
        signal = min(0.30, max(signal, 0.22))
    return host, signal, False


def extract_context(
    html: Optional[str] = None,
    url: str = "",
    domain: str = "",
) -> HtmlContext:
    """Extract the §12 signals from *html*, *url* and *domain*.

    Never raises: a parser error on hostile markup degrades to whatever was
    collected up to that point.
    """
    context = HtmlContext(url=url[:1024], domain=domain[:253])

    # The domain signal does not depend on markup parsing, so it is resolved
    # first and survives even a parse that blows up immediately.
    resolved, signal, host_flag = analyse_domain(url or domain)
    if not context.domain:
        context.domain = resolved
    context.domain_signal = signal
    context.explicit_flag = host_flag

    if not html:
        return context

    context.truncated = len(html) > MAX_INPUT_CHARS
    parser = _ContextParser()
    try:
        parser.feed(html[:MAX_INPUT_CHARS])
        parser.close()
    except Exception as exc:  # noqa: BLE001 - hostile markup must not raise
        logger.debug("html context parser stopped early: %s", exc)

    context.title = unescape(" ".join(parser.title_parts)).strip()
    context.meta_description = parser.meta.get("description", "")
    context.meta_keywords = parser.meta.get("keywords", "")
    context.og_title = parser.meta.get("og:title", "")
    context.og_description = parser.meta.get("og:description", "")
    context.alt_values = parser.alt_values
    context.visible_text = unescape(" ".join(parser.text_parts)).strip()
    context.image_count = parser.image_count
    context.link_count = parser.link_count
    context.explicit_flag = context.explicit_flag or parser.has_nsfw_flag
    return context


__all__ = ["HtmlContext", "analyse_domain", "extract_context"]
