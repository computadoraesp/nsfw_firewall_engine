"""Benchmark / evaluation report renderers (§25).

``pront.md`` §25 lists four output formats: **CSV, JSON, Markdown and HTML**.
JSON and Markdown are produced by the report objects themselves; this module
adds the other two as pure functions over the same dictionaries, so every
format reports exactly the same numbers - a matrix that disagrees between CSV
and Markdown is worse than no matrix at all.

Why CSV and HTML are worth having here:

* **CSV** is what a reviewer actually loads into a spreadsheet to compare runs
  across machines, or pastes into a ticket. Markdown tables do not survive that.
* **HTML** is what a stakeholder reads without a terminal. It is a single
  self-contained file - no CDN, no JavaScript - because a benchmark artefact
  that needs the network to render is useless in an air-gapped review, and a
  remote ``<script src>`` in a security document is a supply-chain smell.

Every renderer escapes its inputs. Benchmark values are numbers, but dataset
names and model ids come from configuration, so treating them as trusted would
be sloppy.
"""

from __future__ import annotations

import csv
import html
import io
from typing import Any, Dict, List, Mapping, Optional, Tuple


def _flatten(prefix: str, value: Any, out: Dict[str, Any]) -> None:
    """Flatten nested dicts/lists into ``a.b`` / ``a[0]`` keys.

    The CSV is a flat key/value table rather than a wide matrix: the benchmark
    and evaluation payloads have different shapes, and a fixed column set would
    end up mostly empty for whichever report was not supplied.
    """
    if isinstance(value, Mapping):
        for key, item in value.items():
            _flatten(f"{prefix}.{key}" if prefix else str(key), item, out)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _flatten(f"{prefix}[{index}]", item, out)
    else:
        out[prefix] = value


def _rows(
    sections: Mapping[str, Optional[Mapping[str, Any]]]
) -> List[Tuple[str, str, Any]]:
    """Return ``(section, metric, value)`` triples, skipping empty sections."""
    rows: List[Tuple[str, str, Any]] = []
    for name, payload in sections.items():
        if not payload:
            continue
        flat: Dict[str, Any] = {}
        _flatten("", payload, flat)
        for metric, value in flat.items():
            rows.append((name, metric, value))
    return rows


def to_csv(sections: Mapping[str, Optional[Mapping[str, Any]]]) -> str:
    """Render ``{section_name: payload}`` as a two-column CSV.

    Sections with no payload are skipped rather than emitting a header with no
    rows, so a run without ``--dataset`` produces a benchmark-only file.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["section", "metric", "value"])
    for name, metric, value in _rows(sections):
        writer.writerow([name, metric, value])
    return buffer.getvalue()


def to_html(
    sections: Mapping[str, Optional[Mapping[str, Any]]],
    title: str = "NSFW Firewall Engine - benchmark matrix",
) -> str:
    """Render a single self-contained HTML report (§25).

    The heuristic-fallback warning is carried through prominently: §49 forbids
    presenting pipeline numbers as detector performance, and an HTML artefact is
    the one most likely to be screenshotted and circulated without its caveat.
    """
    benchmark = sections.get("benchmark") or {}
    heuristic = bool(benchmark.get("heuristic_fallback"))
    models_loaded = benchmark.get("models_loaded")

    parts: List[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{html.escape(title)}</title>",
        "<style>",
        # Inline only: the file must render offline, with no remote fetches.
        "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1b1b1b}",
        "table{border-collapse:collapse;width:100%;margin:1rem 0}",
        "th,td{border:1px solid #ccc;padding:.35rem .6rem;text-align:left;"
        "font-variant-numeric:tabular-nums}",
        "th{background:#f4f4f4}",
        "caption{text-align:left;font-weight:600;margin-top:1.5rem}",
        ".warn{background:#fff4e5;border:1px solid #e0a800;padding:.7rem 1rem;"
        "border-radius:4px}",
        "footer{color:#666;font-size:.85rem;margin-top:2rem}",
        "</style></head><body>",
        f"<h1>{html.escape(title)}</h1>",
    ]

    if heuristic:
        parts.append(
            '<p class="warn"><strong>Heuristic fallback.</strong> No ONNX model was '
            "loaded, so these are pipeline measurements - <em>not</em> detector "
            "quality (pront.md &sect;49). Load weights before drawing any "
            "conclusion from the latency or throughput figures.</p>"
        )
    if models_loaded is not None:
        parts.append(
            f"<p>Models loaded: <strong>{html.escape(str(models_loaded))}</strong></p>"
        )

    # Group rows by section so each table carries its own caption.
    grouped: Dict[str, List[Tuple[str, Any]]] = {}
    order: List[str] = []
    for section, metric, value in _rows(sections):
        if section not in grouped:
            grouped[section] = []
            order.append(section)
        grouped[section].append((metric, value))

    for section in order:
        parts.append(f"<table><caption>{html.escape(section)}</caption>")
        parts.append("<thead><tr><th>metric</th><th>value</th></tr></thead><tbody>")
        for metric, value in grouped[section]:
            parts.append(
                f"<tr><td>{html.escape(str(metric))}</td>"
                f"<td>{html.escape(str(value))}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append(
        "<footer>Generated by <code>python -m benchmarks</code>. Every number "
        "here was measured on the machine that produced this file; regenerate "
        "rather than editing by hand (pront.md &sect;49).</footer>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


__all__ = ["to_csv", "to_html"]
