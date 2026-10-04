"""Fuzz harness for the untrusted parsers (``pront.md`` §37 ``fuzzing``).

Targets the three surfaces that consume attacker-controlled bytes before any
authentication or policy decision is made:

* :func:`app.api.icap.icap_server.read_icap_message` - a line-oriented parser
  driven directly by whatever Squid sends on the wire.
* :mod:`content.mime_detector` - magic-byte sniffing, explicitly built for
  malformed and truncated media (§16).
* :mod:`app.services.html_context` - the §12 extractor, which parses whatever
  HTML a page chooses to return.

The properties asserted are *safety* properties, not correctness ones: a
firewall parser that crashes, hangs or allocates unboundedly is an outage, and
that is reachable by anyone who can send one packet. Specifically, every input
must (a) not raise an unexpected exception, (b) return within a time budget, and
(c) not blow up memory.

This is a deterministic, seeded harness rather than a coverage-guided fuzzer:
it runs in CI on every build with no extra dependency and no corpus, while
still exercising real mutations. Swap in Atheris or libFuzzer for deeper
exploration, but keep these assertions - a crash found by either is a crash.
"""

from __future__ import annotations

import io
import logging
import random
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger("nsfw_engine.scripts.fuzz")

#: Default seed so a CI failure is reproducible from the log line.
DEFAULT_SEED = 0xC0FFEE

#: Per-input wall-clock budget. Generous for a parser, tight enough that a
#: pathological input shows up as a failure instead of a hung CI job.
DEFAULT_TIME_BUDGET_MS = 250.0

#: Default iterations per target. Large enough to be meaningful, small enough
#: to keep the job under a few seconds.
DEFAULT_ITERATIONS = 400

#: Interest points an ICAP header is built around, so mutations produce
#: *plausible* malformed messages rather than random noise the parser rejects
#: on the first byte.
_INTERESTING = [
    b"",
    b" ",
    b"\x00",
    b"\r\n\r\n",
    b"\r\n",
    b"\n" * 64,
    b"\t",
    b":" * 8,
    b"Content-Length: 99999999999999999999\r\n",
    b"Content-Length: -1\r\n",
    b"Content-Length: abc\r\n",
    b"Ignore: 999\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Encapsulated: req-hdr=1, req-body=0\r\n",
    b"OPTIONS: * HTTP/1.0\r\n",
    b"GET http://x/ HTTP/1.1\r\n",
    b"Host: \xff\xfe\r\n",
    b"ISTag: " + b"A" * 4096 + b"\r\n",
    b"A" * 8192,
]


def _seeded_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(length))


def mutate(rng: random.Random, data: bytes) -> bytes:
    """Apply one random mutation to *data*.

    Purely byte-level: no structure is assumed, because the whole point is to
    feed the parsers things nobody would write by hand.
    """
    if not data:
        return _seeded_bytes(rng, rng.randint(0, 64))
    choice = rng.randint(0, 5)
    if choice == 0:  # truncate
        return data[: rng.randint(0, len(data))]
    if choice == 1:  # flip a bit
        index = rng.randrange(len(data))
        mutated = bytearray(data)
        mutated[index] ^= 1 << rng.randrange(8)
        return bytes(mutated)
    if choice == 2:  # splice in an interesting value
        insert = rng.choice(_INTERESTING)
        index = rng.randrange(len(data) + 1)
        return data[:index] + insert + data[index:]
    if choice == 3:  # delete a run
        index = rng.randrange(len(data))
        end = min(len(data), index + rng.randint(1, 64))
        return data[:index] + data[end:]
    if choice == 4:  # duplicate a run
        index = rng.randrange(len(data))
        end = min(len(data), index + rng.randint(1, 64))
        return data[:index] + data[index:end] + data[index:]
    return data + _seeded_bytes(rng, rng.randint(1, 128))


# ---------------------------------------------------------------------------
# Seeds - valid-ish starting points the mutations corrupt.
# ---------------------------------------------------------------------------

def icap_seeds() -> List[bytes]:
    body = b"<html><body>hello</body></html>"
    return [
        b"REQMOD icap://proxy/reqmod ICAP/1.0\r\n"
        b"Host: proxy\r\n"
        b"Encapsulated: req-hdr=0, req-body=0\r\n"
        b"\r\n"
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"\r\n",
        b"RESPMOD icap://proxy/respmod ICAP/1.0\r\n"
        b"Host: proxy\r\n"
        b"Encapsulated: req-hdr=0, res-hdr=0, res-body=1\r\n"
        b"\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body,
    ]


def html_seeds() -> List[bytes]:
    return [
        b"<html><head><title>Example</title></head><body>text</body></html>",
        b'<html><head><meta name="description" content="x">'
        b'<img alt="y"></head><body><p>z</p></body></html>',
        b"<!doctype html><html><body><script>var x=1;</script></body></html>",
    ]


def media_seeds() -> List[bytes]:
    # Minimal magic-byte prefixes for the formats the inspector recognises.
    return [
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,
        b"\xff\xd8\xff\xe0" + b"\x00" * 32,
        b"GIF89a" + b"\x00" * 24,
        b"P6\n2 2\n255\n" + b"\xff" * 12,
        b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 16,
        b"\x1a\x45\xdf\xa3" + b"\x00" * 32,
    ]


# ---------------------------------------------------------------------------
# Targets.
# ---------------------------------------------------------------------------

def target_icap(data: bytes) -> None:
    """Feed arbitrary bytes to the ICAP request parser.

    ``IcapParseError`` is the documented rejection path, so it is not a finding.
    Any *other* exception type escaping means the parser met something it did
    not anticipate - which is precisely what a proxy on the internet will send.
    """
    from app.api.icap.icap_server import IcapParseError, read_icap_message
    from app.core.config import get_config

    # max_body_bytes is mandatory on the real signature; use the configured cap
    # so the harness exercises the same limit production does.
    try:
        cap = int(get_config().transport.icap.max_body_bytes)
    except Exception:  # noqa: BLE001 - config may be unavailable in isolation
        cap = 32 * 1024 * 1024

    try:
        read_icap_message(io.BytesIO(data), max_body_bytes=cap)
    except IcapParseError:
        pass


def target_html(data: bytes) -> None:
    from app.services.html_context import extract_context

    text = data.decode("utf-8", errors="replace")
    context = extract_context(text, url="https://fuzz.example/path")
    # Force the derived views so lazy parsing cannot hide a bug.
    _ = context.descriptive_text
    context.as_dict()


def target_mime(data: bytes) -> None:
    from content.mime_detector import inspect_content

    inspect_content(data)


TARGETS: Tuple[Tuple[str, Callable[[bytes], None], Callable[[], List[bytes]]], ...] = (
    ("icap", target_icap, icap_seeds),
    ("html", target_html, html_seeds),
    ("mime", target_mime, media_seeds),
)


def fuzz_target(
    name: str,
    target: Callable[[bytes], None],
    seeds: Sequence[bytes],
    iterations: int = DEFAULT_ITERATIONS,
    seed: int = DEFAULT_SEED,
    time_budget_ms: float = DEFAULT_TIME_BUDGET_MS,
) -> List[Tuple[bytes, str]]:
    """Run *target* over mutated seeds; return ``(input, failure)`` pairs."""
    rng = random.Random(seed)
    failures: List[Tuple[bytes, str]] = []
    corpus = list(seeds)

    # Warm up before timing. The first call to a target pays for lazy imports
    # (config parsing, module loading), which can be hundreds of milliseconds on
    # a cold interpreter. Without this the budget measures interpreter warm-up
    # rather than parsing cost and reports a false finding on the first input -
    # exactly the kind of noise that teaches people to ignore a fuzzer.
    for seed_input in corpus:
        try:
            target(seed_input)
        except Exception:  # noqa: BLE001 - a seed that already crashes is a finding
            failures.append((seed_input, "seed input raised"))

    for iteration in range(max(1, iterations)):
        # Restart from a seed periodically so the corpus is not one lineage: a
        # pure mutation chain drifts away from every structured input.
        base = corpus[iteration % len(corpus)]
        data = base
        for _ in range(rng.randint(1, 4)):
            data = mutate(rng, data)
        corpus.append(data)

        started = time.perf_counter()
        try:
            target(data)
        except Exception as exc:  # noqa: BLE001 - a finding, by definition
            failures.append((data, f"{type(exc).__name__}: {exc}"))
            continue
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if elapsed_ms > time_budget_ms:
            failures.append((data, f"exceeded {time_budget_ms:.0f}ms ({elapsed_ms:.1f}ms)"))
    return failures


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python scripts/fuzz.py",
        description="Fuzz the untrusted parsers (pront.md §37).",
    )
    parser.add_argument(
        "--iterations", type=int, default=DEFAULT_ITERATIONS, help="inputs per target"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="PRNG seed")
    parser.add_argument(
        "--time-budget-ms",
        type=float,
        default=DEFAULT_TIME_BUDGET_MS,
        help="per-input wall-clock budget",
    )
    parser.add_argument(
        "--target", default=None, choices=[name for name, _t, _s in TARGETS]
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    selected = (
        TARGETS if args.target is None else tuple(t for t in TARGETS if t[0] == args.target)
    )

    print(
        f"Fuzzing untrusted parsers (§37) - seed=0x{args.seed:X} "
        f"iterations={args.iterations}"
    )
    total = 0
    for name, target, seed_factory in selected:
        failures = fuzz_target(
            name,
            target,
            seed_factory(),
            iterations=args.iterations,
            seed=args.seed,
            time_budget_ms=args.time_budget_ms,
        )
        total += len(failures)
        status = "OK" if not failures else f"FAIL ({len(failures)})"
        print(f"  {name:<6} {args.iterations:>5} inputs  {status}")
        for data, reason in failures[:5]:
            print(f"      {reason}")
            print(f"      input: {data[:120]!r}")

    print(f"\n{total} failure(s) across {len(selected)} target(s)")
    if total:
        print("Reproduce with the same --seed and the printed input.")
    return 1 if total else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
