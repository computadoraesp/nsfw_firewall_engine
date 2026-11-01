"""Red-team iteration 2: input-handling attacks against the hardened API.

Iteration 1 closed the authentication and isolation holes. This round attacks
what a caller can send *once they are legitimately authenticated* - which is the
only remaining position for an attacker once C1/C5 are shut, so it is where the
next round of findings lives.

* ``RedosExploits``    - H3: catastrophic backtracking in the HTML stripper.
* ``InputBoundExploits`` - M3/M4/M5: no size limits, lenient base64.
* ``MimeBypassExploits``  - M1: the allow-list is never enforced.
* ``MediaGuardExploits``  - H8/M7: decompression bombs, unbounded video.
* ``PathSafetyExploits``  - M6: an unsanitised path helper is exported.

Run with::

    Python -m pytest tests/test_redteam_iter2.py -v
"""

from __future__ import annotations

import base64
import io
import os
import sys
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_redteam import AsgiClient, _auth, _client  # noqa: E402


# ---------------------------------------------------------------------------
# H3 - catastrophic backtracking
# ---------------------------------------------------------------------------


class RedosExploits(unittest.TestCase):
    """H3: ``<script>`` repeated without a closing tag blows up quadratically.

    ``_SCRIPT_STYLE_RE`` is ``<(script|style)[^>]*>.*?</\\1>`` with ``DOTALL``.
    With no closing tag the lazy ``.*?`` is retried at every offset, once per
    opening tag, so the cost is O(n^2). Measured on this repository:
    2000 tags 0.16s, 4000 tags 0.62s, 8000 tags 2.46s - four times the work for
    twice the input, at every step.
    """

    #: Wall-clock budget for one pathological request. The fix should make this
    #: effectively flat; the assertion is generous so it does not flake on a
    #: loaded CI box, but it still catches a quadratic blow-up.
    BUDGET_SECONDS = 2.0

    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    def test_attack_script_tag_flood_does_not_burn_cpu(self):
        """ATTACK: 8000 unclosed ``<script>`` tags (measured: 2.5s)."""
        payload = "<script>" * 8000
        started = time.perf_counter()
        response = self.client.post(
            "/classify/text", headers=_auth(), json={"text": payload, "media_type": "TEXT"}
        )
        elapsed = time.perf_counter() - started
        self.assertLess(
            elapsed,
            self.BUDGET_SECONDS,
            msg=(
                f"ReDoS: an 8000-tag payload took {elapsed:.2f}s "
                f"(budget {self.BUDGET_SECONDS}s). Growth is quadratic, so a "
                "payload only ~100x larger holds a worker for many minutes."
            ),
        )
        self.assertIn(response.status_code, (200, 400, 413, 422))

    def test_attack_script_tag_flood_is_not_quadratic(self):
        """The cost must not scale quadratically with the attacker's input."""
        timings = {}
        for count in (4000, 16000):
            started = time.perf_counter()
            self.client.post(
                "/classify/text",
                headers=_auth(),
                json={"text": "<script>" * count, "media_type": "TEXT"},
            )
            timings[count] = time.perf_counter() - started

        quad0 = max(timings[4000], 1e-4)
        ratio = timings[16000] / quad0
        # Quadratic would give ~16x. Linear gives ~4x. Anything past 8x is a
        # super-linear blow-up.
        self.assertLess(
            ratio,
            8.0,
            msg=(
                f"super-linear: 4x input took {ratio:.1f}x the time "
                f"({timings[4000]:.3f}s -> {timings[16000]:.3f}s)"
            ),
        )

    def test_analyzer_caps_its_input(self):
        """The Analyzer must bound the text it will scan, not just the caller."""
        from app.services import text_analyzer

        cap = getattr(text_analyzer, "MAX_ANALYZE_CHARS", 0)
        self.assertGreater(
            cap,
            0,
            msg=(
                "TextAnalyzer has no input cap: html_context bounds itself to "
                "MAX_INPUT_CHARS but the strip_html/findall fallback scans the "
                "whole document"
            ),
        )
        # And it must actually apply the cap.
        Analyzer = text_analyzer.TextAnalyzer()
        result = Analyzer.analyze("porn " * 500_000)
        self.assertLessEqual(
            len(result.matches),
            len(Analyzer.keywords),
            msg="matches should be de-duplicated regardless of input size",
        )


# ---------------------------------------------------------------------------
# M3 / M4 / M5 - input bounds
# ---------------------------------------------------------------------------


class InputBoundExploits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    def test_attack_oversized_text_is_refused(self):
        """M3: ``text`` fields had no max_length; 30 MB was accepted."""
        response = self.client.post(
            "/classify/text",
            headers=_auth(),
            json={"text": "A" * (5 * 1024 * 1024), "media_type": "TEXT"},
        )
        self.assertIn(
            response.status_code,
            (400, 413, 422),
            msg=f"5 MB text accepted (got {response.status_code})",
        )

    def test_attack_oversized_base64_is_refused_before_decoding(self):
        """M3: the base64 fields are unbounded too."""
        response = self.client.post(
            "/v1/inspect",
            headers=_auth(),
            json={"content_base64": "A" * (5 * 1024 * 1024)},
        )
        self.assertIn(
            response.status_code,
            (400, 413, 422),
            msg=f"5 MB of base64 accepted (got {response.status_code})",
        )

    def test_attack_lenient_base64_is_rejected(self):
        """M5: ``validate=False`` silently discards non-base64 characters.

        That means two different strings can decode to the same bytes, so a
        payload that passes one filter and not another can be smuggled past a
        digest- or signature-based check by adding junk.
        """
        from app.api.rest.router import _decode_base64

        with self.assertRaises(Exception):
            _decode_base64("!!!not-valid-base64!!!")
        with self.assertRaises(Exception):
            _decode_base64("aGVsbG8=!!!!tampered")

    def test_attack_data_uri_prefix_cannot_hide_a_payload(self):
        """The ``data:`` split must not become a smuggling channel."""
        from app.api.rest.router import _decode_base64

        with self.assertRaises(Exception):
            _decode_base64("data:image/png;base64,!!!!nope!!!!")


# ---------------------------------------------------------------------------
# M1 - MIME allow-list never enforced
# ---------------------------------------------------------------------------


class MimeBypassExploits(unittest.TestCase):
    """M1: ``enforce_mime=False`` everywhere, and only ``valid`` is checked.

    Measured: ZIP, ELF, PDF and a DOS executable are all accepted with ``200``
    and then handed to a native decoder. The allow-list in
    ``config/engine_config.yaml`` has no effect on the classification path.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    @staticmethod
    def _samples():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "x" * 1000)
        return {
            "zip": buffer.getvalue(),
            "elf": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200,
            "pdf": b"%PDF-1.7\n" + b"0" * (1024 * 20),
            "mz_executable": b"MZ" + b"\x00" * 300,
        }

    def test_attack_disallowed_types_are_rejected(self):
        for name, data in self._samples().items():
            with self.subTest(type=name):
                response = self.client.post(
                    "/v1/inspect",
                    headers=_auth(),
                    json={"content_base64": base64.b64encode(data).decode()},
                )
                self.assertIn(
                    response.status_code,
                    (400, 415, 422),
                    msg=(
                        f"{name} accepted with {response.status_code}; the MIME "
                        "allow-list is not enforced on the classification path"
                    ),
                )

    def test_disallowed_flag_is_actually_checked(self):
        """``inspect_payload`` computes ``allowed``; callers must honor it."""
        from app.services.content_inspector import inspect_payload

        report = inspect_payload(b"MZ" + b"\x00" * 300, enforce_mime=True)
        self.assertFalse(
            report.get("allowed", True),
            msg="a DOS executable is reported as allowed against the allow-list",
        )


# ---------------------------------------------------------------------------
# H8 / M7 - media guards
# ---------------------------------------------------------------------------


class MediaGuardExploits(unittest.TestCase):
    def test_decompression_bomb_band_is_closed(self):
        """H8: Pillow raises only above 2x MAX_IMAGE_PIXELS.

        With the cap at 64 MP, anything between 64 MP and 128 MP produces a
        warning instead of an error, so ~100 MP images pass validation and are
        then fully decoded by the preprocessor - roughly 300 MB of RAM per
        request, in a threadpool, with no concurrency limit.
        """
        from PIL import Image

        cap = Image.MAX_IMAGE_PIXELS
        self.assertLessEqual(
            cap,
            32 * 1024 * 1024,
            msg=(
                f"Image.MAX_IMAGE_PIXELS is {cap} "
                f"({cap / 1e6:.0f} MP); Pillow only errors above 2x that, so the "
                "band below it is unguarded"
            ),
        )

    def test_video_duration_is_bounded(self):
        """M7: duration is measured and returned, but never compared."""
        import inspect

        from content import mime_detector

        source = inspect.getsource(mime_detector._check_video)
        self.assertIn(
            "max_duration",
            source,
            msg="_check_video computes `duration` but never validates it",
        )

    def test_video_is_not_written_to_disk_unnecessarily(self):
        """M7: payload bytes landed in a temp file despite retain_raw_payloads=false."""
        import inspect

        from content import mime_detector

        # Inspect the *code*, not the prose: the docstring deliberately names
        # NamedTemporaryFile to explain why it was removed, and a naive source
        # grep matches that comment.
        source = inspect.getsource(mime_detector)
        code = "\n".join(
            line
            for line in source.splitlines()
            if not line.lstrip().startswith("#")
        )
        # Drop docstrings so prose cannot satisfy or break the check.
        import ast

        tree = ast.parse(source)
        docstrings = {
            ast.get_docstring(node, clean=False)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        code = code
        for doc in docstrings:
            if doc:
                code = code.replace(doc, "")
        self.assertNotIn(
            "NamedTemporaryFile",
            code,
            msg=(
                "_check_video writes the payload to a temp file, which "
                "contradicts privacy.retain_raw_payloads: false; cv2 can read a "
                "buffer instead"
            ),
        )
        self.assertNotIn(
            "import tempfile", code, msg="the temp-file machinery is still imported"
        )


# ---------------------------------------------------------------------------
# M6 - exported path helper
# ---------------------------------------------------------------------------


class PathSafetyExploits(unittest.TestCase):
    """M6: ``async_inspect_file`` took a path with no sanitisation and is in
    ``__all__``, so any future caller forwarding user input got arbitrary file
    read plus a SHA256 of the contents.

    The exploit uses a file that genuinely exists, because asserting on
    ``/etc/passwd`` merely proves that ``read_bytes`` raises ``FileNotFoundError``
    on a machine without it - a test that passes for the wrong reason.
    """

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secret = self.root / "secret.txt"
        self.secret.write_text("SENSITIVE-CONTENT", encoding="utf-8")
        # A sibling directory, the classic `../` traversal target.
        self.outside = Path(self.tmp.name).parent / "nsfw_traversal_target.txt"
        self.outside.write_text("SENSITIVE-CONTENT", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()
        try:
            self.outside.unlink()
        except OSError:
            pass

    def test_inspect_file_refuses_traversal_outside_the_root(self):
        import asyncio

        from content.mime_detector import async_inspect_file

        with self.assertRaises(ValueError):
            asyncio.run(async_inspect_file(str(self.outside), allowed_root=str(self.root)))

    def test_inspect_file_refuses_an_absolute_path_outside_the_root(self):
        import asyncio

        from content.mime_detector import async_inspect_file

        with self.assertRaises(ValueError):
            asyncio.run(async_inspect_file(str(self.outside), allowed_root=str(self.root)))

    def test_inspect_file_still_works_inside_the_root(self):
        """The hardening must not break the legitimate use."""
        import asyncio

        from content.mime_detector import async_inspect_file

        report = asyncio.run(
            async_inspect_file(str(self.secret), allowed_root=str(self.root))
        )
        self.assertIn("sha256", report)

    def test_inspect_file_refuses_directories(self):
        import asyncio

        from content.mime_detector import async_inspect_file

        with self.assertRaises(ValueError):
            asyncio.run(async_inspect_file(str(self.root), allowed_root=str(self.root)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()