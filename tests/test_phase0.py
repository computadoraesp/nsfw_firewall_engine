import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Import the JSON logger helper
from utils.logging import get_logger

class TestJsonLogger(unittest.TestCase):
    def test_logger_outputs_valid_json_with_trace_id(self):
        # Capture stdout
        captured = io.StringIO()
        handler = logging.StreamHandler(captured)
        # Use a fresh logger to avoid duplicate handlers
        logger = logging.getLogger("test_logger")
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        # Monkey‑patch the JSON formatter from utils.logging
        from utils.logging import JsonFormatter
        handler.setFormatter(JsonFormatter())

        # Emit a log using the helper that injects trace_id
        from utils.logging import get_logger as get_logger_helper
        helper_logger = get_logger_helper(name="test_logger")
        helper_logger.trace_info("test message")
        handler.flush()
        output = captured.getvalue().strip()
        # Parse JSON
        data = json.loads(output)
        self.assertIn("message", data)
        self.assertEqual(data["message"], "test message")
        self.assertIn("trace_id", data)
        # Ensure trace_id looks like a UUID
        try:
            uuid_obj = uuid.UUID(data["trace_id"])
        except Exception as exc:
            self.fail(f"trace_id is not a valid UUID: {exc}")

class TestPolicyValidator(unittest.TestCase):
    def test_validator_exits_successfully_on_empty_policy_dir(self):
        # Run the validator script on the current repo (policy dir may be empty)
        result = subprocess.run([sys.executable, "policy/validate_rules.py"], cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True)
        # The script should exit with status 0 (no failures) and print at least one OK line
        self.assertEqual(result.returncode, 0, msg=f"Stderr: {result.stderr}\nStdout: {result.stdout}")
        self.assertIn("[OK]", result.stdout)

if __name__ == "__main__":
    unittest.main()
