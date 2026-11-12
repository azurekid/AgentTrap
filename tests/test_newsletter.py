import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools import write_newsletter
from tools.write_newsletter import call_model

ROOT = Path(__file__).resolve().parents[1]


class NewsletterModelTests(unittest.TestCase):
    def test_azure_request_and_response(self):
        messages = [{"role": "user", "content": "Hello"}]
        seen = {}

        def opener(request, timeout):
            seen["request"], seen["timeout"] = request, timeout
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": "A draft"}}]}).encode())

        self.assertEqual(call_model(messages, "deployment", "my-resource", "test-key", opener), "A draft")
        request = seen["request"]
        self.assertEqual(request.full_url, "https://my-resource.openai.azure.com/openai/v1/chat/completions")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Api-key"), "test-key")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(json.loads(request.data), {
            "model": "deployment", "messages": messages, "temperature": 0.6, "max_tokens": 2500,
        })
        self.assertEqual(seen["timeout"], 120)

    def test_invalid_resource_never_calls_endpoint(self):
        for resource in ("", "evil.example", "name@evil", "name/path", "-bad", "bad-"):
            with self.subTest(resource=resource), self.assertRaises(ValueError):
                call_model([], "deployment", resource, "test-key", lambda *args, **kwargs: self.fail())

    def test_missing_configuration_fails_before_network(self):
        env = os.environ.copy()
        for name in ("AZURE_OPENAI_RESOURCE", "AZURE_OPENAI_API_KEY", "NEWSLETTER_MODEL"):
            env.pop(name, None)
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/write_newsletter.py"), "--report", "unused"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("AZURE_OPENAI_RESOURCE, AZURE_OPENAI_API_KEY and NEWSLETTER_MODEL", result.stderr)

    def test_main_writes_newsletter_and_title(self):
        with tempfile.TemporaryDirectory() as directory:
            report, title = Path(directory) / "report.md", Path(directory) / "title.txt"
            report.write_text("### Research\n- [ ] Example (2026-11-12) - Source\n"
                              "  https://example.test/article\n", encoding="utf-8")
            output = io.StringIO()
            env = {"AZURE_OPENAI_RESOURCE": "resource", "AZURE_OPENAI_API_KEY": "test-key",
                   "NEWSLETTER_MODEL": "deployment"}
            args = ["write_newsletter.py", "--report", str(report), "--title-out", str(title), "--issue", "7"]
            with patch.dict(os.environ, env), patch.object(sys, "argv", args), \
                    patch.object(write_newsletter, "call_model", return_value="# Headline\nSee [S1].") as model, \
                    redirect_stdout(output):
                self.assertEqual(write_newsletter.main(), 0)
            self.assertEqual(model.call_args.args[1:], ("deployment", "resource", "test-key"))
            self.assertEqual(title.read_text(encoding="utf-8"), "Headline")
            self.assertIn("[S1](https://example.test/article)", output.getvalue())
            self.assertIn("in #7", output.getvalue())


if __name__ == "__main__":
    unittest.main()
