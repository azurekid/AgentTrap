import io
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
    def test_copilot_request_and_response(self):
        messages = [{"role": "user", "content": "Hello"}]
        with patch.object(write_newsletter.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, stdout="A draft")) as run:
            self.assertEqual(call_model(messages), "A draft")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "copilot")
        self.assertIn("--available-tools=__none__", command)
        self.assertIn("--disable-builtin-mcps", command)
        self.assertIn("--no-custom-instructions", command)
        self.assertIn("--no-auto-update", command)
        self.assertEqual(command[-2:], ["--prompt", "Hello"])
        self.assertEqual(run.call_args.kwargs["cwd"], run.call_args.kwargs["env"]["COPILOT_HOME"])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_empty_or_failed_copilot_response_fails(self):
        with patch.object(write_newsletter.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, stdout=" \n")):
            with self.assertRaises(ValueError):
                call_model([])
        with patch.object(write_newsletter.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "copilot")):
            with self.assertRaises(subprocess.CalledProcessError):
                call_model([])

    def test_main_writes_newsletter_and_title(self):
        with tempfile.TemporaryDirectory() as directory:
            report, title = Path(directory) / "report.md", Path(directory) / "title.txt"
            report.write_text("### Research\n- [ ] Example (2026-11-12) - Source\n"
                              "  https://example.test/article\n", encoding="utf-8")
            output = io.StringIO()
            args = ["write_newsletter.py", "--report", str(report), "--title-out", str(title), "--issue", "7"]
            with patch.object(sys, "argv", args), \
                    patch.object(write_newsletter, "call_model", return_value="# Headline\nSee [S1].") as model, \
                    redirect_stdout(output):
                self.assertEqual(write_newsletter.main(), 0)
            self.assertEqual(len(model.call_args.args[0]), 2)
            self.assertEqual(title.read_text(encoding="utf-8"), "Headline")
            self.assertIn("[S1](https://example.test/article)", output.getvalue())
            self.assertIn("in #7", output.getvalue())

    def test_writer_executes_copilot_and_creates_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            report, title, cli = path / "report.md", path / "title.txt", path / "copilot"
            report.write_text("### Research\n- [ ] Example (2026-11-12) - Source\n"
                              "  https://example.test/article\n", encoding="utf-8")
            cli.write_text("#!/bin/sh\nprintf '# Headline\\nSee [S1].\\n'\n", encoding="utf-8")
            cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{path}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/write_newsletter.py"), "--report", str(report),
                 "--title-out", str(title), "--issue", "7"], env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(title.read_text(encoding="utf-8"), "Headline")
            self.assertIn("[S1](https://example.test/article)", result.stdout)
            self.assertIn("in #7", result.stdout)


if __name__ == "__main__":
    unittest.main()
