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
            self.assertIn("See [Example](https://example.test/article).", output.getvalue())
            self.assertIn("- [Example](https://example.test/article) (2026-11-12, Source)", output.getvalue())
            self.assertNotIn("[S1]", output.getvalue())
            self.assertIn("in #7", output.getvalue())

    def test_writer_executes_copilot_and_creates_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            report, title, html, cli = (path / name for name in ("report.md", "title.txt", "newsletter.html", "copilot"))
            report.write_text("### Research\n- [ ] Example (2026-11-12) - Source\n"
                              "  https://example.test/article(a)?b=1&c=2\n", encoding="utf-8")
            cli.write_text("#!/bin/sh\nprintf '# Headline\\n\\n**TL;DR**\\n\\n- See [S1][S99].\\n\\n"
                           "## Defender checklist\\n- [ ] Review the report [S1].\\n'\n", encoding="utf-8")
            cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{path}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/write_newsletter.py"), "--report", str(report),
                 "--title-out", str(title), "--issue", "7", "--html-out", str(html)],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(title.read_text(encoding="utf-8"), "Headline")
            self.assertIn("[Example](<https://example.test/article(a)?b=1&amp;c=2>)", result.stdout)
            self.assertIn("in #7", result.stdout)
            html_text = html.read_text(encoding="utf-8")
            self.assertIn('<svg class="radar"', html_text)
            self.assertEqual(html_text.count("<h1>Headline</h1>"), 1)
            self.assertIn("<h2>TL;DR</h2>", html_text)
            self.assertIn('<a href="https://example.test/article(a)?b=1&amp;c=2">Example</a>', html_text)
            self.assertIn('type="checkbox"', html_text)
            self.assertIn("in #7", html_text)
            for output in (result.stdout, html_text):
                self.assertNotRegex(output, r"\[S\d+\]")

    def test_only_approved_links_and_escaped_report_metadata_in_html(self):
        items = write_newsletter.parse_report(
            "### Research\n- [ ] Invalid (2026-11-12) - Source\n"
            "  https://user@example.test/hidden\n"
            "- [ ] Example [lab] *study* <em> (2026-11-12) - <img src=x>\n"
            "  https://example.test/article\n"
        )
        self.assertEqual(len(items), 1)
        narrative = write_newsletter.sanitise(
            "# Headline [S2]\n\nSee [S2][S999].\n\n"
            "[label][ref]\n\n[ref]: https://other.test\n\n![S2]\n",
            items,
        )
        body = write_newsletter.compose(narrative, items)
        html = write_newsletter.render_html(
            body + "\n[unexpected](/local) <script>example</script>\n",
            items, "<Headline>", "2026-11-12",
        )
        self.assertEqual(write_newsletter.headline(narrative), "Headline")
        self.assertEqual(html.count('<a href="https://example.test/article">Example [lab] *study* &lt;em&gt;</a>'), 3)
        self.assertIn("<title>&lt;Headline&gt; | Agent Security Weekly</title>", html)
        self.assertIn("&lt;img src=x&gt;", html)
        self.assertNotIn('href="/local"', html)
        self.assertNotIn("other.test", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("[S999]", html)


if __name__ == "__main__":
    unittest.main()
