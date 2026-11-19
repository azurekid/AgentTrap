import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path
from unittest.mock import patch

from tools import publish_newsletter, write_newsletter
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
            args = ["write_newsletter.py", "--report", str(report), "--title-out", str(title)]
            with patch.object(sys, "argv", args), \
                    patch.object(write_newsletter, "call_model", return_value="# Headline\nSee [S1].") as model, \
                    redirect_stdout(output):
                self.assertEqual(write_newsletter.main(), 0)
            self.assertEqual(len(model.call_args.args[0]), 2)
            self.assertEqual(title.read_text(encoding="utf-8"), "Headline")
            self.assertIn('See ([Source](https://example.test/article "Example")).', output.getvalue())
            self.assertIn("- [Example](https://example.test/article) (2026-11-12, Source)", output.getvalue())
            self.assertNotIn("[S1]", output.getvalue())
            self.assertIn("**END OF TRANSMISSION //** Verify the signal. Defend the perimeter.", output.getvalue())
            self.assertNotIn("Drafted by AI", output.getvalue())

    def test_writer_executes_copilot_and_creates_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            report, title, html, cli = (path / name for name in ("report.md", "title.txt", "newsletter.html", "copilot"))
            report.write_text("### Research\n- [ ] Example (2026-11-12) - Source\n"
                              "  https://example.test/article(a)?b=1&c=2\n", encoding="utf-8")
            cli.write_text("#!/bin/sh\nprintf '# Stolen keys put agents at risk: what this means for teams running coding agents"
                           "\\n\\n**TL;DR**\\n\\n- See [S1][S99].\\n\\n"
                           "## Top stories\\n\\n### Supply chain\\n\\n#### Check old keys\\n\\n"
                           "**Threat level:** High. Rotate them.\\n\\n"
                           "## Defender checklist\\n- [ ] Review the report [S1].\\n'\n", encoding="utf-8")
            cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{path}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/write_newsletter.py"), "--date", "2026-11-18", "--report", str(report),
                 "--title-out", str(title), "--html-out", str(html)],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(title.read_text(encoding="utf-8"), "Stolen keys put agents at risk")
            self.assertTrue(result.stdout.startswith("# Stolen keys put agents at risk\n\n"))
            self.assertNotIn("what this means", result.stdout)
            self.assertIn("[Example](<https://example.test/article(a)?b=1&amp;c=2>)", result.stdout)
            html_text = html.read_text(encoding="utf-8")
            self.assertIn('<svg class="radar"', html_text)
            self.assertEqual(html_text.count("<h1>Stolen keys put agents at risk</h1>"), 1)
            self.assertIn('class="radar-target"', html_text)
            self.assertIn("<h2>TL;DR</h2>", html_text)
            self.assertIn("<h2>Top stories</h2>", html_text)
            self.assertIn("### Supply chain\n\n#### Check old keys", result.stdout)
            self.assertIn("<h3>Supply chain</h3>\n<h4>Check old keys</h4>", html_text)
            self.assertIn('<p class="threat high">', html_text)
            self.assertIn('<svg class="logo"', html_text)
            self.assertIn('<span class="cites"><a href="https://example.test/article(a)?b=1&amp;c=2" '
                          'title="Example">Source</a></span>', html_text)
            self.assertIn('<a href="https://example.test/article(a)?b=1&amp;c=2">Example</a>', html_text)
            self.assertIn('type="checkbox"', html_text)
            self.assertIn("<strong>END OF TRANSMISSION //</strong> Verify the signal. Defend the perimeter.", html_text)
            self.assertNotIn("Pause radar", html_text)
            for output in (result.stdout, html_text):
                self.assertNotRegex(output, r"\[S\d+\]")

            web = path / "web"
            static = web / "static"
            static.mkdir(parents=True)
            manifest = web / "publications.json"
            old = {"issue": 20, "title": "Earlier edition", "date": "2026-11-11", "summary": "Earlier news"}
            news = {"id": "curated-link", "title": "Curated news"}
            manifest.write_text(json.dumps({"editions": [old], "news": [news]}), encoding="utf-8")
            day = date(2026, 11, 18)
            headline = title.read_text(encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                publish_newsletter.publish(web, 25, headline, date(2026, 11, 19), html_text)
            publish_newsletter.publish(web, 25, headline, day, html_text)
            publish_newsletter.publish(web, 25, headline, day, html_text)
            snapshot = static / "newsletter-issue-25.html"
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                publish_newsletter.publish(web, 25, headline, day, html_text + "\n")
            self.assertEqual(snapshot.read_text(encoding="utf-8"), html_text)
            saved = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(saved["news"], [news])
            self.assertEqual(saved["editions"][0], old)
            self.assertEqual(len(saved["editions"]), 2)
            self.assertEqual(saved["editions"][1]["date"], day.isoformat())
            self.assertEqual(saved["editions"][1]["title"], headline)

    def test_long_headline_breaks_at_a_word_boundary(self):
        text = "# Stolen keys show why coding agents need tighter permissions"
        self.assertEqual(write_newsletter.headline(text), "Stolen keys show why coding agents need tighter")

    def test_grouped_citations_and_em_dashes_in_both_editions(self):
        url = "https://example.test/keys\u2014update"
        items = write_newsletter.parse_report(
            "### Research\n- [ ] Key update \u2014 notice (2026-11-12) - Press &mdash; Team\n"
            f"  {url}\n- [ ] Tool update (2026-11-12) - Blog\n"
            "  https://example.test/tools\n"
        )
        narrative = write_newsletter.sanitise(
            "# Weekly\u2014update\n\nCheck your keys &#x2014; see [S1, S2, S999].", items,
        )
        markdown = write_newsletter.compose(narrative, items)
        title = write_newsletter.headline(narrative)
        html = write_newsletter.render_html(markdown, items, title, "2026-11-12")
        for output in (title, markdown, html):
            self.assertNotIn("\u2014", output)
            self.assertNotRegex(output, r"\bS(?:1|2|999)\b")
        self.assertIn("Weekly - update", title)
        self.assertIn("Check your keys - see", html)
        self.assertIn("Press - Team", html)
        self.assertIn(
            '<span class="cites"><a href="https://example.test/keys%E2%80%94update" '
            'title="Key update - notice">Press - Team</a> '
            '<a href="https://example.test/tools" title="Tool update">Blog</a></span>', html,
        )

    def test_citations_use_short_labels_and_reading_list_titles_are_trimmed(self):
        items = write_newsletter.parse_report(
            f"### Advisory\n- [ ] CVE-2026-0001: {'long text ' * 30}(2026-11-12) - NVD CVEs\n"
            "  https://example.test/cve\n"
            "### Discovery\n- [ ] Agent bug found - Example News (2026-11-12) - Discovery: write-ups\n"
            "  https://example.test/lead\n"
        )
        markdown = write_newsletter.compose(write_newsletter.sanitise("Patch now [S1] [S2][S1].", items), items)
        self.assertIn('Patch now ([CVE\\-2026\\-0001](https://example.test/cve "CVE\\-2026\\-0001\\: long text', markdown)
        self.assertIn(', [Example News](https://example.test/lead "Agent bug found \\- Example News")).', markdown)
        self.assertEqual(markdown.count("](https://example.test/cve"), 2)
        self.assertIn("- [Agent bug found](https://example.test/lead) (2026-11-12, Example News)", markdown)
        self.assertRegex(markdown, r"(?m)^- \[CVE\\-2026\\-0001\\: (long text ){9}long\\\.\\\.\\\.\]\(")

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
        self.assertEqual(html.count('<a href="https://example.test/article">Example [lab] *study* &lt;em&gt;</a>'), 1)
        self.assertEqual(html.count('<a href="https://example.test/article" '
                                    'title="Example [lab] *study* &lt;em&gt;">&lt;img src=x&gt;</a>'), 2)
        self.assertIn("<title>&lt;Headline&gt; | Agent Security Weekly</title>", html)
        self.assertIn("&lt;img src=x&gt;", html)
        self.assertNotIn('href="/local"', html)
        self.assertNotIn("other.test", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("[S999]", html)


if __name__ == "__main__":
    unittest.main()
