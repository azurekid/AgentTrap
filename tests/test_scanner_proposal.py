import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import propose_scanner_update as proposer
from tools import publish_scanner_proposal as publisher

ROOT = Path(__file__).resolve().parents[1]


def task():
    return {
        "number": 123, "title": "Add a sourced regression", "state": "open",
        "labels": [{"name": proposer.APPROVAL_LABEL}],
        "body": "### Primary sources\nhttps://example.test/disclosure\n"
                "### Observable scanner signal\nMemory poisoning in AGENTS.md\n"
                "### Defanged positive example\nRemember this permanently.\n"
                "### Benign lookalike\nRemember to run tests before committing.\n",
    }


class ScannerProposalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "repo"
        self.root.mkdir()
        for name in (*proposer.CONTEXT_FILES, "SOURCES.md", "credential_rules.json", "allowlist.json"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "Base")
        self.issue = task()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def proposal_patch(self):
        sources = self.root / "SOURCES.md"
        sources.write_text(sources.read_text() + "\nRegression: https://example.test/disclosure\n")
        sample = self.root / "tests/test_approved_regression.py"
        sample.write_text(
            "import unittest\nfrom scan_agents_md import scan_file, DEFAULT_ALLOW\n\n"
            "class ApprovedRegression(unittest.TestCase):\n"
            "    def test_positive_and_benign(self):\n"
            "        for text, expected in [('Remember this permanently.', True), "
            "('Remember to run tests before committing.', False)]:\n"
            "            rules = {f['rule'] for f in scan_file('/repo/AGENTS.md', text, DEFAULT_ALLOW)}\n"
            "            self.assertEqual('MEMORY-POISONING' in rules, expected)\n"
        )
        self.git("add", "--intent-to-add", ".")
        diff = self.git("diff") + "\n"
        self.git("restore", "--staged", ".")
        self.git("restore", "SOURCES.md")
        sample.unlink()
        return diff

    def prepare(self, diff, output):
        proposer.prepare(self.issue, json.dumps({
            "decision": "propose", "summary": "Sourced regression with a benign lookalike.", "patch": diff,
        }), output, self.root)

    def test_approval_and_required_evidence(self):
        proposer.validate_issue(self.issue)
        for mutation in ({"labels": []}, {"state": "closed"}, {"pull_request": {}},
                         {"body": "Raw feed text"}, {"number": "../other"}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                proposer.validate_issue({**self.issue, **mutation})
        messages = proposer.build_prompt(self.issue, self.root)
        self.assertIn("You have no tools", messages[0]["content"])
        self.assertEqual(json.loads(messages[1]["content"])["approved_task"]["number"], 123)

    def test_path_and_metadata_guards(self):
        diff = self.proposal_patch()
        self.assertIn("SOURCES.md", proposer.validate_patch(diff, self.root))
        invalid = [
            diff.replace("SOURCES.md", ".github/workflows/evil.yml"),
            diff.replace("SOURCES.md", "../outside"),
            diff.replace("new file mode 100644", "new file mode 100755"),
            diff.replace("new file mode 100644", "new file mode 120000"),
            diff + "\nrename from a\nrename to b\n",
        ]
        for value in invalid:
            with self.subTest(value=value[:60]), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                proposer.validate_patch(value, self.root)

    def test_no_change_and_invalid_output(self):
        output = Path(self.directory.name) / "proposal"
        proposer.prepare(self.issue, json.dumps({"decision": "no_change", "summary": "Already covered."}),
                         output, self.root)
        self.assertFalse((output / "changes.patch").exists())
        self.assertIsNone(publisher.publish(output, "example/repo", self.root))
        for result in ({"decision": "wrong", "summary": "No"},
                       {"decision": "no_change", "summary": ""},
                       {"decision": "no_change", "summary": "No", "patch": "unexpected"}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                proposer.prepare(self.issue, json.dumps(result), output, self.root)

    def test_command_line_replays_a_saved_proposal(self):
        diff = self.proposal_patch()
        folder = Path(self.directory.name)
        issue_file, response_file = folder / "issue.json", folder / "response.json"
        issue_file.write_text(json.dumps(self.issue))
        response_file.write_text(json.dumps({
            "decision": "propose", "summary": "Add the approved regression.", "patch": diff,
        }))
        output = folder / "proposal"
        subprocess.run(
            [sys.executable, str(ROOT / "tools/propose_scanner_update.py"),
             "--issue-json", str(issue_file), "--response", str(response_file), "--output", str(output)],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        self.assertEqual((output / "changes.patch").read_text(), diff)
        self.assertEqual(json.loads((output / "proposal.json").read_text())["decision"], "propose")

    def test_end_to_end_patch_validation_and_draft_publication(self):
        diff = self.proposal_patch()
        output = Path(self.directory.name) / "proposal"
        self.prepare(diff, output)
        # Exercise the generated test against the real scanner, without executing fixture strings.
        subprocess.run(["git", "apply", "-"], cwd=self.root, input=diff, text=True, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests",
                        "-p", "test_approved_regression.py"], cwd=self.root, check=True)
        self.git("restore", "SOURCES.md")
        (self.root / "tests/test_approved_regression.py").unlink()
        for cache in (self.root / "__pycache__", self.root / "tests/__pycache__"):
            shutil.rmtree(cache)
        metadata = json.loads((output / "proposal.json").read_text())
        (output / "validated.json").write_text(json.dumps({
            "base": metadata["base"], "patch_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        }))
        origin = Path(self.directory.name) / "origin.git"
        subprocess.run(["git", "init", "--bare", "-q", str(origin)], check=True)
        self.git("remote", "add", "origin", str(origin))
        commands = []
        real_run = publisher.run

        def fake_github(*command, **kwargs):
            if command[0] != "gh":
                return real_run(*command, **kwargs)
            commands.append(command)
            if command[1] == "api":
                return json.dumps(self.issue)
            if command[1:3] == ("pr", "list"):
                return "[]"
            if command[1:3] == ("pr", "create"):
                return "https://github.com/example/repo/pull/456"
            self.fail(f"Unexpected GitHub command: {command}")

        with patch.object(publisher, "run", side_effect=fake_github), \
                patch.dict(os.environ, {"DEFAULT_BRANCH": "main"}):
            self.assertEqual(publisher.publish(output, "example/repo", self.root),
                             "https://github.com/example/repo/pull/456")
        create = next(command for command in commands if command[1:3] == ("pr", "create"))
        self.assertIn("--draft", create)
        self.assertEqual(create[create.index("--base") + 1], "main")
        self.assertEqual(self.git("branch", "--show-current"), "scanner-proposal/issue-123")
        self.assertIn("refs/heads/scanner-proposal/issue-123", self.git("ls-remote", "--heads", "origin"))
        self.assertIn("Co-authored-by: Copilot", self.git("log", "-1", "--format=%B"))

    def test_publication_rejects_task_edits_and_unvalidated_patches(self):
        output = Path(self.directory.name) / "proposal"
        diff = self.proposal_patch()
        self.prepare(diff, output)
        metadata = json.loads((output / "proposal.json").read_text())
        receipt = {"base": metadata["base"], "patch_sha256": "wrong"}
        (output / "validated.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "receipt"):
            publisher.publish(output, "example/repo", self.root)
        receipt["patch_sha256"] = hashlib.sha256(diff.encode()).hexdigest()
        (output / "validated.json").write_text(json.dumps(receipt))
        changed_issue = {**self.issue, "body": self.issue["body"] + "Edited"}
        with patch.object(publisher, "run", return_value=json.dumps(changed_issue)), \
                self.assertRaisesRegex(ValueError, "task changed"):
            publisher.publish(output, "example/repo", self.root)


if __name__ == "__main__":
    unittest.main()
