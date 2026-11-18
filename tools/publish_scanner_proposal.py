"""Publish a validated scanner patch as a draft PR, without running proposed code."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

try:
    from .propose_scanner_update import ROOT, issue_digest, validate_issue, validate_patch
except ImportError:
    from propose_scanner_update import ROOT, issue_digest, validate_issue, validate_patch


def run(*command, root=ROOT, **kwargs):
    return subprocess.check_output(command, cwd=root, text=True, **kwargs).strip()


def publish(directory, repo, root=ROOT):
    metadata = json.loads((directory / "proposal.json").read_text(encoding="utf-8"))
    if metadata["decision"] == "no_change":
        print("No draft PR: the finding requires no scanner change. See the proposal artifact.")
        return None
    patch = (directory / "changes.patch").read_text(encoding="utf-8")
    receipt = json.loads((directory / "validated.json").read_text(encoding="utf-8"))
    if receipt != {"base": metadata["base"], "patch_sha256": hashlib.sha256(patch.encode()).hexdigest()}:
        raise ValueError("Validation receipt does not match the proposal")
    issue = json.loads(run("gh", "api", f"repos/{repo}/issues/{metadata['issue']}", root=root))
    validate_issue(issue)
    if issue_digest(issue) != metadata["issue_digest"]:
        raise ValueError("Approved task changed after generation; review and rerun")
    if run("git", "rev-parse", "HEAD", root=root) != metadata["base"]:
        raise ValueError("Default branch changed after generation; rerun against the new base")
    if run("git", "status", "--porcelain", root=root):
        raise ValueError("Publishing requires a clean checkout")
    paths = validate_patch(patch, root)
    branch = f"scanner-proposal/issue-{issue['number']}"
    existing = json.loads(run("gh", "pr", "list", "--repo", repo, "--state", "open",
                              "--head", branch, "--json", "url", root=root))
    if existing:
        print(f"Existing proposal left unchanged: {existing[0]['url']}")
        return existing[0]["url"]
    # Never overwrite an earlier proposal branch, even if its PR has been closed.
    if run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}", root=root):
        raise ValueError("A proposal branch already exists; delete it after review before rerunning")
    run("git", "switch", "-c", branch, root=root)
    subprocess.run(["git", "apply", "--index", "-"], cwd=root, input=patch, text=True, check=True)
    staged = run("git", "diff", "--cached", "--name-only", root=root).splitlines()
    if sorted(staged) != sorted(paths):
        raise ValueError("Staged files differ from the validated proposal")
    run("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", f"Propose scanner regression update for #{issue['number']}\n\n"
        "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>", root=root)
    run("git", "-c", "core.hooksPath=/dev/null", "push", "--no-verify", "origin", f"HEAD:refs/heads/{branch}", root=root)
    body = (
        f"Source issue: #{issue['number']} (left open for review).\n\n"
        "Tool-free model proposal from a maintainer-approved task. Validation completed in a separate "
        "job without publishing credentials: Python tests, generated-table check, and PowerShell tests.\n\n"
        "Review source support, detection scope, positive fixtures and benign lookalikes before marking "
        "ready. This pipeline does not merge or deploy. The proposal artifact contains the model's rationale.\n\n"
        "Actions checks may need to be started manually because this PR is opened with GITHUB_TOKEN.\n"
    )
    url = run("gh", "pr", "create", "--repo", repo, "--draft", "--base",
              os.environ.get("DEFAULT_BRANCH", "main"), "--head", branch,
              "--title", f"Scanner proposal for research issue #{issue['number']}",
              "--body", body, root=root)
    print(url)
    return url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    args = parser.parse_args()
    publish(args.proposal, args.repo)


if __name__ == "__main__":
    main()
