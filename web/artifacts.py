"""Content-addressed inspected snapshots; never infer package completeness from uploads."""
import hashlib
import json
import re
from pathlib import PurePosixPath

import yaml

from scan_agents_md import DEFAULT_ALLOW, scan_file

IDENTITY_VERSION = "artifact-v1"


def frontmatter_name(text: str) -> tuple[str | None, str | None]:
    lines = text.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None
    end = next((index for index, line in enumerate(lines[1:65], 1) if line.strip() in ("---", "...")), None)
    if end is None or sum(len(line) for line in lines[:end]) > 8192:
        return None, "Frontmatter name unavailable: header is unclosed or exceeds metadata limits."
    header = "\n".join(lines[1:end])
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(header), 1):
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if count > 512 or depth > 16 or isinstance(event, yaml.AliasEvent):
                return None, "Frontmatter name unavailable: metadata complexity exceeds supported limits."
        metadata = yaml.safe_load(header)
    except yaml.YAMLError:
        return None, "Frontmatter name unavailable: invalid YAML metadata."
    if not isinstance(metadata, dict) or "name" not in metadata:
        return None, None
    name = metadata["name"]
    if (not isinstance(name, str) or not name.strip() or len(name) > 160
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        return None, "Frontmatter name unavailable: expected a single-line text value of at most 160 characters."
    if any(hit["rule"].startswith("SECRET-") or hit["rule"] in ("AUTH-HEADER", "OAUTH-TOKEN", "URL-CREDENTIALS")
           for hit in scan_file("AGENTS.md", name, DEFAULT_ALLOW)):
        return None, "Frontmatter name withheld: possible embedded credential."
    return name.strip(), None


def identity(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def identify(files: list[dict], documents: list[dict[str, str]], detector: str, partial: bool,
             scan_options: dict) -> list[dict]:
    docs = {d["path"]: d for d in documents}
    roots = {str(PurePosixPath(p).parent): p for p in docs if PurePosixPath(p).name.lower() == "skill.md"}
    members: dict[str, list[str]] = {root: [] for root in roots}
    standalone = []
    for path in docs:
        parents = [root for root in roots if root == "." or path.startswith(root + "/")]
        if parents:
            members[max(parents, key=lambda root: 0 if root == "." else len(root))].append(path)
        else:
            standalone.append(path)
    groups = [(root, paths, "skill_snapshot", roots[root]) for root, paths in members.items()]
    mcp_paths = {f["path"] for f in files if f.get("mcp", {}).get("status") in ("complete", "incomplete")}
    groups += [(path, [path], "mcp_snapshot" if path in mcp_paths else "agent_file", None) for path in standalone]
    artifacts = []
    file_results = {f["path"]: f for f in files}
    for root, paths, kind, skill_path in sorted(groups):
        manifest = []
        relatives = {}
        for path in sorted(paths):
            doc = docs[path]
            relative = str(PurePosixPath(path).relative_to(root)) if kind == "skill_snapshot" and root != "." else path
            if kind != "skill_snapshot":
                relative = PurePosixPath(path).name
            relatives[path] = relative
            content = doc["text"].encode("utf-8")
            manifest.append({
                "path": relative, "sha256": doc.get("raw_sha256") or hashlib.sha256(content).hexdigest(),
                "bytes": int(doc.get("raw_bytes", len(content))),
                "mode": doc.get("mode", "unknown"),
            })
        complete = bool(skill_path and docs[skill_path].get("package_complete") == "true" and not partial)
        coverage_notes = []
        if skill_path:
            relative_paths = {item["path"] for item in manifest}
            for path in paths:
                for reference in re.findall(r"\b(?:scripts|references|assets)/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+", docs[path]["text"]):
                    if reference not in relative_paths:
                        coverage_notes.append(f"Referenced path not in inspected snapshot: {reference}")
            if coverage_notes:
                complete = False
            if any(other != root and (root == "." or other.startswith(root + "/")) for other in roots):
                complete = False
                coverage_notes.append("Nested skill packages are evaluated separately; the parent is not claimed complete.")
        content_id = identity({"version": IDENTITY_VERSION, "kind": kind, "files": manifest,
                               "hash_scope": "raw" if all(docs[p].get("raw_sha256") for p in paths) else "inspected_text"})
        evaluation_id = identity({"artifact": content_id, "detector": detector, "options": scan_options,
                                  "package_complete": complete, "scan_partial": partial})
        artifact = {
            "kind": kind, "root": root, "content_id": content_id, "evaluation_id": evaluation_id,
            "package_complete": complete, "files": manifest,
            "coverage_notes": sorted(set(coverage_notes)),
            "scope": "complete supported skill package" if complete else "inspected snapshot only; not a complete package claim",
        }
        name_path = skill_path or (paths[0] if PurePosixPath(paths[0]).suffix.lower() in (".md", ".mdc") else None)
        name, warning = frontmatter_name(docs[name_path]["text"]) if name_path else (None, None)
        artifact["name"] = name
        artifact["name_source"] = "frontmatter.name" if name else None
        if warning:
            artifact["coverage_notes"].append(warning)
        artifacts.append(artifact)
        for path in paths:
            file = file_results[path]
            file["artifact_id"] = content_id
            occurrences = {}
            for hit in file["findings"]:
                location = (hit["rule"], hit["line"], hit.get("json_pointer"), hit.get("evidence_source", "raw"),
                            hit.get("encoded_offset"), hit.get("decoded_line"), tuple(hit.get("encoding_chain", [])))
                occurrences[location] = occurrences.get(location, 0) + 1
                hit["id"] = identity({
                    "evaluation": evaluation_id, "path": relatives[path], "rule": hit["rule"],
                    "line": hit["line"], "pointer": hit.get("json_pointer"), "source": hit.get("evidence_source", "raw"),
                    "occurrence": occurrences[location],
                    **{key: hit[key] for key in ("encoded_offset", "decoded_line", "encoding_chain") if key in hit},
                })
    return artifacts
