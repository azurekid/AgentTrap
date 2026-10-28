"""Isolated, time-bounded scanner process. Input is data, never executed."""
import json
import sys

from scan_agents_md import DEFAULT_ALLOW, scan_file
from web.decoding import PayloadInspector
from web.mcp import inspect_mcp


def main() -> None:
    documents = json.load(sys.stdin)
    result = []
    count = 0
    for document in documents:
        findings = scan_file("/repository/" + document["path"], document["text"], DEFAULT_ALLOW)
        payloads = PayloadInspector(document["path"])
        findings.extend(payloads.inspect(document["text"]))
        structured, mcp = inspect_mcp(document["path"], document["text"], payloads)
        findings.extend(structured)
        # A decoded secret may share the same original physical line with other evidence.
        if any(f["rule"].startswith("SECRET-") for f in findings):
            for hit in findings:
                hit["snippet"] = "[REDACTED: file contains potential credential]"
        count += len(findings)
        if count > 2000:
            print(json.dumps({"error": "Finding limit exceeded (2,000). Scan fewer files."}))
            return
        result.append({"path": document["path"], "findings": findings, "mcp": mcp, "decoding": payloads.summary()})
    print(json.dumps({"files": result}))


if __name__ == "__main__":
    main()
