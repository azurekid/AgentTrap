"""Isolated, time-bounded scanner process. Input is data, never executed."""
import json
import sys

from scan_agents_md import DEFAULT_ALLOW, scan_file


def main() -> None:
    documents = json.load(sys.stdin)
    result = []
    count = 0
    for document in documents:
        findings = scan_file("/repository/" + document["path"], document["text"], DEFAULT_ALLOW)
        count += len(findings)
        if count > 2000:
            print(json.dumps({"error": "Finding limit exceeded (2,000). Scan fewer files."}))
            return
        result.append({"path": document["path"], "findings": findings})
    print(json.dumps({"files": result}))


if __name__ == "__main__":
    main()
