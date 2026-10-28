"""Inspect saved MCP tool definitions as data, never connect to or execute a server."""
import json

from scan_agents_md import DEFAULT_ALLOW, scan_file
from web.decoding import PayloadInspector

MAX_TOOLS = 500
MAX_NODES = 4000
MAX_DEPTH = 32


def inspect_mcp(path: str, text: str, payloads: PayloadInspector | None = None) -> tuple[list[dict], dict]:
    if not path.lower().endswith(".json"):
        return [], {"status": "not_applicable", "tools": 0, "observations": []}
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return [], {"status": "not_parsed", "tools": 0, "observations": [
            {"kind": "parse", "message": "Strict JSON parsing unavailable; raw-text rules still ran."},
        ]}
    root = "/result" if isinstance(value, dict) and isinstance(value.get("result"), dict) else ""
    container = value["result"] if root else value
    if not isinstance(container, dict) or "tools" not in container:
        return [], {"status": "not_applicable", "tools": 0, "observations": []}
    tools = container["tools"]
    if not isinstance(tools, list):
        return [], {"status": "incomplete", "tools": 0, "observations": [
            {"kind": "schema", "pointer": root + "/tools", "message": "tools must be an array of tool definitions."},
        ]}
    findings, observations = [], []
    payloads = payloads or PayloadInspector(path)
    status = "complete"
    nodes = 0
    inspected = 0

    def observe(kind: str, pointer: str, message: str) -> None:
        observations.append({"kind": kind, "pointer": pointer, "message": message})

    def walk(item, pointer: str, depth: int) -> None:
        nonlocal nodes, status
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            status = "incomplete"
            return
        if isinstance(item, str):
            for hit in scan_file("/repository/" + path, item, DEFAULT_ALLOW):
                hit["line"] = 0
                hit["json_pointer"] = pointer
                hit["evidence_source"] = "decoded_json"
                findings.append(hit)
            findings.extend(payloads.inspect(item, pointer))
        elif isinstance(item, dict):
            for key, child in item.items():
                if nodes > MAX_NODES:
                    break
                escaped = key.replace("~", "~0").replace("/", "~1")
                walk(child, pointer + "/" + escaped, depth + 1)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                if nodes > MAX_NODES:
                    break
                walk(child, f"{pointer}/{index}", depth + 1)

    names = set()
    for index, tool in enumerate(tools[:MAX_TOOLS]):
        pointer = f"{root}/tools/{index}"
        if not isinstance(tool, dict):
            status = "incomplete"
            observe("schema", pointer, "Tool definition must be an object.")
            continue
        inspected += 1
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            observe("schema", pointer + "/name", "Tool name must be a nonempty string.")
        elif name in names:
            observe("schema", pointer + "/name", "Duplicate tool name in this snapshot; resolve which definition is exposed.")
        else:
            names.add(name)
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            observe("schema", pointer + "/inputSchema", "Expected an object inputSchema. This is a structure observation, not proof of unsafe execution.")
        else:
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list) or any(
                not isinstance(key, str) or key not in properties for key in required
            ):
                observe("schema", pointer + "/inputSchema", "properties/required are inconsistent; verify the schema with a JSON Schema validator.")
            if isinstance(properties, dict):
                for key in properties:
                    if key.lower() in {"password", "token", "api_key", "secret", "credential"}:
                        escaped = key.replace("~", "~0").replace("/", "~1")
                        observe("sensitive_input", pointer + "/inputSchema/properties/" + escaped,
                                "Sensitive-input name: review collection, logging and retention. The name alone is not a vulnerability; format annotations do not enforce redaction.")
        walk(tool, pointer, 0)
        if nodes > MAX_NODES:
            break
    if len(tools) > MAX_TOOLS:
        status = "incomplete"
    if container.get("nextCursor") is not None:
        status = "incomplete"
        observe("coverage", root + "/nextCursor", "This saved tools/list page has a continuation cursor. Other pages were not inspected.")
    if status == "incomplete":
        observe("coverage", root + "/tools", "Structured inspection is incomplete (pagination, invalid structure or tool/depth/node limits). No server was contacted.")
    return findings, {"status": status, "tools": inspected, "observations": observations}
