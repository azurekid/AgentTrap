"""Bounded text transformations only. Never evaluate, decompress or execute payloads."""
import base64
import binascii
import re
from collections import deque
from urllib.parse import unquote_to_bytes

from scan_agents_md import DEFAULT_ALLOW, scan_file

MAX_DEPTH = 3
MAX_CANDIDATES = 128
MAX_PAYLOADS = 32
MAX_DECODED_BYTES = 64 * 1024
PATTERNS = (
    ("base64", re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{24,8192}={0,2}(?![A-Za-z0-9+/_=-])")),
    ("hex", re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{32,8192}(?![A-Za-z0-9])")),
    ("hex_escape", re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,2048}")),
    ("percent", re.compile(r"[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{8,8192}")),
)


class PayloadInspector:
    def __init__(self, path: str):
        self.path = path
        self.candidates = 0
        self.payloads = 0
        self.decoded_bytes = 0
        self.limited = False

    @staticmethod
    def _decode(raw: str, encoding: str) -> tuple[str, str] | None:
        try:
            if encoding == "base64":
                data = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
                # PowerShell EncodedCommand uses UTF-16LE, unlike ordinary UTF-8 blobs.
                codec = "utf-16-le" if len(data) >= 8 and data[1::2].count(0) >= len(data[1::2]) * 0.6 else "utf-8"
            elif encoding == "percent":
                data, codec = unquote_to_bytes(raw), "utf-8"
            else:
                data, codec = bytes.fromhex(raw.replace("\\x", "")), "utf-8"
            decoded = data.decode(codec)
        except (binascii.Error, ValueError, UnicodeError):
            return None
        if not decoded or decoded == raw or "\x00" in decoded:
            return None
        if sum(c.isprintable() or c in "\n\r\t" for c in decoded) < len(decoded) * 0.95:
            return None
        return decoded, "base64/utf-16le" if codec == "utf-16-le" else encoding

    def inspect(self, text: str, json_pointer: str | None = None) -> list[dict]:
        findings = []
        queue = deque([(text, [], 0, 0)])
        while queue and not self.limited:
            current, chain, origin_line, origin_offset = queue.popleft()
            for encoding, pattern in PATTERNS:
                for match in pattern.finditer(current):
                    raw = match.group()
                    if encoding == "percent" and len(re.findall(r"%[0-9a-fA-F]{2}", raw)) < 2:
                        continue
                    if self.candidates >= MAX_CANDIDATES:
                        self.limited = True
                        break
                    self.candidates += 1
                    result = self._decode(raw, encoding)
                    if result is None:
                        continue
                    decoded, label = result
                    size = len(decoded.encode("utf-8"))
                    if len(chain) >= MAX_DEPTH or self.payloads >= MAX_PAYLOADS or self.decoded_bytes + size > MAX_DECODED_BYTES:
                        self.limited = True
                        break
                    self.payloads += 1
                    self.decoded_bytes += size
                    next_chain = [*chain, label]
                    line = origin_line if chain else current.count("\n", 0, match.start()) + 1
                    offset = origin_offset if chain else match.start()
                    for hit in scan_file("/repository/" + self.path, decoded, DEFAULT_ALLOW):
                        if hit["rule"] in {"BASE64-BLOB", "BASE64-PAYLOAD"}:
                            continue
                        hit["decoded_line"] = hit["line"]
                        hit["line"] = 0 if json_pointer is not None else line
                        hit["evidence_source"] = "decoded_payload"
                        hit["encoding_chain"] = next_chain
                        hit["encoded_offset"] = offset
                        if json_pointer is not None:
                            hit["json_pointer"] = json_pointer
                        findings.append(hit)
                    queue.append((decoded, next_chain, line, offset))
                if self.limited:
                    break
        return findings

    def summary(self) -> dict:
        return {
            "status": "incomplete" if self.limited else "complete",
            "candidates": self.candidates, "payloads": self.payloads,
            "decoded_bytes": self.decoded_bytes,
            "notes": ["Encoded-text inspection reached a depth, candidate, payload or byte limit."] if self.limited else [],
            "scope": "Bounded base64, UTF-16LE base64, hex, hex-escape and percent decoding; not all obfuscation formats.",
        }
