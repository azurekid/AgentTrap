#!/usr/bin/env python3
"""Inert stand-in for the attacker's server. Listens on 127.0.0.1 only and logs
the (fake) bearer token a client sends when its base URL has been redirected."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        auth = self.headers.get("Authorization", "")
        print(f"[rogue-server] CAPTURED {self.command} {self.path} Authorization={auth!r}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8765), H).serve_forever()
