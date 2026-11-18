#!/usr/bin/env python3
# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Loopback-only sink standing in for webhook[.]site (docs/TDS.md §4).
# Binds 127.0.0.1 only. Asserts the payload shape (zlib+base64 JSON) and
# records one JSONL receipt per POST. Stdlib only.
# ============================================================================
import base64
import json
import os
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECEIPTS = os.environ.get("AF_SINK_RECEIPTS", "/tmp/af-sink-receipts.jsonl")
PORT = int(os.environ.get("AF_SINK_PORT", "8099"))


class SinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet; receipts are the record
        pass

    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"ok": true}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        receipt = {
            "time": self.log_date_time_string(),
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "body_b64": base64.b64encode(raw).decode("ascii"),
            "payload_ok": False,
            "payload_keys": [],
        }
        try:
            # Incident shape: the POST body is base64(zlib(JSON)) text.
            doc = json.loads(zlib.decompress(base64.b64decode(raw)).decode("utf-8"))
            receipt["payload_ok"] = isinstance(doc, dict)
            receipt["payload_keys"] = sorted(doc.keys()) if isinstance(doc, dict) else []
        except Exception:
            receipt["payload_ok"] = False
        with open(RECEIPTS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt) + "\n")
        # The real endpoint returned 200; the sink mirrors that acceptance.
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", PORT), SinkHandler) as httpd:
        httpd.serve_forever()
