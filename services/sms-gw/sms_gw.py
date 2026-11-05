"""Simulated cellular SMS gateway. Stands in for the 4G modem: records messages, sends nothing."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from vlog import log


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        log("vilaaurora-sms", f"site={body.get('site')} source={self.client_address[0]} text={body.get('text')!r}")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
