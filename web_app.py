import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src.generator import PasswordGenerationError
from src.web import HTML, generate_payload


HOST = "127.0.0.1"
PORT = 8000


class PasswordWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(HTML)
            return
        if parsed.path == "/api/generate":
            self._send_generation(parsed.query)
            return
        self.send_error(404, "Not found")

    def log_message(self, format, *args):
        return

    def _send_html(self, html):
        payload = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload, status=200):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_generation(self, query):
        params = parse_qs(query)

        try:
            self._send_json(generate_payload(params))
        except (PasswordGenerationError, ValueError) as error:
            self._send_json({"error": str(error)}, status=400)


def main():
    server = ThreadingHTTPServer((HOST, PORT), PasswordWebHandler)
    print(f"Open http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
