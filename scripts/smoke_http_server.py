"""Bounded local HTTP endpoint for the harmless Foxhole fixture."""
import argparse
import ipaddress
import re
from http.server import BaseHTTPRequestHandler, HTTPServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("token")
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.address)
    if not address.is_private or address.is_loopback or not 1 <= args.port <= 65534:
        parser.error("A private host-service IPv4 address and port are required")
    if not re.fullmatch("[0-9a-f]{32}", args.token):
        parser.error("Invalid smoke token")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def do_GET(self):
            if self.path not in ("/health", "/health?foxhole_smoke=" + args.token):
                self.send_error(404)
                return
            body = ("FOXHOLE_SMOKE_HTTP " + args.token + "\n").encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    with HTTPServer((str(address), args.port), Handler) as server:
        server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
