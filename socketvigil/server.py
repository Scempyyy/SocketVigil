"""SocketVigil Web Console HTTP Server."""

import http.server
import json
import os
import socketserver
import urllib.parse
from socketvigil.mapper import scan_network_connections


WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


class SocketVigilHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"service": "SocketVigil", "status": "active"}).encode("utf-8"))
            return

        elif parsed.path == "/api/connections":
            conns = scan_network_connections()
            unique_apps = sorted(list({c.process_name for c in conns if c.process_name != "-"}))
            tracking_count = sum(1 for c in conns if c.privacy_risk == "TRACKING")
            insecure_count = sum(1 for c in conns if c.privacy_risk == "INSECURE")

            res = {
                "total_sockets": len(conns),
                "unique_apps_count": len(unique_apps),
                "unique_apps": unique_apps,
                "tracking_endpoints": tracking_count,
                "insecure_endpoints": insecure_count,
                "connections": [c.to_dict() for c in conns],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        super().do_GET()


def start_socketvigil_server(host: str = "127.0.0.1", port: int = 8999):
    class ReuseAddressServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReuseAddressServer((host, port), SocketVigilHTTPHandler) as httpd:
        print(f"\n🌐 SocketVigil Privacy Map live at http://{host}:{port}")
        print("Press Ctrl+C to terminate.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer terminated cleanly.")
