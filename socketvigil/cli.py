"""SocketVigil Command Line Interface."""

import argparse
import json
import sys
from socketvigil.mapper import scan_network_connections
from socketvigil.server import start_socketvigil_server


def main():
    parser = argparse.ArgumentParser(
        prog="socketvigil",
        description="SocketVigil: Real-Time Application Network Privacy Map & Telemetry Interceptor.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # MAP command
    map_parser = subparsers.add_parser("map", help="Scan and display active application network connections")
    map_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # APPS command
    subparsers.add_parser("apps", help="List all applications currently holding open network sockets")

    # SERVE command
    serve_parser = subparsers.add_parser("serve", help="Launch interactive SocketVigil web dashboard")
    serve_parser.add_argument("--port", type=int, default=8999, help="Port to bind (default: 8999)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")

    args = parser.parse_args()

    if args.command == "serve" or args.command is None:
        port = getattr(args, "port", 8999)
        host = getattr(args, "host", "127.0.0.1")
        start_socketvigil_server(host=host, port=port)

    elif args.command == "map":
        conns = scan_network_connections()
        if args.json:
            print(json.dumps([c.to_dict() for c in conns], indent=2))
        else:
            print(f"\n🌐 SocketVigil: {len(conns)} Active Sockets Mapped\n")
            print(f"{'VERDICT':<10} | {'APPLICATION':<20} | {'PROTO':<5} | {'REMOTE DESTINATION'}")
            print("-" * 80)
            for c in conns[:40]:
                print(f"{c.privacy_risk:<10} | {c.process_name[:20]:<20} | {c.proto:<5} | {c.remote_host} ({c.remote_addr}:{c.remote_port})")
            print("-" * 80)

    elif args.command == "apps":
        conns = scan_network_connections()
        apps = sorted(list({c.process_name for c in conns if c.process_name != "-"}))
        print(f"\n📡 {len(apps)} Applications Communicating on Network:\n")
        for app in apps:
            count = sum(1 for c in conns if c.process_name == app)
            print(f"• {app:<25} ({count} active sockets)")


if __name__ == "__main__":
    main()
