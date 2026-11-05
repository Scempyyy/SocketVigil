"""SocketVigil network socket inspection and privacy classification engine."""

import os
import re
import socket
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional


DNS_CACHE: Dict[str, str] = {
    "127.0.0.1": "localhost",
    "::1": "localhost",
    "0.0.0.0": "all-interfaces",
    "::": "all-interfaces",
}

KNOWN_TRACKING_PATTERNS = [
    r"telemetry",
    r"analytics",
    r"tracking",
    r"metrics",
    r"crashlytics",
    r"doubleclick",
    r"google-analytics",
    r"segment\.io",
    r"datadog",
    r"mixpanel",
    r"amplitude",
    r"bugsnag",
    r"sentry\.io",
]


@dataclass
class NetworkConnection:
    proto: str
    local_addr: str
    local_port: str
    remote_addr: str
    remote_port: str
    remote_host: str
    state: str
    process_name: str
    pid: str
    privacy_risk: str  # SAFE, TRACKING, INSECURE, ANOMALY
    risk_reason: str
    provider_tag: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def resolve_ip(ip: str) -> str:
    """Resolves IP to domain with local in-memory cache."""
    if not ip or ip in DNS_CACHE:
        return DNS_CACHE.get(ip, ip)

    # Local IP ranges
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127."):
        DNS_CACHE[ip] = "Private LAN"
        return "Private LAN"

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        DNS_CACHE[ip] = host
        return host
    except Exception:
        DNS_CACHE[ip] = ip
        return ip


def classify_provider(host: str) -> str:
    h = host.lower()
    if "1e100.net" in h or "google" in h or "gstatic" in h:
        return "Google Cloud / Services"
    elif "cloudflare" in h or "1.1.1.1" in h:
        return "Cloudflare CDN"
    elif "amazonaws" in h or "aws" in h:
        return "Amazon Web Services"
    elif "microsoft" in h or "azure" in h:
        return "Microsoft Azure"
    elif "github" in h:
        return "GitHub / Fastly"
    elif "Private LAN" in h or "localhost" in h:
        return "Local Workstation / LAN"
    return "External Host"


def scan_network_connections() -> List[NetworkConnection]:
    """Captures and classifies active TCP/UDP network connections."""
    conns: List[NetworkConnection] = []

    try:
        proc = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=2.5)
        raw_output = proc.stdout
    except Exception:
        return []

    lines = raw_output.splitlines()
    if len(lines) <= 1:
        return []

    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) < 5:
            continue

        proto = parts[0].upper()
        state = parts[1].upper() if len(parts) >= 6 else "UNKNOWN"
        local = parts[4] if len(parts) >= 6 else parts[3]
        remote = parts[5] if len(parts) >= 6 else parts[4]

        proc_info = parts[6] if len(parts) >= 7 else (parts[5] if len(parts) >= 6 else "")

        # Extract process name & pid: users:(("chrome",pid=1234,fd=5))
        pname = "System / Kernel"
        pid = "-"
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc_info)
        if m:
            pname = m.group(1)
            pid = m.group(2)
        elif "pid=" in proc_info:
            m2 = re.search(r'pid=(\d+)', proc_info)
            if m2:
                pid = m2.group(1)

        # Parse local address & port
        l_parts = local.rsplit(":", 1)
        l_addr = l_parts[0]
        l_port = l_parts[1] if len(l_parts) > 1 else ""

        # Parse remote address & port
        r_parts = remote.rsplit(":", 1)
        r_addr = r_parts[0]
        r_port = r_parts[1] if len(r_parts) > 1 else ""

        if r_addr in ("*", "0.0.0.0", "::") and state == "LISTEN":
            r_host = "Listening Port"
        else:
            r_host = resolve_ip(r_addr)

        # Privacy Evaluation
        privacy_risk = "SAFE"
        risk_reason = "Normal encrypted traffic"
        provider = classify_provider(r_host)

        # Check tracking
        for pattern in KNOWN_TRACKING_PATTERNS:
            if re.search(pattern, r_host, re.IGNORECASE):
                privacy_risk = "TRACKING"
                risk_reason = f"Outbound connection to telemetry endpoint ({pattern})"
                break

        # Check insecure HTTP (port 80)
        if r_port == "80" and state != "LISTEN":
            privacy_risk = "INSECURE"
            risk_reason = "Unencrypted plaintext HTTP connection (Port 80)"

        conns.append(
            NetworkConnection(
                proto=proto,
                local_addr=l_addr,
                local_port=l_port,
                remote_addr=r_addr,
                remote_port=r_port,
                remote_host=r_host,
                state=state,
                process_name=pname,
                pid=pid,
                privacy_risk=privacy_risk,
                risk_reason=risk_reason,
                provider_tag=provider,
            )
        )

    return conns
