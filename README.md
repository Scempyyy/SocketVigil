# 🌐 SocketVigil

[![CI](https://github.com/Scempyyy/SocketVigil/actions/workflows/ci.yml/badge.svg)](https://github.com/Scempyyy/SocketVigil/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#zero-dependencies)

> **Real-time application network privacy map, telemetry interceptor, and outbound socket analyzer.**

---

## ⚡ What is SocketVigil?

Desktop applications, Electron apps, and background processes constantly communicate with external servers—sending telemetry, analytics, crash logs, and cloud requests without explicit visibility to the user.

**SocketVigil** maps out every active connection on your machine:
- 📡 **Process-Level Socket Attribution**: Pinpoints which exact executable name, PID, and user owns each open TCP/UDP socket.
- 🎯 **Destination Classification**: Resolves remote IP addresses to hostnames and categorizes infrastructure (Cloudflare, AWS, Google Cloud, Microsoft Azure, Private LAN).
- 🚨 **Telemetry & Tracker Detection**: Flags outbound calls to known analytics, telemetry, and tracking endpoints.
- 🔓 **Insecure HTTP Warnings**: Detects unencrypted plaintext transmission over port 80.
- 📊 **Cyber Privacy Dashboard**: Modern dark-mode web console with real-time connection auto-refresh and exportable JSON reports.
- 🚀 **Zero External Dependencies**: Pure Python standard library interacting natively with Linux socket subsystem (`ss`).

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────┐
│                   SocketVigil Engine                   │
│          Inspects Linux Socket Subsystem (ss)          │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
┌──────────────┐     ┌─────────────┐      ┌─────────────┐
│ Process Map  │     │ Reverse DNS │      │ Privacy Rule│
│ PID, App Name│     │ Resolution  │      │ Trackers,   │
│ Protocol/Port│     │ Cloud CDN   │      │ Port 80 HTTP│
└──────┬───────┘     └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │    Privacy Verdict Map    │
              │   SAFE | TRACKER | INSEC  │
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │ Interactive Visual Console│
              │   http://localhost:8999   │
              └───────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Launch Web Dashboard

```bash
# Clone the repository
git clone https://github.com/Scempyyy/SocketVigil.git
cd SocketVigil

# Start the dashboard
python3 socketvigil.py serve
```

Open your browser to **`http://localhost:8999`**.

### 2. Terminal CLI Commands

```bash
# Display active network socket map
python3 socketvigil.py map

# List all apps with open network connections
python3 socketvigil.py apps

# Output machine-readable JSON
python3 socketvigil.py map --json
```

---

## 🧪 Testing

```bash
python3 -m unittest discover tests -v
```

---

## 📄 License

SocketVigil is open-source software licensed under the **[MIT License](LICENSE)**. Created by [Scempyyy](https://github.com/Scempyyy).
