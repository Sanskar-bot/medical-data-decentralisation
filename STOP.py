#!/usr/bin/env python3
"""
MedVault — STOP.py
Terminates all MedVault background services started by START.py.
"""
import os, sys, json, socket

ROOT    = os.path.dirname(os.path.abspath(__file__))
PIDFILE = os.path.join(ROOT, "medvault_pids.json")

PORTS = [5000, 5001, 5002, 5003]

print("\n  🛑  Stopping MedVault services…", flush=True)

# ── Method 1: kill by saved PIDs ─────────────────────────────────────────────
if os.path.exists(PIDFILE):
    try:
        pids = json.load(open(PIDFILE))
        for label, pid in pids.items():
            if not pid:
                continue
            try:
                if sys.platform == "win32":
                    os.system(f"taskkill /F /PID {pid} >nul 2>&1")
                else:
                    os.kill(int(pid), 15)
                print(f"  ✅  Stopped {label} (PID {pid})", flush=True)
            except Exception as e:
                print(f"  ⚠  Could not stop {label} (PID {pid}): {e}", flush=True)
        os.remove(PIDFILE)
    except Exception as e:
        print(f"  ⚠  Could not read PID file: {e}", flush=True)

# ── Method 2: kill by port (catch any orphans) ────────────────────────────────
for port in PORTS:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            # port still open — kill it
            if sys.platform == "win32":
                os.system(f"for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :{port}') do taskkill /F /PID %a >nul 2>&1")
            else:
                os.system(f"fuser -k {port}/tcp 2>/dev/null")
            print(f"  ✅  Closed port {port}", flush=True)
    except OSError:
        pass  # already closed

print("\n  ✅  All MedVault services stopped.\n", flush=True)
