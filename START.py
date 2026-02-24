#!/usr/bin/env python3
"""
MedVault — START.py
Run this one file to launch the entire system.

  Backend API     → http://127.0.0.1:5000
  Patient Portal  → http://127.0.0.1:5001
  Doctor Portal   → http://127.0.0.1:5002
"""
import subprocess, sys, os, time, webbrowser, signal

ROOT = os.path.dirname(os.path.abspath(__file__))
PY   = sys.executable
procs  = []
labels = []

def start(label, script, port):
    # FIX 1: Removed stdout=subprocess.PIPE — piping without a reader fills
    # the OS buffer (~64 KB) and causes the child process to block/exit.
    # Letting output flow directly to the terminal avoids the deadlock.
    p = subprocess.Popen([PY, script], cwd=ROOT)
    procs.append(p)
    labels.append(label)
    return p

def wait_for(port, timeout=20):
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False

def cleanup(sig=None, frame=None):
    print("\n  🛑  Shutting down MedVault...", flush=True)
    for p in procs:
        try: p.terminate()
        except: pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, cleanup)

print("""
╔══════════════════════════════════════════════════════╗
║        🏥  MedVault — Zero-Trust Health Portal       ║
║                 Starting all services...             ║
╚══════════════════════════════════════════════════════╝
""", flush=True)

print("  ▶  Backend API       → http://127.0.0.1:5000", flush=True)
start("Backend API", os.path.join(ROOT, "server", "server.py"), 5000)
if not wait_for(5000, 15):
    print("  ⚠  Backend slow to start — continuing anyway", flush=True)
else:
    print("  ✅  Backend ready", flush=True)

print("  ▶  Patient Portal    → http://127.0.0.1:5001", flush=True)
start("Patient Portal", os.path.join(ROOT, "portals", "patient_portal.py"), 5001)
if not wait_for(5001, 12):
    print("  ⚠  Patient portal slow to start", flush=True)
else:
    print("  ✅  Patient portal ready", flush=True)

print("  ▶  Doctor Portal     → http://127.0.0.1:5002", flush=True)
start("Doctor Portal", os.path.join(ROOT, "portals", "doctor_portal.py"), 5002)
if not wait_for(5002, 12):
    print("  ⚠  Doctor portal slow to start", flush=True)
else:
    print("  ✅  Doctor portal ready", flush=True)

print("""
╔══════════════════════════════════════════════════════╗
║  ✅  MedVault is running!                            ║
║                                                      ║
║  🏥  Patient Portal  →  http://127.0.0.1:5001        ║
║  🩺  Doctor Portal   →  http://127.0.0.1:5002        ║
║  ⚙️  Backend API     →  http://127.0.0.1:5000        ║
║                                                      ║
║  Press Ctrl+C to stop all services                   ║
╚══════════════════════════════════════════════════════╝
""", flush=True)

time.sleep(1)
webbrowser.open("http://127.0.0.1:5001")
time.sleep(0.4)
webbrowser.open("http://127.0.0.1:5002")

# FIX 2: Replaced the broken `all(p.poll() is None ...)` loop.
# The old loop exited silently the moment any process stopped, with no info
# about which service failed or why. The new loop identifies the culprit by name.
try:
    while True:
        time.sleep(1)
        for p, label in zip(procs, labels):
            code = p.poll()
            if code is not None:
                print(f"\n  ❌  '{label}' has exited unexpectedly (exit code: {code}).", flush=True)
                print("  ℹ️   Check the terminal output above for error details.", flush=True)
                print("  🛑  Shutting down remaining services...", flush=True)
                cleanup()
except KeyboardInterrupt:
    cleanup()