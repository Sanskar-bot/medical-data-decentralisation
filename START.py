#!/usr/bin/env python3
"""
MedVault — START.py
Run this one file to launch the entire system in the background.
A browser window opens automatically at http://127.0.0.1:5003

  Backend API     → http://127.0.0.1:5000
  Landing Page    → http://127.0.0.1:5003  ← entry point (login / sign up)
  Patient Portal  → http://127.0.0.1:5001
  Doctor Portal   → http://127.0.0.1:5002

All services run as background processes — closing this terminal does NOT
stop them.  Run STOP.py (or kill the PIDs in medvault_pids.txt) to stop.
"""
import subprocess, sys, os, time, webbrowser, json, signal, socket

ROOT   = os.path.dirname(os.path.abspath(__file__))
PY     = sys.executable
PIDFILE = os.path.join(ROOT, "medvault_pids.json")

# ── Helper: start a service detached from this terminal ──────────────────────
def start_background(label, script, port):
    if sys.platform == "win32":
        # DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP: no console
        # CREATE_BREAKAWAY_FROM_JOB: escapes the IDE's job object so the child
        # survives after this launcher process exits.
        DETACHED                = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000
        log_path = os.path.join(ROOT, f"logs_{label.replace(' ','_')}.log")
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["FLASK_ENV"]        = "development"
        try:
            p = subprocess.Popen(
                [PY, script],
                cwd=ROOT,
                env=env,
                creationflags=DETACHED | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
                stdout=open(log_path, "w", encoding="utf-8"),
                stderr=subprocess.STDOUT,
            )
        except OSError:
            # Job object disallows breakaway — fall back to PowerShell Start-Process
            # which always runs outside the current job object.
            err_path = os.path.splitext(log_path)[0] + ".err.log"
            rel_script = os.path.relpath(script, ROOT)
            ps_cmd = (
                "$env:PYTHONIOENCODING='utf-8'; "
                "$env:FLASK_ENV='development'; "
                f"Start-Process -FilePath '{PY}' "
                f"-ArgumentList @('{rel_script}') "
                f"-WorkingDirectory '{ROOT}' "
                f"-WindowStyle Hidden "
                f"-RedirectStandardOutput '{log_path}' "
                f"-RedirectStandardError '{err_path}'"
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-WindowStyle", "Hidden", "-Command", ps_cmd],
                cwd=ROOT, creationflags=CREATE_NEW_PROCESS_GROUP,
            )
            # Return a dummy object — PID tracking won't work for this path
            class _Dummy: pid = None
            return _Dummy()
    else:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["FLASK_ENV"]        = "development"
        p = subprocess.Popen(
            [PY, script],
            cwd=ROOT,
            env=env,
            stdout=open(os.path.join(ROOT, f"logs_{label.replace(' ','_')}.log"), "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    return p


def wait_for(port, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def already_running(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


print("""
╔══════════════════════════════════════════════════════╗
║        🏥  MedVault — Zero-Trust Health Portal       ║
║              Launching background services…          ║
╚══════════════════════════════════════════════════════╝
""", flush=True)

pids = {}
services = [
    ("Backend API",   os.path.join(ROOT, "server",  "server.py"),          5000),
    ("Patient Portal",os.path.join(ROOT, "portals", "patient_portal.py"),  5001),
    ("Doctor Portal", os.path.join(ROOT, "portals", "doctor_portal.py"),   5002),
    ("Landing Page",  os.path.join(ROOT, "portals", "landing.py"),         5003),
]

for label, script, port in services:
    if already_running(port):
        print(f"  ✅  {label:<16} already running on :{port}", flush=True)
        pids[label] = None
        continue
    print(f"  ▶  {label:<16} → http://127.0.0.1:{port}", flush=True)
    p = start_background(label, script, port)
    pids[label] = p.pid

    # Backend must be ready before portals start
    if port == 5000:
        if wait_for(5000, 20):
            print(f"  ✅  {label} ready", flush=True)
        else:
            print(f"  ⚠  {label} slow to start — continuing anyway", flush=True)

# Save PIDs so STOP.py can clean up
try:
    with open(PIDFILE, "w") as f:
        json.dump(pids, f, indent=2)
except Exception:
    pass

# Wait for landing page to be reachable
if wait_for(5003, 25):
    print("\n  ✅  All services launched!", flush=True)
else:
    print("\n  ⚠  Landing page slow — opening browser anyway", flush=True)

print("""
╔══════════════════════════════════════════════════════╗
║  ✅  MedVault is running in the background!          ║
║                                                      ║
║  🌐  Entry Point     →  http://127.0.0.1:5003        ║
║      (Login / Sign Up — start here)                  ║
║                                                      ║
║  🏥  Patient Portal  →  http://127.0.0.1:5001        ║
║  🩺  Doctor Portal   →  http://127.0.0.1:5002        ║
║  ⚙️  Backend API     →  http://127.0.0.1:5000        ║
║                                                      ║
║  Logs: logs_*.log in project root                    ║
║  To stop:  python STOP.py                            ║
╚══════════════════════════════════════════════════════╝
""", flush=True)

time.sleep(0.5)
webbrowser.open("http://127.0.0.1:5003")

# This process exits — services keep running in background
print("  ℹ️   This launcher has exited. Services continue running.", flush=True)
