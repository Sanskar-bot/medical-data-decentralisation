"""
patch_landing.py — applies all Bug 1 (SHA-256->werkzeug) and Bug 3 (identity) fixes
to portals/landing.py using line-based surgical replacements.
"""
import re

with open('portals/landing.py', 'r', encoding='utf-8', errors='replace') as f:
    src = f.read()

original_len = len(src)
changes = []
warnings = []

def replace_once(label, old, new, text):
    if old in text:
        changes.append(label)
        return text.replace(old, new, 1)
    warnings.append(f"NOT FOUND: {label}")
    return text

# ---- BUG 1 FIX 1: register_patient local user_data.json password_hash ----
src = replace_once(
    "register_patient local hash",
    '"password_hash": hashlib.sha256(password.encode()).hexdigest(),\n            "jwt_token": "",',
    '"password_hash": hash_password(password),\n            "jwt_token": "",',
    src
)

# ---- BUG 1 FIX 2: register_patient /internal/register_user_db call ----
src = replace_once(
    "register_patient backend register hash",
    '"password_hash": hashlib.sha256(password.encode()).hexdigest(),\n                      "profile_code": profile_code,',
    '"password_hash": hash_password(password),\n                      "profile_code": profile_code,',
    src
)

# ---- BUG 1 FIX 3: register_patient JWT fetch - remove sha_hash ----
src = replace_once(
    "register_patient JWT fetch sha-256",
    'json={"email": email, "password": password,\n                      "password_hash": hashlib.sha256(password.encode()).hexdigest()},\n                headers=_headers(), timeout=10,\n            )\n            if _lr.ok:\n                session["jwt_token"] = _lr.json().get("access_token", "")\n            else:\n                session["jwt_token"] = ""\n        except Exception:\n            session["jwt_token"] = ""\n\n        return jsonify({\n            "message":      "ok",\n            "profile_code": profile_code,',
    'json={"email": email, "password": password},\n                headers=_headers(), timeout=10,\n            )\n            if _lr.ok:\n                _lr_data = _lr.json()\n                session["jwt_token"] = _lr_data.get("access_token", "")\n                session["user_id"]   = _lr_data.get("user_id", "")\n            else:\n                session["jwt_token"] = ""\n        except Exception:\n            session["jwt_token"] = ""\n\n        return jsonify({\n            "message":      "ok",\n            "profile_code": profile_code,',
    src
)

# ---- BUG 1 FIX 4: register_doctor /internal/register_user_db call ----
src = replace_once(
    "register_doctor backend register hash",
    '"password_hash": hashlib.sha256(password.encode()).hexdigest(),\n                      "profile_code": doctor_code,',
    '"password_hash": hash_password(password),\n                      "profile_code": doctor_code,',
    src
)

# ---- BUG 1 FIX 5: register_doctor JWT fetch - remove sha_hash ----
src = replace_once(
    "register_doctor JWT fetch sha-256",
    'json={"email": email, "password": password,\n                      "password_hash": hashlib.sha256(password.encode()).hexdigest()},\n                headers=_headers(), timeout=10,\n            )\n            if _lr.ok:\n                session["jwt_token"] = _lr.json().get("access_token", "")\n            else:\n                session["jwt_token"] = ""\n        except Exception:\n            session["jwt_token"] = ""\n\n        return jsonify({\n            "message":     "ok",\n            "doctor_code": doctor_code,',
    'json={"email": email, "password": password},\n                headers=_headers(), timeout=10,\n            )\n            if _lr.ok:\n                _lr_data = _lr.json()\n                session["jwt_token"] = _lr_data.get("access_token", "")\n                session["user_id"]   = _lr_data.get("user_id", "")\n            else:\n                session["jwt_token"] = ""\n        except Exception:\n            session["jwt_token"] = ""\n\n        return jsonify({\n            "message":     "ok",\n            "doctor_code": doctor_code,',
    src
)

# ---- BUG 1 FIX 6: login() - remove sha_hash lines ----
# Show what the login section looks like first
login_start = src.find('def login():')
if login_start != -1:
    snippet = src[login_start:login_start+600]
    with open('login_snippet.txt', 'w', encoding='utf-8') as dbg:
        dbg.write(snippet)
    print("Login snippet written to login_snippet.txt")

# Use regex to replace sha_hash computation and usage in login()
src_before = src
# Pattern 1: sha_hash = hashlib.sha256... line
src = re.sub(
    r'\n        sha_hash = hashlib\.sha256\(password\.encode\(\)\)\.hexdigest\(\)\n',
    '\n',
    src, count=1
)
if src != src_before:
    changes.append("login: removed sha_hash computation line")
else:
    warnings.append("login sha_hash computation line not found via regex")

# Pattern 2: password_hash: sha_hash in login's post
src_before = src
src = re.sub(
    r'json=\{"email": identifier, "password": password,\s*"password_hash": sha_hash\},',
    'json={"email": identifier, "password": password},',
    src, count=1
)
if src != src_before:
    changes.append("login: removed password_hash from POST body")
else:
    warnings.append("login password_hash: sha_hash in POST not found")

# ---- BUG 1 FIX 7: login_upgrade() - remove sha2 and password_hash lines ----
src_before = src
src = re.sub(
    r'\n        sha2 = hashlib\.sha256\(new_pw\.encode\(\)\)\.hexdigest\(\)\n',
    '\n',
    src, count=1
)
if src != src_before:
    changes.append("login_upgrade: removed sha2 computation line")
else:
    warnings.append("login_upgrade sha2 line not found")

src_before = src
src = re.sub(
    r'json=\{"email": identifier, "password": new_pw,\s*"password_hash": sha2\},',
    'json={"email": identifier, "password": new_pw},',
    src, count=1
)
if src != src_before:
    changes.append("login_upgrade: removed sha2 from POST body")
else:
    warnings.append("login_upgrade sha2 in POST not found")

# ---- BUG 1 FIX 8: Add hash_password to imports ----
if 'hash_password' not in src:
    # Check if auth_utils is imported at all
    m = re.search(r'from auth_utils import ([^\n]+)', src)
    if m:
        old_import = m.group(0)
        names = m.group(1)
        new_import = old_import.rstrip() + ', hash_password'
        src = src.replace(old_import, new_import, 1)
        changes.append("Added hash_password to auth_utils import in landing.py")
    else:
        # Find hashlib import and add after it
        src = re.sub(
            r'(import hashlib)',
            r'\1\nfrom auth_utils import hash_password, check_password',
            src, count=1
        )
        changes.append("Added hash_password import after hashlib in landing.py")
else:
    changes.append("hash_password already imported in landing.py")

# ---- BUG 3 FIX 1: patient_prescriptions_direct ----
src = replace_once(
    "patient_prescriptions_direct UUID fix",
    'r = http.get(f"{BACKEND}/emr/prescriptions/patient/{pid}", headers=hdrs, timeout=8)',
    '# BUG3 FIX: EMR tables store users.id (UUID), not profile_code\n            _emr_pid = session.get("user_id") or pid\n            r = http.get(f"{BACKEND}/emr/prescriptions/patient/{_emr_pid}", headers=hdrs, timeout=8)',
    src
)

# ---- BUG 3 FIX 2: patient_lab_reports_direct ----
src = replace_once(
    "patient_lab_reports_direct UUID fix",
    'r = http.get(f"{BACKEND}/emr/lab-reports/patient/{pid}", headers=hdrs, timeout=8)',
    '# BUG3 FIX: EMR tables store users.id (UUID), not profile_code\n            _emr_pid = session.get("user_id") or pid\n            r = http.get(f"{BACKEND}/emr/lab-reports/patient/{_emr_pid}", headers=hdrs, timeout=8)',
    src
)

# ---- BUG 3 FIX 3: EMR profile endpoint ----
# Find and fix any /emr/patient/{pid}/profile call
src_before = src
src = re.sub(
    r'http\.get\(f"\{BACKEND\}/emr/patient/\{pid\}/profile"',
    '# BUG3 FIX: EMR uses users.id (UUID)\n            _emr_pid3 = session.get("user_id") or pid\n            r = http.get(f"{BACKEND}/emr/patient/{_emr_pid3}/profile"',
    src, count=1
)
if src != src_before:
    changes.append("patient_emr_profile_direct UUID fix")
else:
    warnings.append("patient_emr_profile_direct /emr/patient/{pid}/profile not found")

print("Changes applied:")
for c in changes:
    print(f"  OK: {c}")

if warnings:
    print("\nWarnings (need manual check):")
    for w in warnings:
        print(f"  WARN: {w}")

print(f"\nFile size: {original_len} -> {len(src)} bytes")

with open('portals/landing.py', 'w', encoding='utf-8') as f:
    f.write(src)
print("portals/landing.py written.")
