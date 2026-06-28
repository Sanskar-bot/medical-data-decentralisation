import re

with open('portals/patient_portal.py', 'r', encoding='utf-8', errors='replace') as f:
    src = f.read()

changes = []
warnings = []

# ---- CORS fix: replace wildcard cors() with cors_after_request ----
old_cors = '@app.after_request\ndef cors(r):\n    r.headers["Access-Control-Allow-Origin"]  = "*"\n    r.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key,Authorization"\n    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,DELETE"\n    return r'
new_cors = '@app.after_request\ndef cors(r):\n    # Whitelist-based CORS - replaces the old wildcard\n    return cors_after_request(r)'
if old_cors in src:
    src = src.replace(old_cors, new_cors, 1)
    changes.append('CORS: replaced wildcard with cors_after_request()')
else:
    warnings.append('cors() function pattern not found')

# ---- SHA-256 fix in api_register() ----
# Try several possible patterns
for old, new, label in [
    (
        '    import hashlib\n    pw_hash = hashlib.sha256(pw.encode()).hexdigest()',
        '    pw_hash = hash_password(pw)',
        'api_register SHA-256 v1'
    ),
    (
        'import hashlib\n    pw_hash = hashlib.sha256(pw.encode()).hexdigest()',
        'pw_hash = hash_password(pw)',
        'api_register SHA-256 v2'
    ),
]:
    if old in src:
        src = src.replace(old, new, 1)
        changes.append(label)
        break
else:
    warnings.append('api_register SHA-256 pattern not found')

# ---- SHA-256 fix in patient_login() ----
for old, new, label in [
    (
        '    import hashlib\n    pw_hash = hashlib.sha256(d.get("password","").encode()).hexdigest()',
        '    raw_pw = d.get("password", "")\n    pw_hash = hash_password(raw_pw)',
        'patient_login SHA-256 v1'
    ),
    (
        '    import hashlib\n    pw_hash = hashlib.sha256(d.get("password","").encode()).hexdigest()',
        '    raw_pw = d.get("password", "")\n    pw_hash = hash_password(raw_pw)',
        'patient_login SHA-256 v1b'
    ),
]:
    if old in src:
        src = src.replace(old, new, 1)
        changes.append(label)
        break
else:
    # Use regex
    src_before = src
    src = re.sub(
        r'import hashlib\s*\n\s*pw_hash\s*=\s*hashlib\.sha256\(d\.get\(["\']password["\'],\s*["\']["\']\)\.encode\(\)\)\.hexdigest\(\)',
        'raw_pw = d.get("password", "")\n    pw_hash = hash_password(raw_pw)',
        src, count=1
    )
    if src != src_before:
        changes.append('patient_login SHA-256 via regex')
    else:
        warnings.append('patient_login SHA-256 not found')

# ---- Update patient_login POST to send raw password ----
src_before = src
src = re.sub(
    r'json=\{"email":d\.get\("email",""\),"password_hash":pw_hash\}',
    'json={"email":d.get("email",""), "password":d.get("password","")}',
    src, count=1
)
if src != src_before:
    changes.append('patient_login: POST sends raw password')
else:
    warnings.append('patient_login POST body pattern not found')

# ---- Add imports ----
old_import = 'from auth_utils import login_required  # noqa: E402'
new_import = 'from auth_utils import login_required, hash_password, cors_after_request  # noqa: E402'
if old_import in src:
    src = src.replace(old_import, new_import, 1)
    changes.append('Added hash_password, cors_after_request to auth_utils import')
else:
    warnings.append('auth_utils import line not found')

print("Changes applied:")
for c in changes:
    print("  OK:", c)

if warnings:
    print("Warnings:")
    for w in warnings:
        print("  WARN:", w)

with open('portals/patient_portal.py', 'w', encoding='utf-8') as f:
    f.write(src)
print("patient_portal.py written.")
