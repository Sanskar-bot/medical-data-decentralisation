import re

with open('portals/doctor_portal.py', 'r', encoding='utf-8', errors='replace') as f:
    src = f.read()

changes = []
warnings = []

# ---- CORS fix: replace wildcard cors() with cors_after_request ----
old_cors = '@app.after_request\ndef cors(r):\n    r.headers["Access-Control-Allow-Origin"]  = "*"\n    r.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key"\n    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"\n    return r'
new_cors = '@app.after_request\ndef cors(r):\n    # Whitelist-based CORS - replaces the old wildcard\n    return cors_after_request(r)'
if old_cors in src:
    src = src.replace(old_cors, new_cors, 1)
    changes.append('CORS: replaced wildcard with cors_after_request()')
else:
    warnings.append('cors() pattern not found - trying regex')
    src_before = src
    src = re.sub(
        r'@app\.after_request\s*\ndef cors\(r\):\s*\n\s*r\.headers\["Access-Control-Allow-Origin"\]\s*=\s*"\*".*?return r',
        '@app.after_request\ndef cors(r):\n    return cors_after_request(r)',
        src, count=1, flags=re.DOTALL
    )
    if src != src_before:
        changes.append('CORS: replaced wildcard via regex')
    else:
        warnings.append('cors() pattern not found by regex either')

# ---- Add cors_after_request to auth_utils import ----
old_import = 'from auth_utils import login_required  # noqa: E402'
new_import = 'from auth_utils import login_required, cors_after_request  # noqa: E402'
if old_import in src:
    src = src.replace(old_import, new_import, 1)
    changes.append('Added cors_after_request to auth_utils import')
else:
    warnings.append('auth_utils import line not found in doctor_portal.py')

print("Changes:")
for c in changes:
    print("  OK:", c)
if warnings:
    print("Warnings:")
    for w in warnings:
        print("  WARN:", w)

with open('portals/doctor_portal.py', 'w', encoding='utf-8') as f:
    f.write(src)
print("doctor_portal.py written.")
