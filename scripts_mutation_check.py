"""Mutation check: remove ONE security check at a time and confirm the test
suite fails. Run: python scripts_mutation_check.py"""
import pathlib, subprocess, sys

M = [
 ("download authorize",      "app/documents.py", '''    # Check authorization on every download request.
    if not authorize(user, document, "read"):''', '''    if False:'''),
 ("edit authorize",          "app/documents.py", '''    # Centralized authorization check.
    if not authorize(user, document, "edit"):''', '''    if False:'''),
 ("delete authorize",        "app/documents.py", '''    if not authorize(user, document, "delete"):''', '''    if False:'''),
 ("share/permissions/revoke owner check", "app/sharing.py", "document.owner_id != user.id", "False"),
 ("authz: no grant => deny", "app/authz.py", "    if grant is None:\r\n        return False", "    if False:\r\n        return False"),
 ("authz: edit needs edit grant", "app/authz.py", 'return grant.permission == "edit"', 'return True'),
 ("authz: share/delete owner-only", "app/authz.py", '''    if action in {"delete", "share"}:\r\n        return False''', '''    if action in {"delete", "share"}:\r\n        return True'''),
 ("session revocation",      "app/auth.py", 'if session.get("sv", 0) != user.session_version:', 'if False:'),
 ("disabled user check",     "app/auth.py", "if not user or not user.is_active:\n        session.clear()", "if not user:\n        session.clear()"),
 ("admin-only decorator",    "app/admin.py", '@admin_bp.route("/admin/users", methods=["GET"])\n@role_required("admin")', '@admin_bp.route("/admin/users", methods=["GET"])'),
 ("user-directory role gate","app/admin.py", 'if user.role not in {"owner", "admin"}:', 'if False:'),
 ("upload owner-only",       "app/documents.py", 'if user.role != "owner":', 'if False:'),
 ("audit fail-closed",       "app/audit.py", "            blocked = jsonify", "            return response\n            blocked = jsonify"),
 ("login rate limit",        "app/auth.py", "if (limiter.blocked(acct_key, LOGIN_LIMIT_PER_ACCOUNT)", "if (False and limiter.blocked(acct_key, LOGIN_LIMIT_PER_ACCOUNT)"),
 ("cross-site block",        "app/__init__.py", 'if origin and urlparse(origin).netloc != request.host', 'if False'),
 ("list re-authorize (defence in depth)", "app/documents.py", '''        if not authorize(user, document, "read"):\n            continue''', '''        if False:\n            continue'''),
]
import os
START = int(os.environ.get("START", "0"))
survived = []
for name, path, old, new in M[START:]:
    p = pathlib.Path(path); src = p.read_bytes().decode()
    if old not in src:
        print(f"?? pattern missing: {name}"); survived.append(name + " (pattern missing)"); continue
    p.write_bytes(src.replace(old, new, 1).encode())
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                           capture_output=True, text=True)
    finally:
        p.write_bytes(src.encode())
    caught = r.returncode != 0
    print(("CAUGHT   " if caught else "SURVIVED ") + name, flush=True)
    if not caught: survived.append(name)
print("\nSurvivors:", survived or "none")
