# VeriVault (TrustVault)

Secure document sharing with per-document permissions, instant revocation and a tamper-evident audit trail. Flask + SQLite + a dependency-free web UI. Built for the Snovasys RISE challenge.

**Live demo:** https://verivault-3e5w.onrender.com

## Demo accounts (demo deployment only, created by `SEED_DEMO=1`)
| Role | Email | Password |
|---|---|---|
| Admin | admin@vault.test | Admin#Demo2026 |
| Owner | owner@vault.test | Owner#Demo2026 |
| Viewer | viewer@vault.test | Viewer#Demo2026 |
| Viewer (second, for testing) | partner@vault.test | Partner#Demo2026 |

Seed data: owner has 3 documents - `salary-letter.txt` (viewer: read), `contract-draft.txt` (partner: edit), `board-minutes.txt` (private).
Try: sign in as `viewer`, see only the salary letter; as `partner`, only the contract; as `admin`, see *metadata and activity* but not contents; as `owner`, revoke a grant and watch the other user lose access on the next click.

## Run locally (from a clean clone)
```bash
python -m venv venv
venv\Scripts\activate            # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
set SEED_DEMO=1                  # optional: demo users + documents (Mac/Linux: export SEED_DEMO=1)
python run.py                    # http://127.0.0.1:5000
```
Tables are created automatically (schema = `app/models.py`; SQLite file in `instance/`). To start fresh, delete the `instance/` folder.

Without seed data: register, then promote yourself: `flask --app run set-role you@example.com admin` (roles: `viewer`, `owner`, `admin`).
Quick try-out only: `VERIVAULT_DEMO=1` shows a "Become an owner" button. **Never enable it in production.**

## Tests
```bash
python -m pytest -q                    # 85+ tests, incl. app/tests/test_threats.py
python scripts_mutation_check.py       # removes one security check at a time; every one must be CAUGHT
```

## Deploy (Render, free)
1. Push this repo to GitHub.
2. Render > **New + > Blueprint** > choose the repo (it reads `render.yaml`).
3. After the build, open the URL and sign in with a demo account above.

Notes: one worker on purpose (audit lock + rate limiter are per-process). Free instances have an ephemeral disk; data resets on restart and `SEED_DEMO=1` recreates the demo. For persistence use a paid plan with a disk and set `DATA_DIR`. See `.env.example`.

## Environment variables
`SECRET_KEY` (auto-generated if unset - there is no default), `COOKIE_SECURE`, `TRUST_PROXY`, `SEED_DEMO`, `VERIVAULT_DEMO`, `DATA_DIR`, `DATABASE_URL`.

## Documents
* `THREATS.md` - threat list, defences, accepted risks
* `API.md` - every endpoint and who may call it
* `WRITEUP.md` - what was built / not built, permission model
* `PROMPTS.md` - AI usage log
