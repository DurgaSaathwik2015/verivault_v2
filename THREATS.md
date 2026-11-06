# THREATS.md

Honest list of how VeriVault could be broken, what was done, and what was
knowingly accepted. Each "Fixed" row names the test that fails if the defence
is removed (all in `app/tests/test_threats.py` unless noted). Run
`python scripts_mutation_check.py` to see the suite catch each check being
deleted.

**Security model in one line:** the server decides on every request; the UI
hides nothing that the API does not also refuse.

## A. Reaching a document you were not granted

| # | Threat | Defence | Test |
|---|--------|---------|------|
| 1 | **IDOR**: change the id in download / edit / delete / share / permissions / revoke | Every route loads the document and calls `authorize()` (`app/authz.py`) or the owner check (`app/sharing.py`). DB lookup on every request; nothing is cached. | T01, T04, T05 |
| 2 | **Existence oracle**: "403 vs 404" reveals which ids exist | Refused and missing both return the same 404 JSON; a test asserts the bodies are identical. | T01 |
| 3 | **Anonymous access** | All routes return 401 before touching any document. | T02 |
| 4 | **Listing/search leaks** other people's files (filters, wildcards `%` `_`, owner filter) | SQL filter narrows to own/granted rows, then every row is re-authorised. LIKE wildcards are escaped. | T03, T31 |
| 5 | **Privilege creep through grants**: a reader editing, an editor deleting or re-sharing | `authz.py`: read=read; edit=read+edit; delete/share = owner only. Editors may only change `filename`/`category` (allow-list; `owner_id`, `storage_filename`... rejected). | T04, T05 |
| 6 | **Admin as a back door** | Admin has *no* automatic document access (least privilege). Admin sees metadata and activity, never content. | T07 |
| 7 | **Role escalation**: self-registering as admin, mass-assignment | Registration always creates `viewer`; role only changeable by admin API / CLI. | T10, T08 |
| 8 | **Demo self-promotion left on** | `/auth/demo-owner` returns 403 unless `VERIVAULT_DEMO=1`. Never set in production. | T11 |
| 9 | **User directory harvesting** | `/users` limited to owners/admins; returns id+username only. | T09 |
| 10 | **Files reachable by URL** (static dir, guessable names, traversal) | Files live in `instance/uploads` outside the static folder, stored under random UUID names; served only through the authorised download route. Original filename sanitised with `secure_filename`. | T25, T26 |
| 11 | **Stored XSS / content sniffing** via uploaded files or names | Allow-list of types + magic-byte check; downloads are `attachment`, `application/octet-stream`, `nosniff`; UI escapes all values; CSP `script-src 'self'`, no inline scripts. | T23, T27, T29 |

## B. Taking access away

| # | Threat | Defence | Test |
|---|--------|---------|------|
| 12 | Revoked user keeps access | No grant cache and no signed download links: access is re-read from the DB on each request, so revocation is effective on the very next request, even in an already-open session. **Cost:** one extra query per request. | T06 |
| 13 | Disabled / departed user's session still works | Disabled accounts are rejected on every request and their sessions are revoked (`session_version`). | T13 |
| 14 | Stolen cookie replayed after logout / password change / role change | Session cookies carry `sv`; logout, password change, role change and disable bump `User.session_version`, killing every older cookie. **Side-effect:** logging out signs you out of all devices. | T12, T14, T15 |
| 15 | Forged session cookie | There is **no hard-coded default** `SECRET_KEY`: env var, or a random key generated once into the instance folder. | T16 |
| 16 | Delete leaves access behind | Deleting removes the row, grants (cascade) and the file. | T32 |

## C. Audit trail

| # | Threat | Defence | Test |
|---|--------|---------|------|
| 17 | Refused attempts not recorded | Central `after_request` hook records every upload/download/change/delete/grant/revoke/login/admin change with outcome (`success`/`denied`/`failure`) and actor. | T18, T21 |
| 18 | Entries too thin to prove anything | Permission entries store target user and permission level; admin changes store target/new role/state. | T19 |
| 19 | **Quiet alteration**: edit/delete rows | Each entry hashes its content + the previous hash (SHA-256 chain); `verify_chain()` detects edits, deletions in the middle and re-ordering. ORM listeners and SQLite triggers refuse UPDATE/DELETE, including raw SQL. | `test_audit.py` |
| 20 | Action succeeds but the log write fails | **Fail-closed**: if the audit row cannot be written the response becomes 503, so a file is never delivered without a record. | T20 |
| 21 | Non-admins reading everyone's history | Non-admins see only their own actions and events on documents they own; admin sees all with details. | T22 |

## D. Web and account hygiene

| # | Threat | Defence | Test |
|---|--------|---------|------|
| 22 | Password guessing | 8 failures / 15 min per IP+email and 40 per IP -> 429 (even the right password is refused during lockout); unknown-email logins burn equal hashing time; passwords capped at 128 chars. | T17 |
| 23 | CSRF | `SameSite=Lax` + `HttpOnly` cookie, plus server rejection of cross-origin `Origin` / `Sec-Fetch-Site: cross-site` on all writes. | T28 |
| 24 | Clickjacking, sniffing, caching | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `nosniff`, `Cache-Control: no-store` on API responses, HSTS when `COOKIE_SECURE=true`. | T29, T27 |
| 25 | Oversized upload / DoS | 10 MB file limit, request cap at 11 MB (413), empty files refused. | T24 |
| 26 | SQL injection | SQLAlchemy ORM with bound parameters only; no string-built SQL. | (design) |

## E. Knowingly accepted (and why)

0. **Redundant list check.** `GET /documents` filters in SQL *and* re-authorises each row. The mutation script shows deleting only the second layer is not caught, because the SQL layer alone is equivalent today (deleting the SQL layer *is* caught by T03). I kept the second layer as defence in depth against a future query bug.

1. **Audit chain tail truncation.** Someone with write access to the database *file* could drop the newest rows, or drop the triggers and rebuild the chain; `verify_chain()` would still pass. The Admin/Activity page shows the entry count and head hash so an admin can record it elsewhere; a real deployment would ship the head hash to an external append-only store. Not built in a week.
2. **Audit write is after the action for mutations.** For downloads we fail closed before delivery. For grant/revoke/delete the DB change is committed first; if the audit write then fails the user gets a 503 and the failure is logged, but the change stands. Fixing it needs the audit insert in the *same* transaction as every action.
3. **Rate limiter and audit lock are per-process.** Deploy one worker (`gunicorn -w 1 --threads 4`); multi-worker needs Redis / DB-level serialisation. SQLite audit triggers do not exist on other databases.
4. **Registration reveals whether a username/email is taken (409).** Kept for usability; login does not reveal it.
5. **Timing side-channels on document existence** are not fully removed (404 paths do slightly different work).
6. **Content checks are shallow.** Magic bytes and extension only: a DOCX is any ZIP; no malware scan. Mitigated by attachment-only serving, but files are not scanned.
7. **No email verification, no MFA, no password reset.** Out of scope for a week; passwords are PBKDF2-hashed (Werkzeug).
8. **Deleted-document history** is visible to the actor and admin but not to an owner who later lost the row (the owner's audit view is by *currently owned* documents).
9. **Files are not encrypted at rest.** Protection is filesystem permissions + unreachability by URL. Encrypting would add key-management risk I chose not to take on.
10. **No AI feature inside the product.** The brief offers optional AI suggestions for sharing; I left it out, so there is no path by which a model could widen access.
11. **Deleting is permanent** (no recovery/retention), a deliberate simplification.
12. **Seed/demo credentials are public** (README). They exist only on the demo deployment; never seed production.
