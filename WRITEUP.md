# VeriVault write-up

## What I built
A Flask + SQLite document platform with a single-page web UI.
* Accounts with three roles (admin / owner / viewer), session auth with immediate revocation.
* Upload (owners), list, **search** (name, owner, category, date), download, edit metadata, delete.
* Per-document grants (`read`, `edit`) to named users; owners grant and revoke at any time.
* A **hash-chained, append-only audit trail** of uploads, downloads, changes, deletions, grants, revokes, logins (incl. refused ones) and admin actions.
* An **admin console**: 24h activity numbers, "worth noticing" alerts (users refused many times, failed-login bursts, broken audit chain), user management (role / disable), document metadata and who can see each document.
* 85+ automated tests; `THREATS.md`; `API.md`; mutation script proving the tests notice a removed check.

## Permission model (in my own words)
Every document has exactly one **owner** and zero or more **grants** (`document, user, read|edit`). Nothing inherits: no folders, no groups, no "everyone with the link". The single decision function is `authorize(user, document, action)` in `app/authz.py`:

* owner -> everything;
* anyone else -> needs a grant row: `read` allows read; `edit` allows read + edit; **delete and share are never delegable**;
* admin -> **no special rights over document content**. Admins run accounts and see activity/metadata. If an admin must read a file, the owner has to grant it, and that grant is audited like any other.

Refusals return 404 so the system never confirms whether a document exists.

**Why per-document grants and nothing else:** it is the model where "one file, forty files" mistakes cannot happen, and it is small enough to test exhaustively. The cost is that sharing 40 files means 40 grants (no bulk/groups).

**What "immediately" means and costs.** There are no cached permissions and no signed URLs, so each request re-reads the grant from the database. Revoking therefore works on the next request, even mid-session. The cost is one extra query per request, and that I cannot offer anonymous expiring links.

**Sessions** are signed cookies carrying a `session_version`. Logout, password change, role change and disable bump the user's version, which instantly invalidates every cookie issued earlier (even stolen ones).

## Audit protection
Entries are append-only (ORM listeners + SQLite triggers refuse UPDATE/DELETE, even raw SQL) and hash-chained (each hash covers the previous hash), so editing or removing a middle entry is detected by `verify_chain()`. Writes are fail-closed for downloads. Honest limits (tail truncation by someone with file access, mutations audited after commit) are listed in `THREATS.md` section E.

## What I deliberately did not build
Groups/folders, external-recipient links, versions, retention/recovery, encryption at rest, MFA/password reset, email verification, malware scanning, AI sharing suggestions (so no model can widen access). Reasons are in `THREATS.md`.

## How I used AI
See `PROMPTS.md` (dated, with the specific mistakes and the commits that fixed them).

## What is unfinished / known gaps
See `THREATS.md` section E. Also: free-tier hosting wipes the disk on restart, so the demo reseeds itself; the UI was tested through the API and a syntax check, not a full browser test suite.
