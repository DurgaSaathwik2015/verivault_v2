# API reference

JSON everywhere. Session cookie (`session`, HttpOnly, SameSite=Lax) after login.
"Refused" document requests return **404** (never 403) so existence is not revealed.
Unauthenticated -> 401. Throttled login -> 429. Audit-log failure -> 503.

Roles: **admin** (accounts + activity, no document content), **owner** (uploads, owns, shares), **viewer** (reads/edits what is granted).

## Auth
| Method & path | Who | Notes |
|---|---|---|
| `POST /auth/register` | anyone | `{username,email,password}`; always creates a `viewer` |
| `POST /auth/login` | anyone | `{email,password}`; 8 failures/15 min lockout |
| `POST /auth/logout` | logged in | revokes all of this user's sessions |
| `GET /auth/me` | logged in | |
| `POST /auth/change-password` | logged in | `{current_password,new_password}`; signs out other sessions |
| `POST /auth/demo-owner` | logged in, **only if `VERIVAULT_DEMO=1`** | viewer -> owner |

## Documents
| Method & path | Who | Notes |
|---|---|---|
| `GET /documents` | logged in | only docs you own or were granted. Query: `q` (name), `owner`, `category`, `date_from`, `date_to` (YYYY-MM-DD), `limit`, `offset`. Each item has `access`: `owner`/`read`/`edit` |
| `POST /documents/upload` | **owner** | multipart field `file`; allow-listed type + magic bytes, <=10 MB |
| `GET /documents/<id>/download` | owner, or grant `read`/`edit` | |
| `PATCH /documents/<id>` | owner, or grant `edit` | only `filename`, `category` |
| `DELETE /documents/<id>` | **owner only** | |

## Sharing
| Method & path | Who | Notes |
|---|---|---|
| `POST /documents/<id>/share` | **document owner** | `{user_id, permission: "read"|"edit"}` (upsert) |
| `GET /documents/<id>/permissions` | **document owner** | |
| `DELETE /documents/<id>/share/<user_id>` | **document owner** | takes effect on the next request |

## Directory, audit, admin
| Method & path | Who | Notes |
|---|---|---|
| `GET /users?q=` | owner, admin | id + username of active users (for sharing) |
| `GET /audit?action=&outcome=` | logged in | admin: everything + details; others: own actions and events on documents they own. Returns `chain_valid` and `head` |
| `GET /admin/summary` | **admin** | 24h counts + alerts (probing, failed logins, broken chain) |
| `GET /admin/users` | **admin** | |
| `PATCH /admin/users/<id>` | **admin** | `{role?, is_active?}`; cannot target yourself; revokes that user's sessions |
| `GET /admin/documents` | **admin** | metadata + who has access, never content |
| `GET /config`, `GET /health` | anyone | |
