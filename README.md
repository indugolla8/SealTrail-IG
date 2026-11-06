\# SealTrail-IG



A small FastAPI service for storing documents with strict per-user access control and a tamper-evident audit log.



\## Features

\- Roles: \*\*owner\*\* (uploads, shares, revokes), \*\*viewer\*\* (reads or edits what is shared), \*\*admin\*\* (views the audit log, cannot read file contents)

\- Central permission check on every document route; no access returns 404 so document IDs can't be probed

\- Share with `read` or `edit` level; revoking takes effect on the next request

\- Hash-chained audit log with an admin-only verify endpoint

\- Upload checks: extension allowlist, magic-byte check, 5 MB limit, safe filenames

\- Login lockout: 5 failed attempts per email in 10 minutes returns 429

\- JWT login (2-hour tokens), bcrypt password hashing



\## Setup (Windows PowerShell)

```

git clone https://github.com/indugolla8/SealTrail-IG.git

cd SealTrail-IG

python -m venv venv

.\\venv\\Scripts\\Activate.ps1

pip install -r requirements.txt

python -m app.seed

uvicorn app.main:app --reload

```

Open http://127.0.0.1:8000/docs and use \*\*Authorize\*\* to log in.



\## Demo accounts

| Role | Email | Password |

|---|---|---|

| admin | admin@sealtrail.test | Admin#Demo2026 |

| owner | owner@sealtrail.test | Owner#Demo2026 |

| viewer | viewer@sealtrail.test | Viewer#Demo2026 |



These are for local demos only. Do not use them anywhere real.



\## Configuration

| Variable | Purpose | Default |

|---|---|---|

| `DATABASE\_URL` | Database location | `sqlite:///./sealtrail.db` |

| `SECRET\_KEY` | JWT signing key | random per process in dev |

| `SEALTRAIL\_ENV` | Set to `prod` to require `SECRET\_KEY` | `dev` |



Generate a key with:

```

python -c "import secrets; print(secrets.token\_hex(32))"

```



\## Endpoints

\- `POST /auth/login`, `GET /auth/me`

\- `POST /documents`, `GET /documents`, `GET /documents/{id}/download`, `PUT /documents/{id}`, `DELETE /documents/{id}`

\- `POST /documents/{id}/share`, `GET /documents/{id}/shares`, `DELETE /documents/{id}/share/{user\_id}`

\- `GET /admin/audit`, `GET /admin/audit/verify` (admin only)



\## Tests

```

python -m pytest -v

```

The tests use a temporary database, so your real data and audit log are not touched.



\## Security notes

See \[THREATS.md](THREATS.md) for the threat model and known gaps.

