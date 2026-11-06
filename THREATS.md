# SealTrail-IG Threat Model

## What we protect
Uploaded documents, who can access them, and a trustworthy record of every access attempt.

## Roles
- **owner**: uploads documents, shares and revokes access, edits, deletes and restores their own documents, and views the access history of their documents.
- **viewer**: reads or edits only documents shared with them.
- **admin**: manages users and reads the audit log. Admins cannot read file contents (deliberate choice).

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| User opens another user's document | Central `check_access` on every document route; fresh DB lookup each request | permissions.py |
| Probing which document IDs exist | No access returns 404, same as missing; real reason goes only to the audit log | permissions.py |
| Viewer escalates by sharing or deleting | Share and delete are owner-only | permissions.py, sharing.py |
| Access lingers after revoke | No caching; revoke deletes the permission row and applies on the next request | sharing.py |
| Non-admin reads audit log | Admin-only routes; denied attempts are logged | admin.py |
| Audit log tampering | Hash-chained entries; `/admin/audit/verify` detects edited or removed rows | audit.py |
| Malicious upload (wrong type) | Extension allowlist plus magic-byte check for pdf/png/jpg | documents.py |
| Oversized upload | 5 MB limit, read with a cap | documents.py |
| Path traversal via filename | `os.path.basename`; files stored under random UUID names | documents.py |
| Sharing with admin to bypass the content rule | Sharing with admins is rejected | sharing.py |
| Password guessing | 5 failed logins per email in 10 minutes returns 429; lockouts are audited | auth.py |
| Forged login tokens | Signed JWTs with pinned algorithm; SECRET_KEY from environment, app refuses to start in prod without it | security.py |
| Owner can't see who touches their documents | Owner-only history from the audit log, including denied attempts | lifecycle.py |
| Someone restores another user's deleted document | Restore is owner-only; non-owners get the same 404 as a missing document; restores are audited | lifecycle.py |
| Rename used to disguise a file type | Rename must keep the original extension, which must be on the allowlist | documents.py |

## Known gaps (accepted for now)
- Audit chain is tamper-evident, not tamper-proof: someone with full database access could rewrite the whole chain.
- Audit writes are not serialized: under heavy concurrent load two entries could chain from the same predecessor and make verification fail.
- Login lockout is in memory: it resets on restart and is not shared across multiple workers. It is per email, not per IP.
- An attacker can deliberately lock a known email out for 10 minutes (denial of service on that account).
- `.txt` files have no content check.
- Deleted documents are soft-deleted; the file stays on disk. Restore only clears the soft-delete flag, and there is no permanent-delete or retention policy.
- Files are stored unencrypted on disk.
- Runs over plain HTTP locally; production needs HTTPS.
- Tokens expire after 2 hours but cannot be revoked earlier.
- SECRET_KEY must be set in production (SEALTRAIL_ENV=prod); the app refuses to start without it.
