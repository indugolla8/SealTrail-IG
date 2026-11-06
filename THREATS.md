\# SealTrail-IG Threat Model



\## What we protect

Uploaded documents, who can access them, and a trustworthy record of every access attempt.



\## Roles

\- \*\*owner\*\*: uploads documents, shares and revokes access, edits and deletes their own documents.

\- \*\*viewer\*\*: reads or edits only documents shared with them.

\- \*\*admin\*\*: manages users and reads the audit log. Admins cannot read file contents (deliberate choice).



\## Threats and mitigations



| Threat | Mitigation | Where |

|---|---|---|

| User opens another user's document | Central `check\_access` on every document route; fresh DB lookup each request | permissions.py |

| Probing which document IDs exist | No access returns 404, same as missing; real reason goes only to the audit log | permissions.py |

| Viewer escalates by sharing or deleting | Share and delete are owner-only | permissions.py, sharing.py |

| Access lingers after revoke | No caching; revoke deletes the permission row and applies on the next request | sharing.py |

| Non-admin reads audit log | Admin-only routes; denied attempts are logged | admin.py |

| Audit log tampering | Hash-chained entries; `/admin/audit/verify` detects edited or removed rows | audit.py |

| Malicious upload (wrong type) | Extension allowlist plus magic-byte check for pdf/png/jpg | documents.py |

| Oversized upload | 5 MB limit, read with a cap | documents.py |

| Path traversal via filename | `os.path.basename`; files stored under random UUID names | documents.py |

| Sharing with admin to bypass the content rule | Sharing with admins is rejected | sharing.py |



\## Known gaps (accepted for now)

\- Audit chain is tamper-evident, not tamper-proof: someone with full database access could rewrite the whole chain.

\- No rate limiting or lockout on login.

\- `.txt` files have no content check.

\- Deleted documents are soft-deleted; the file stays on disk.

\- Files are stored unencrypted on disk.

\- Runs over plain HTTP locally; production needs HTTPS and a strong secret key from the environment.

\- Tokens expire after 2 hours but cannot be revoked earlier.

\- SECRET\_KEY must be set in production (SEALTRAIL\_ENV=prod); the app refuses to start without it.

