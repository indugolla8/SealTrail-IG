# PROMPTS.md

## Entry 1 - 6 Nov 2026
Tool: Claude (chat)
Asked: how to set up the repo and run the project.
AI produced: setup commands for a Flask project, including `pip freeze > requirements.txt`.
What was wrong: my project is FastAPI, and that command overwrote the project's real requirements.txt with only Flask and pytest.
What I did instead: I noticed from the git log that the project was already FastAPI, restored the file with `git checkout -- requirements.txt`, and reinstalled from it. All 30 tests pass.

## Entry 2 - 6 Nov 2026
Tool: Claude (chat)
Asked: how to clone the repo and set up the project.
AI produced: commands without saying which folder to run them in.
What was wrong: I ran them in C:\Windows\system32 and git could not create the folder (permission denied).
What I did instead: moved to my Documents folder and cloned again there.

## Entry 3 - 9 Nov 2026 (authorisation)
Tool: Claude (chat)
Asked: to check my app against the ten requirements in the brief.
AI produced: a table saying categories and search looked missing, based only on my endpoint list.
What was wrong: the web UI does have a category field and a search-by-name box. I also tested authorisation on the live site: a viewer with a read share tried to rename a document, the server refused it with 404, and the audit log recorded it as denied ("needs edit, has read").
What I did instead: kept the feature and noted that search covers names only and that the Rename button still shows for read-only users.

## Entry 4 - 9 Nov 2026 (audit trail)
Tool: Claude (chat)
Asked: how to check the audit log on the deployed site.
AI produced: steps to call /admin/audit and /admin/audit/verify as admin.
What was wrong: nothing wrong found. The log showed uploads, a delete, a share and the denied edit, and verify returned valid: true.
What I did instead: kept the log as is and noted which actions I had checked.
