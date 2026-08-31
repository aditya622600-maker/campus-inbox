# Security Policy

Campus Inbox handles private Gmail metadata and OAuth credentials. Never include a
client secret, access token, refresh token, `.env` file, database file, or cached
email data in a Git commit, screenshot, issue, or message.

## Reporting a security problem

Do not post secrets or private email information in a public GitHub issue. Until a
dedicated security contact is published, describe the problem without private data
to the repository owner through a private channel.

If a credential may have been exposed, rotate the Google OAuth client secret in
Google Cloud immediately. Users can also disconnect Campus Inbox from their Google
Account permissions and use **Delete my data** in the app.

## Before committing

Run:

```bash
npm run verify:repo
```

The repository intentionally excludes local environment files, OAuth tokens,
SQLite databases, cached messages, dependencies, and local logs.
