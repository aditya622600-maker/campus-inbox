# Campus Inbox

A privacy-conscious student inbox that classifies college email into **Critical**, **Worth a look**, and **Low priority** using transparent rules.

## Current demo

- Prioritizes exams, assignments, deadlines, and academic warnings
- Marks attendance below 75% as critical
- Surfaces hackathons, internships, placements, and scholarships as opportunities
- Filters newsletters, ordinary club promotions, and surveys
- Explains every classification
- Supports priority filters, search, and sorting
- Responsive on desktop and mobile
- Runs entirely in the browser with fictional sample messages

## Run locally

Install dependencies, create the local environment file, and start the server:

```powershell
npm install
Copy-Item .env.example .env
npm start
```

Open `http://localhost:3000`. OAuth cannot complete from the static `file://` page.

## Connect Gmail with OAuth

1. Create a Google Cloud project and enable the Gmail API.
2. Configure the Google Auth Platform consent screen.
3. Keep the app in **Testing** and add your Gmail address as a test user.
4. Create an OAuth client of type **Web application**.
5. Add this exact redirect URI: `http://localhost:3000/auth/google/callback`.
6. Put the client ID and client secret in `.env`.
7. Start the server and click **Connect Gmail**.

The app requests only `gmail.readonly`. Tokens remain in server memory and disappear when the server restarts.

Each browser receives a signed, HTTP-only session cookie. Gmail tokens and OAuth state are isolated inside that browser's server-side session instead of being shared globally. Set `SESSION_SECRET` to a random value of at least 32 characters; production cookies require HTTPS.

OAuth tokens are encrypted with AES-256-GCM before entering session storage. Set `TOKEN_ENCRYPTION_KEY` to a base64-encoded 32-byte random key and keep it outside source control. Authenticated encryption detects accidental or malicious changes to the ciphertext.

The current dashboard loads up to 75 messages received during the last 30 days.

## Database cache

Downloaded messages are classified once and cached in the local SQLite database `.data/campus-inbox.db`. Updates use a transaction so a failed write cannot leave a partially updated cache. Later refreshes reuse unchanged messages and call `messages.get` only for new message IDs. The database stores message ID, sender, subject, a 240-character preview, date, priority, and reason; it does not store the full email body. The `.data` directory is excluded from Git.

During the ownership upgrade, old unscoped cache records are removed and safely rebuilt from Gmail under the connected user's private owner ID.

Every cache row is scoped by a private owner ID derived from the connected Gmail address with a keyed HMAC. The database does not store the Gmail address itself. All reads, inserts, and deletions require the session's owner ID, and `(owner_id, message_id)` is the composite primary key. Set `DATA_OWNERSHIP_KEY` to a base64-encoded 32-byte random key.

Disconnecting Gmail is a CSRF-protected POST action. It revokes the Google refresh token when available (falling back to the access token), destroys the local server session, and clears the signed browser cookie. If Google revocation is temporarily unavailable, the local logout still completes and the UI tells the user to remove access from Google Account permissions manually.

The settings dialog includes a CSRF-protected **Delete my data** action. It deletes only database rows matching the current session's owner ID, revokes Google access, destroys the local session, and clears the cookie. It never deletes or modifies messages in Gmail.

## HTTP security

- Helmet sets Content Security Policy, clickjacking protection, MIME protections, and a no-referrer policy.
- Production uses an HTTPS-only `__Host-` session cookie; local development uses a non-secure localhost cookie.
- OAuth, Gmail refresh, and account-mutation routes have separate IP-based rate limits.
- Express fingerprinting is disabled.
- Unexpected errors return a generic message and reference ID while technical details remain server-side.

## Legal pages

The dashboard links to `/privacy.html` and `/terms.html`. The privacy policy documents Gmail access, classification, storage, retention, deletion, sharing, security and Google API Limited Use compliance. Replace the temporary contact wording with a dedicated public support email before launch.

## Production hosting

The included Render Blueprint deploys the Node backend with a private persistent disk mounted at `/var/data`. The SQLite database stores both encrypted server-side sessions and the user-isolated email cache, so restarts do not sign everyone out or erase cached classifications.

Set all six production secrets in the Render dashboard; never copy `.env` into Git. `GOOGLE_REDIRECT_URI` must use the final HTTPS hostname and end in `/auth/google/callback`. A persistent disk requires a paid Render web-service instance. Do not deploy this SQLite configuration to Vercel or to a free service with an ephemeral filesystem.

## Classification design

The MVP is deliberately rule-based. This makes decisions predictable and explainable. A later version can add a machine-learning fallback for ambiguous messages while retaining hard safety rules such as `attendance < 75%`.

## Important

All messages included in this repository are fictional. Do not commit real emails, OAuth client secrets, access tokens, refresh tokens, student IDs, or personal information.
