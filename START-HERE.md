# Secret — one-time password sharing

## Deploy
1. Create a new GitHub repository and upload this folder's contents at its root.
2. In Cloudflare Workers & Pages, create a Worker connected to that repository. Name it **secret** (or change `name` in wrangler.json to match).
3. Leave the build command empty. Deploy command: `npx wrangler deploy`.
4. Open the Worker → Settings → **Runtime variables and secrets** (not build variables). Add both as **Secret**:
   - `ADMIN_PASSWORD`: your own strong sender login password, at least 16 characters.
   - `SMTP_PASSWORD`: your SMTP2GO SMTP user's password.
5. Save/deploy the settings. Open the Worker URL, sign in and create a test link addressed to yourself. Request a code, verify, reveal, and then confirm the same link cannot reveal again.
6. Optionally add your own hostname under Domains & Routes (for example secret.cl1p.xyz).

The SMTP username and sender are preconfigured as noreply@cl1p.xyz, host mail.smtp2go.com, port 465 with implicit TLS. Check SMTP2GO → Sending → SMTP Users for the credentials, and Verified Senders for authorization to send from cl1p.xyz. A mailbox password is not necessarily an SMTP2GO SMTP user password. Never commit passwords to GitHub or paste them into wrangler.json. The supplied credential is NOT included in this project.

Cloudflare creates the Durable Object binding and storage automatically. No D1 database ID, SQL import, API key, or external server is required. Keep the migration and binding in wrangler.json on subsequent deployments.

## Using it
Sender logs in, enters the intended email, a password/note, and expiration (5 minutes–48 hours). Copy the entire generated link, including the part after `#`, and send it to that recipient. Creating a link does not automatically email it.

Recipient enters the matching email, requests a six-digit code, verifies, and deliberately clicks Reveal password. Opening the link, a preview or a security scanner's GET cannot consume it. Copy the revealed secret before closing or refreshing. The page clears it after five minutes. It does not erase the system clipboard.

## Protections and limits
- Browser AES-256-GCM encryption with a fresh random key and IV per share. The key is in the URL fragment, not uploaded to the server. Keep the full URL private. No short dictionary codes for sensitive links.
- Only encrypted payload, recipient email, expiration and verification state are stored. Email codes never contain the secret or decryption key.
- Codes last up to 10 minutes, verification grants up to 5 minutes, never beyond link expiry. A link permits 5 code sends total, with a 60-second resend cooldown, and 10 verification attempts total. A successful code is consumed; a resend invalidates earlier codes and grants.
- Serialized Durable Object handling prevents concurrent double retrieval. Active stored data is removed BEFORE delivering the encrypted payload. A dropped response may consume the link without displaying the secret: create a new link in that case. There is deliberately no retry recovery.
- Expiration is checked on every request; an alarm deletes unused expired data. Platform alarms can run late, but expired secrets cannot be retrieved.
- Deletion means removal from active application storage, not a guarantee of immediate physical erasure from provider backups. Cloudflare may retain platform recovery data. Encryption keys are not stored there. The hosting operator controls the JavaScript and must remain trusted.
- No app analytics or request-body logging. Observability disabled in config. Provider-level metadata and SMTP provider delivery records may remain; never enable payload logging. Email addresses and codes are handled by SMTP2GO.
- Admin sessions last 8 hours. Same-origin POSTs, HttpOnly/Secure/SameSite cookie, no-store responses, CSP, and no external scripts. Changing ADMIN_PASSWORD invalidates sessions and pending verification codes/grants; recipients must request new codes.
- Per-IP rate limits: 30 API requests/minute, 5 login attempts/minute. These are Cloudflare edge limits, not a global spending cap. Usage/provider charges follow your plans.
- Max note 8 KB UTF-8 (UI also limits to 4,000 characters). Standard ASCII email addresses supported.

## Troubleshooting
- Setup message: add secrets under Runtime variables, not Builds. ADMIN_PASSWORD must have at least 16 characters.
- Email fails: confirm SMTP User credentials, verified sender/domain, account quota, and SMTP2GO activity. Wait one minute before retrying. SMTP uses port 465 TLS; never switch this implementation to port 587 without adding STARTTLS support.
- Incomplete link: retain the full `#...` fragment; some link rewriting tools may drop it.
- Expired/used/verification limit: create a new link. Deleted passwords cannot be recovered by the app.

## Development / validation
`npm ci`, `npm test`, `npx wrangler deploy --dry-run`.
Tests cover encryption roundtrip, expiry, code limits/reuse, SMTP failure state, simultaneous reveal, admin auth, origin validation, cache headers and GET safety. SMTP transport is tested with a simulated server. Runtime and browser checks were performed separately. Real SMTP2GO delivery must be verified after deployment.

References: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/ and https://developers.smtp2go.com/docs/smtp-relay
