Anubis is a proof-of-work bot shield that sits in front of your YunoHost
domains. Bots get a JavaScript challenge before they ever reach your apps
(or even the SSO login page); real visitors pass once and get a cookie.

This package runs the upstream Go binary natively (no Docker) and adds a
small web GUI, reachable from the YunoHost portal, where you tick exactly
which domains/subdomains should be protected - e.g. protect
`captcha.example.com` while leaving your blog open.

Notable behavior:

- The check happens in nginx' *rewrite* phase, so Anubis challenges bots
  **before** ssowat's access phase - the SSO login page itself is shielded.
- `/.well-known/*`, `/yunohost/*` and the Anubis GUI location are never
  challenged, so certificates and the portal keep working.
- If Anubis goes down, requests **fail open** (sites stay reachable).
- The GUI is permission-gated (admins by default) and only lets you manage
  domains that exist on the server (`yunohost domain list`).
