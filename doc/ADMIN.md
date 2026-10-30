# Administering Anubis

Single instance only (`multi_instance = false`): the package manages
machine-global resources (per-domain nginx fragments, a shared client-IP map)
and fixed loopback ports (8923/8924/9090).

## Web GUI

Open the Anubis tile in the YunoHost portal (or https://your-domain/ if
installed at root) as an admin: tick the domains to protect, set the
challenge difficulty, and press **Apply**. Nginx is tested (`nginx -t`) and
reloaded automatically; if a fragment would break nginx, the change is
reverted and the GUI reports the error.

The domain hosting the GUI itself cannot be protected (you would lock the
panel behind the challenge).

To change difficulty without the GUI:

    sudo yunohost app config get anubis
    sudo yunohost app config set anubis -a "difficulty=5"

## How it works

```
 browser ──HTTPS──> nginx vhost (per protected domain)
                      │  rewrite_by_lua gate (gate.lua)
                      │     ├─ cosocket -> 127.0.0.1:8923 /api/check
                      │     │     X-Real-IP <- CF-Connecting-IP / $remote_addr
                      │     ├─ 401 -> 307 /.within.website/?redir=...  (challenge)
                      │     ├─ 403 -> blocked (explicit DENY rule)
                      │     └─ other -> continue to ssowat access phase -> app
                      └─ /.within.website/ -> Anubis challenge UI
```

Key points:

- The check runs in nginx' **rewrite** phase, i.e. *before* ssowat's access
  phase: bots are challenged before they reach the SSO login.
- `gate.lua` calls the check endpoint over a Lua **cosocket**, not
  `ngx.location.capture` - the latter raises "http2 requests not supported
  yet" inside HTTP/2 connections, which YunoHost vhosts speak, and a
  pcall-wrapped error silently fails the gate open.
- A managed policy file (`policy.yaml`, shipped by the package) sets
  `status_codes: {CHALLENGE: 401, DENY: 403}` explicitly. Without it the
  Anubis check API answers DENY with HTTP 200 and the gate cannot tell a
  blocked bot from an allowed visitor. The policy also allows
  private/loopback ranges so local tooling is never gated.
- Per protected domain, a managed fragment
  `/etc/nginx/conf.d/<domain>.d/zz-anubis.conf` is written; disabling
  protection removes it. A global `map` for the real client IP behind
  Cloudflare lives in `/etc/nginx/conf.d/anubis-client-ip.conf`.
- `/.well-known/*`, `/yunohost/*` and the GUI's own host are never
  challenged; if Anubis is down the gate **fails open**.
- Settings (`protected_domains`, `difficulty`, `hs512_secret`) live in the
  app settings; the root-owned helper
  `/usr/local/bin/anubis-ynh-apply` renders everything (the Flask webui
  calls it through a narrow sudoers rule).
- The GUI itself is SSO-gated: nginx only reaches it after ssowat
  authentication; ssowat's `YNH_USER` header is re-forwarded by the vhost
  fragment as `Ynh-User` because the waitress WSGI server silently drops
  underscore header names. The webui unit deliberately has no
  NoNewPrivileges/seccomp sandbox options so its sudo helper call works.

## CLI

    sudo anubis-ynh-apply status      # current state as JSON
    sudo anubis-ynh-apply render      # re-render fragments + reload nginx
    sudo anubis-ynh-apply set --domains "a.example.com,b.example.com"
