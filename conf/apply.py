#!/usr/bin/env python3
"""
anubis-ynh-apply - regenerate Anubis nginx gates / env from app settings.

Root-owned helper for the YunoHost `anubis` app (invoked via sudo from the
webui, or directly by the packaging scripts).

Modes:
    anubis-ynh-apply status
        -> JSON on stdout: current domain list + protection state
    anubis-ynh-apply set --domains "a.com,b.com" [--difficulty N]
        -> validate domains, store settings, regenerate, nginx -t, reload
    anubis-ynh-apply render
        -> regenerate everything from current settings (no setting change)
"""

import argparse
import json
import os
import pwd
import re
import subprocess
import sys

APP_DEFAULT = "anubis"
CONF_D = "/etc/nginx/conf.d"
FRAGMENT_NAME = "zz-anubis.conf"
REGISTRY = "/etc/yunohost/apps"

app = os.environ.get("ANUBIS_APP", APP_DEFAULT)


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def setting(key, value=None):
    cmd = ["yunohost", "app", "setting", app, key]
    if value is not None:
        cmd += ["-v", value]
    r = run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"setting {key}: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip()


def all_domains():
    r = run(["yunohost", "domain", "list", "--output", "json"])
    if r.returncode != 0:
        raise RuntimeError(f"domain list: {r.stderr.strip()}")
    return sorted(json.loads(r.stdout)["domains"])


def parse_list(raw):
    return sorted({d.strip().lower() for d in (raw or "").split(",") if d.strip()})


def load_template(name):
    # The registry copy lives at /etc/yunohost/apps/<app>/conf/<name> after
    # install; we also keep a copy in the install dir (backed up with the app).
    for path in (
        os.path.join(REGISTRY, app, "conf", name),
        os.path.join(SETTING_CACHE["install_dir"], name),
    ):
        if os.path.isfile(path):
            with open(path) as f:
                return f.read()
    raise RuntimeError(f"template {name} not found")


SETTING_CACHE = {}


def get_settings():
    s = {k: setting(k) for k in (
        "port", "port_metrics", "port_webui", "install_dir",
        "difficulty", "hs512_secret", "domain", "path", "protected_domains",
    )}
    s["path"] = s["path"] or "/"
    if not s["hs512_secret"]:
        fail("hs512_secret setting is empty - reinstall or set it manually")
    return s


def render(text, mapping):
    for k, v in mapping.items():
        text = text.replace(f"__{k.upper()}__", str(v))
    leftovers = set(re.findall(r"__[A-Z0-9_]+__", text))
    if leftovers:
        raise RuntimeError(f"unrendered template vars: {sorted(leftovers)}")
    return text


def write_fragment(domain, mapping, uid):
    body = render(load_template("domain-fragment.conf"), mapping)
    frag = os.path.join(CONF_D, f"{domain}.d", FRAGMENT_NAME)
    os.makedirs(os.path.dirname(frag), exist_ok=True)
    tmp = frag + ".new"
    with open(tmp, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o640)
    os.replace(tmp, frag)


def remove_fragment(domain):
    frag = os.path.join(CONF_D, f"{domain}.d", FRAGMENT_NAME)
    if os.path.exists(frag):
        os.remove(frag)


CLIENT_IP_MAP = """\
# Managed by the Anubis YunoHost app - real client IP behind Cloudflare.
map $http_cf_connecting_ip $anubis_client_ip {
    default $http_cf_connecting_ip;
    "" $remote_addr;
}
"""


def ensure_client_ip_map():
    path = os.path.join(CONF_D, "anubis-client-ip.conf")
    if not os.path.exists(path) or open(path).read() != CLIENT_IP_MAP:
        with open(path, "w") as f:
            f.write(CLIENT_IP_MAP)


def remove_client_ip_map():
    path = os.path.join(CONF_D, "anubis-client-ip.conf")
    if os.path.exists(path):
        os.remove(path)


def render_env(s, uid):
    lines = [
        f"BIND=127.0.0.1:{s['port']}",
        f"METRICS_BIND=127.0.0.1:{s['port_metrics']}",
        f"DIFFICULTY={s['difficulty'] or 4}",
        f"HS512_SECRET={s['hs512_secret']}",
        f"REDIRECT_DOMAINS={s['protected_domains']}",
        "COOKIE_SECURE=true",
        "SLOG_LEVEL=INFO",
    ]
    env_path = os.path.join(s["install_dir"], "anubis.env")
    with open(env_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(env_path, 0o640)
    os.chown(env_path, uid, -1)


def apply(protected, s):
    # The GUI host must never be protected, or admins could lock themselves
    # out of the panel (the gate only exempts the GUI *location*, and at
    # path=/ that is the whole site).
    if s["domain"] in protected:
        fail(f"'{s['domain']}' hosts the Anubis GUI itself and cannot be protected")
    uid = pwd.getpwnam(app).pw_uid
    mapping = {
        "APP": app,
        "PORT": s["port"],
        "INSTALL_DIR": s["install_dir"],
    }
    gate_mapping = dict(
        mapping,
        GUARD_DOMAIN=s["domain"],
        GUARD_PREFIX=(s["path"].rstrip("/") if s["path"] not in ("", "/") else ""),
    )
    domains = all_domains()
    for d in domains:
        if d in protected:
            write_fragment(d, dict(mapping, DOMAIN=d), uid)
        else:
            remove_fragment(d)

    # gate.lua - single shared file; excludes the GUI's own location by
    # host+prefix so admins can always reach the panel to toggle protection.
    gate = render(load_template("gate.lua"), gate_mapping)
    gate_path = os.path.join(s["install_dir"], "gate.lua")
    with open(gate_path, "w") as f:
        f.write(gate)
    os.chmod(gate_path, 0o644)

    render_env(s, uid)
    ensure_client_ip_map()

    if run(["nginx", "-t"]).returncode != 0:
        for d in domains:
            remove_fragment(d)
        remove_client_ip_map()
        run(["nginx", "-t"])
        fail("nginx -t failed with anubis fragments (server-level "
             "rewrite_by_lua conflict?); protection NOT applied")

    run(["systemctl", "restart", app])
    run(["systemctl", "reload", "nginx"])


def status(s):
    protected = parse_list(s["protected_domains"])
    out = []
    for d in all_domains():
        dom_dir = os.path.join(CONF_D, f"{d}.d")
        frag = os.path.join(dom_dir, FRAGMENT_NAME)
        out.append({
            "domain": d,
            "protected": os.path.exists(frag),
            "has_vhost": os.path.isdir(dom_dir),
            "is_app_domain": d == s["domain"],
            "requested": d in protected,
        })
    print(json.dumps({
        "domains": out,
        "difficulty": int(s["difficulty"] or 4),
        "anubis_running": run(["systemctl", "is-active", app]).stdout.strip() == "active",
        "nginx_running": run(["systemctl", "is-active", "nginx"]).stdout.strip() == "active",
    }))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    sp = sub.add_parser("set")
    sp.add_argument("--domains", default=None)
    sp.add_argument("--difficulty", type=int, default=None)
    sub.add_parser("status")
    sub.add_parser("render")
    sub.add_parser("remove-all")
    args = p.parse_args()

    try:
        s = get_settings()
    except RuntimeError as e:
        fail(f"app '{app}' not installed or unreadable: {e}")
    SETTING_CACHE["install_dir"] = s["install_dir"]

    try:
        if args.mode == "status":
            status(s)
            return

        if args.mode == "set":
            if args.difficulty is not None:
                if not 0 <= args.difficulty <= 8:
                    fail("difficulty must be 0-8")
                setting("difficulty", str(args.difficulty))
                s["difficulty"] = str(args.difficulty)
            if args.domains is not None:
                wanted = parse_list(args.domains)
                bad = [d for d in wanted if d not in all_domains()]
                if bad:
                    fail(f"unknown domain(s): {', '.join(bad)}")
                setting("protected_domains", ",".join(wanted))
                s["protected_domains"] = ",".join(wanted)
            apply(parse_list(s["protected_domains"]), s)
            print(json.dumps({"ok": True, "protected": parse_list(s["protected_domains"])}))
            return

        if args.mode == "render":
            apply(parse_list(s["protected_domains"]), s)
            print(json.dumps({"ok": True}))
            return

        if args.mode == "remove-all":
            for d in all_domains():
                remove_fragment(d)
            remove_client_ip_map()
            if run(["nginx", "-t"]).returncode == 0:
                run(["systemctl", "reload", "nginx"])
            print(json.dumps({"ok": True}))
            return
    except RuntimeError as e:
        fail(str(e))


if __name__ == "__main__":
    main()
