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
    anubis-ynh-apply policy-get
        -> JSON: current policy.yaml content (raw text)
    anubis-ynh-apply policy-set
        -> reads policy YAML on stdin, validates (YAML + rule schema +
           Anubis accepting it), atomically installs, restarts anubis
"""

import argparse
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile

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


# ---------------------------------------------------------------- policy


# Key lists transcribed from upstream lib/config/config.go (BotConfig,
# fileConfig, ChallengeRules, Weight, Threshold) so the GUI rejects what
# anubis rejects and accepts what anubis accepts.
POLICY_KEYS = ("status_codes", "bots", "import", "metrics", "impressum",
               "store", "logging", "honeypot", "thresholds", "geoip",
               "openGraph", "dnsbl", "dns_ttl")
BOT_KEYS = ("name", "action", "user_agent_regex", "path_regex",
            "headers_regex", "expression", "challenge", "weight",
            "remote_addresses", "remote_addresses_url", "geoip", "asns",
            "import")
ACTIONS = ("ALLOW", "DENY", "CHALLENGE", "WEIGH", "DEBUG_BENCHMARK")
CHALLENGE_KEYS = ("difficulty", "algorithm")
CHALLENGE_ALGOS = ("fast", "slow", "metarefresh")


def policy_path(s):
    return os.path.join(s["install_dir"], "policy.yaml")


def policy_get(s):
    path = policy_path(s)
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        content = ""
    print(json.dumps({"policy": content}))


def _validate_bot(bot, idx):
    """Validate one bot rule from the policies doc; returns error or None."""
    if not isinstance(bot, dict):
        return f"rule #{idx}: must be a mapping"
    if "import" in bot:
        # upstream ships nameless import snippets (e.g. (data)/bots/*.yaml);
        # anubis accepts them, so only require the import value to be a string
        if not isinstance(bot["import"], str) or not bot["import"].strip():
            return f"rule #{idx}: 'import' must be a non-empty string"
        unknown = [k for k in bot if k not in BOT_KEYS]
        if unknown:
            return f"rule #{idx}: unknown key(s): {', '.join(unknown)}"
        return None
    name = bot.get("name")
    if not name or not isinstance(name, str):
        return f"rule #{idx}: missing or invalid 'name'"
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        return (f"rule '{name}': name must be lower-case kebab-case "
                f"(rule names are exposed in Prometheus metrics)")
    action = bot.get("action")
    if action not in ACTIONS:
        return (f"rule '{name}': action must be one of {', '.join(ACTIONS)}")
    matchers = ("user_agent_regex", "path_regex", "headers_regex",
                "remote_addresses", "expression")
    if action == "WEIGH" and "weight" not in bot:
        return f"rule '{name}': WEIGH rules need a 'weight' block"
    if action != "WEIGH" and not any(k in bot for k in matchers):
        return (f"rule '{name}': needs at least one matcher "
                f"({', '.join(matchers)}) or 'remote_addresses'")
    unknown = [k for k in bot if k not in BOT_KEYS]
    if unknown:
        return f"rule '{name}': unknown key(s): {', '.join(unknown)}"
    for rx in ("user_agent_regex", "path_regex"):
        v = bot.get(rx)
        if v is not None:
            try:
                re.compile(v)
            except re.error as e:
                return f"rule '{name}': invalid {rx} '{v}': {e}"
    hr = bot.get("headers_regex")
    if hr is not None:
        if not isinstance(hr, dict) or not hr:
            return f"rule '{name}': headers_regex must be a non-empty mapping"
        for h, v in hr.items():
            if not isinstance(h, str) or not isinstance(v, str):
                return f"rule '{name}': headers_regex entries must be strings"
            try:
                re.compile(v)
            except re.error as e:
                return f"rule '{name}': invalid headers_regex '{v}': {e}"
    ra = bot.get("remote_addresses")
    if ra is not None:
        if not isinstance(ra, list) or not ra or \
           not all(isinstance(x, str) for x in ra):
            return f"rule '{name}': remote_addresses must be a list of CIDRs"
    ch = bot.get("challenge")
    if ch is not None:
        if not isinstance(ch, dict):
            return f"rule '{name}': challenge must be a mapping"
        bad = [k for k in ch if k not in CHALLENGE_KEYS]
        if bad:
            return f"rule '{name}': unknown challenge key(s): {', '.join(bad)}"
        if "difficulty" in ch and (not isinstance(ch["difficulty"], int)
                                   or not 0 <= ch["difficulty"] <= 99):
            return f"rule '{name}': challenge.difficulty must be an integer 0-99"
        if "algorithm" in ch and ch["algorithm"] not in CHALLENGE_ALGOS:
            return (f"rule '{name}': challenge.algorithm must be one of "
                    f"{', '.join(CHALLENGE_ALGOS)}")
    w = bot.get("weight")
    if w is not None:
        if not isinstance(w, dict) or "adjust" not in w:
            return f"rule '{name}': weight must be a mapping with 'adjust'"
        if not isinstance(w["adjust"], int):
            return f"rule '{name}': weight.adjust must be an integer"
    return None


def _validate_policy_text(text):
    """Full validation: YAML parse + doc-schema rules. Returns (data, err)."""
    try:
        import yaml
    except ImportError:
        return None, "PyYAML not available on this server"
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, f"YAML parse error: {e}"
    if data is None:
        return {}, "empty policy"
    if not isinstance(data, dict):
        return None, "policy must be a mapping (bots:, status_codes:, ...)"
    unknown = [k for k in data if k not in POLICY_KEYS]
    if unknown:
        return None, f"unknown top-level key(s): {', '.join(unknown)}"
    sc = data.get("status_codes")
    if sc is not None:
        if not isinstance(sc, dict):
            return None, "status_codes must be a mapping"
        for k, v in sc.items():
            if k not in ("CHALLENGE", "DENY"):
                return None, f"status_codes: unknown action '{k}'"
            if not isinstance(v, int) or not 100 <= v <= 599:
                return None, f"status_codes.{k} must be an HTTP code 100-599"
    bots = data.get("bots")
    if bots is not None:
        if not isinstance(bots, list):
            return None, "bots must be a list of rules"
        seen = set()
        for i, bot in enumerate(bots, 1):
            err = _validate_bot(bot, i)
            if err:
                return None, err
            nm = bot.get("name")
            if nm:
                if nm in seen:
                    return None, f"duplicate rule name '{nm}'"
                seen.add(nm)
        return data, None


def _install_policy(text, s):
    """Shared install pipeline: validate, dry-run, atomically install,
    restart, health-probe. Used by policy-set and policy-reset."""
    data, err = _validate_policy_text(text)
    if err:
        fail(f"invalid policy: {err}")

    path = policy_path(s)

    # Atomic install: write temp file in the same dir, validate with a live
    # anubis instance on a scratch port, then rename + restart.
    with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(path),
                                     prefix=".policy-", delete=False) as tf:
        tf.write(text)
        tmp = tf.name
    try:
        os.chmod(tmp, 0o644)
        probe = run([os.path.join(s["install_dir"], "bin", "anubis"),
                     "-bind", "127.0.0.1:0", "-policy-fname", tmp,
                     "-difficulty", "1", "-healthcheck"])
        if probe.returncode != 0:
            fail("anubis rejected the policy: "
                 f"{(probe.stderr or probe.stdout).strip()[-400:]}")
        # keep root ownership of the policy file (it is not app-writable)
        os.replace(tmp, path)
        os.chown(path, 0, 0)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    r = run(["systemctl", "restart", app])
    if r.returncode != 0:
        fail(f"anubis failed to restart: {r.stderr.strip()[-300:]}")
    # confirm it actually came up and answers checks. Any HTTP response
    # (401 challenge / 403 deny / 502 no-target) proves it is serving;
    # curl -sf would false-fail on those.
    import time
    for _ in range(20):
        chk = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   f"http://127.0.0.1:{s['port']}/.within.website/x/cmd/anubis/api/check"])
        code = (chk.stdout or "").strip()
        if code.isdigit() and 100 <= int(code) <= 599:
            break
        time.sleep(0.5)
    else:
        fail("anubis did not become healthy after policy change")
    return data


def policy_set(s):
    text = sys.stdin.read()
    _install_policy(text, s)
    print(json.dumps({"ok": True}))


def policy_reset(s):
    # The pristine package default lives in the app registry
    # (/etc/yunohost/apps/<app>/conf/policy.yaml) and is refreshed by every
    # upgrade, so "default" always means "what this package ships".
    default = load_template("policy.yaml")
    if not default:
        fail("package default policy not found in the app registry")
    _install_policy(default, s)
    print(json.dumps({"ok": True}))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    sp = sub.add_parser("set")
    sp.add_argument("--domains", default=None)
    sp.add_argument("--difficulty", type=int, default=None)
    sp = sub.add_parser("status")
    sub.add_parser("render")
    sub.add_parser("policy-get")
    sub.add_parser("policy-set")
    sub.add_parser("policy-reset")
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

        if args.mode == "policy-get":
            policy_get(s)
            return

        if args.mode == "policy-set":
            policy_set(s)
            return

        if args.mode == "policy-reset":
            policy_reset(s)
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
