#!/usr/bin/env python3
"""Anubis YunoHost admin GUI.

Reached only through the SSO-gated 'main' permission (admins by default),
so the identity injected by ssowat (YNH_USER) is trusted. All privileged
actions go through the root-owned /usr/local/bin/anubis-ynh-apply helper.
"""

import json
import subprocess

from flask import Flask, jsonify, render_template, request

APPLY_BIN = "/usr/local/bin/anubis-ynh-apply"
APP = None  # set from env in create_app

# Friendly menu of upstream rule packs shipped inside the anubis binary
# ((data)/... paths). Kept in sync with TecharoHQ/anubis v1.28.1.
RULE_PACKS = [
    {"value": "(data)/bots/_deny-pathological.yaml", "label": "Pathological bots",
     "effect": "Deny headless browsers, cloud scrapers, fake and ancient user agents"},
    {"value": "(data)/bots/ai-catchall.yaml", "label": "AI bots (catch-all)",
     "effect": "Deny undocumented and unknown AI/LLM bots"},
    {"value": "(data)/crawlers/ai-training.yaml", "label": "AI training crawlers",
     "effect": "Deny bots that crawl your site to train AI models"},
    {"value": "(data)/meta/ai-block-aggressive.yaml", "label": "AI bots - aggressive",
     "effect": "Deny ALL AI bots, including documented ones"},
    {"value": "(data)/meta/ai-block-moderate.yaml", "label": "AI bots - moderate",
     "effect": "Deny AI training + unknown AI bots; allow documented search/user bots"},
    {"value": "(data)/meta/ai-block-permissive.yaml", "label": "AI bots - permissive",
     "effect": "Allow well-documented AI bots with published IP allowlists"},
    {"value": "(data)/bots/aggressive-brazilian-scrapers.yaml", "label": "Aggressive scrapers",
     "effect": "Add weight for ancient browsers and scraper-style user agents"},
    {"value": "(data)/common/domain-fronting.yaml", "label": "Domain fronting",
     "effect": "Deny requests that hide their real destination behind a CDN"},
    {"value": "(data)/common/keep-internet-working.yaml", "label": "Keep internet working",
     "effect": "Allow link checkers, archives and feed readers that respect robots.txt"},
    {"value": "(data)/crawlers/_allow-good.yaml", "label": "Good search engines",
     "effect": "Allow Googlebot, Bingbot, DuckDuckBot and other legit crawlers"},
    {"value": "(data)/clients/x-firefox-ai.yaml", "label": "Firefox AI browsing",
     "effect": "Add weight for Firefox's built-in AI features"},
    {"value": "(data)/crawlers/xai.yaml", "label": "xAI bots",
     "effect": "Deny xAI (Grok) crawlers"},
]

# matcher choices offered in the "custom rule" form
MATCHER_TYPES = [
    {"value": "user_agent_regex", "label": "Browser/app identity (user agent)"},
    {"value": "path_regex", "label": "URL path"},
    {"value": "headers_regex", "label": "HTTP headers"},
    {"value": "remote_addresses", "label": "Visitor IP address / range"},
]


def run_apply(*args):
    """Run the root helper via sudo; returns (ok, parsed_json_or_error)."""
    r = subprocess.run(["sudo", "-n", APPLY_BIN, *args],
                       capture_output=True, text=True, timeout=120)
    out = (r.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {"raw": out}
    if r.returncode != 0:
        data.setdefault("error", (r.stderr or out or "helper failed").strip()[-400:])
        return False, data
    return True, data


def run_apply_stdin(mode, payload):
    """Run the root helper with a stdin payload (policy-set)."""
    proc = subprocess.run(["sudo", "-n", APPLY_BIN, mode], input=payload,
                          capture_output=True, text=True, timeout=300)
    out = (proc.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {"raw": out}
    if proc.returncode != 0:
        data.setdefault("error", (proc.stderr or out or "helper failed").strip()[-400:])
        return False, data
    return True, data


def _admin_check(user):
    # Belt and braces: re-check YunoHost admins membership server-side
    # when possible (the yunohost CLI needs root, so this is best-effort -
    # the SSO permission remains the real gate).
    r = subprocess.run(
        ["yunohost", "user", "group", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return True
    try:
        admins = json.loads(r.stdout).get("admins", [])
    except json.JSONDecodeError:
        return True
    if admins and user not in admins:
        return False
    return True


# ------------------------------------------------------------- structured view
# The friendly editor shows bot rules; all other top-level policy keys are
# preserved verbatim when saving from it, and remain editable in the
# collapsed "advanced" YAML editor on the same page.

def _pack_label(imp):
    p = next((p for p in RULE_PACKS if p["value"] == imp), None)
    if p:
        return p["label"]
    tail = imp.rsplit("/", 1)[-1].replace(".yaml", "").strip("_")
    return tail.replace("-", " ")


def _pack_effect(imp):
    p = next((p for p in RULE_PACKS if p["value"] == imp), None)
    return p["effect"] if p else "Upstream rule pack: " + imp


def _rule_summary(bot):
    """One-line plain-language summary of a custom rule."""
    parts = []
    if "user_agent_regex" in bot:
        parts.append("browser identity matches " + str(bot["user_agent_regex"])[:40])
    if "path_regex" in bot:
        parts.append("URL matches " + str(bot["path_regex"])[:40])
    if "headers_regex" in bot:
        parts.append("headers match " + str(bot["headers_regex"])[:40])
    if "remote_addresses" in bot:
        parts.append("visitor IP in " + ", ".join(map(str, bot["remote_addresses"][:4]))[:44])
    if "geoip" in bot:
        g = bot.get("geoip") or {}
        cc = ", ".join(map(str, (g.get("countries") or [])[:6]))
        parts.append("visitor from " + (cc or "geo rule"))
    if "asns" in bot:
        a = bot.get("asns") or {}
        m = ", ".join("AS" + str(x) for x in (a.get("match") or [])[:4])
        parts.append("network " + (m or "rule"))
    if "expression" in bot:
        parts.append("custom expression")
    if not parts:
        parts.append("no matcher")
    return "; ".join(parts)[:120]


def rules_view():
    """Parse the live policy into a structured view for the GUI."""
    ok, data = run_apply("policy-get")
    if not ok:
        return None, data.get("error", "unknown error")
    import yaml
    try:
        doc = yaml.safe_load(data.get("policy", "")) or {}
    except yaml.YAMLError as e:
        return None, f"current policy is not valid YAML: {e}"
    bots = doc.get("bots") or []
    rules = []
    for bot in bots:
        if not isinstance(bot, dict):
            continue
        if "import" in bot:
            imp = bot["import"]
            rules.append({"kind": "pack", "import": imp,
                          "label": _pack_label(imp),
                          "summary": _pack_effect(imp)})
        else:
            rules.append({"kind": "rule", "name": bot.get("name", ""),
                          "action": bot.get("action", ""),
                          "summary": _rule_summary(bot)})
    return {"rules": rules, "packs": RULE_PACKS,
            "matchers": MATCHER_TYPES, "actions":
            ["ALLOW", "DENY", "CHALLENGE", "WEIGH"]}, None


def build_policy(doc, rules_payload):
    """Rebuild the full policy from the structured payload.

    doc: parsed current policy (non-bots keys preserved verbatim)
    rules_payload: list of {"kind": "pack"|"rule", ...} entries
    """
    import yaml
    bots = []
    seen = set()
    for r in rules_payload:
        if r.get("kind") == "pack":
            imp = str(r.get("import", "")).strip()
            if not imp:
                continue
            if imp in seen:
                raise ValueError("rule pack '" + _pack_label(imp) + "' is added twice")
            seen.add(imp)
            bots.append({"import": imp})
            continue
        name = str(r.get("name", "")).strip()
        action = str(r.get("action", "")).strip().upper()
        if not name:
            raise ValueError("every custom rule needs a name")
        if name in seen:
            raise ValueError("duplicate rule name '" + name + "'")
        seen.add(name)
        if action not in ("ALLOW", "DENY", "CHALLENGE", "WEIGH"):
            raise ValueError(f"rule '{name}': unknown action '{action}'")
        mtype = str(r.get("matcher_type", "")).strip()
        mval = str(r.get("matcher_value", "")).strip()
        if not mtype or not mval:
            raise ValueError(f"rule '{name}': choose what it should match")
        bot = {"name": name, "action": action}
        if mtype in ("user_agent_regex", "path_regex", "headers_regex"):
            bot[mtype] = mval
        elif mtype == "remote_addresses":
            bot["remote_addresses"] = [x.strip() for x in mval.split(",") if x.strip()]
        else:
            raise ValueError(f"rule '{name}': unknown matcher type '{mtype}'")
        if action == "WEIGH":
            try:
                adjust = int(r.get("weight_adjust", 10))
            except (TypeError, ValueError):
                raise ValueError(f"rule '{name}': weight must be a number")
            bot["weight"] = {"adjust": adjust}
        bots.append(bot)
    doc["bots"] = bots
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def create_app():
    import os
    global APP
    APP = os.environ.get("ANUBIS_APP", "anubis")
    port = os.environ.get("ANUBIS_PORT", "8923")

    app = Flask(__name__)

    def current_user():
        # Only present when ssowat has authenticated + authorized the
        # visitor for this app's permission. Read the raw WSGI environ key:
        # WSGI servers normalize the header name differently (waitress turns
        # YNH_USER into 'Ynh-User'), but HTTP_YNH_USER is deterministic.
        return request.environ.get("HTTP_YNH_USER")

    @app.before_request
    def require_user():
        # static assets + readiness probe carry no data, no identity needed
        if request.path.startswith(f"{app.static_url_path}/") or \
           request.path.rstrip("/").endswith("/ping"):
            return
        user = current_user()
        if not user:
            # Should not happen: the SSO permission gates the location.
            return "Forbidden - reach this page through the YunoHost portal", 403
        if not _admin_check(user):
            return "Forbidden - Anubis configuration is restricted to YunoHost admins", 403

    @app.route("/ping")
    def ping():
        return jsonify({"ok": True})

    @app.route("/")
    def index():
        ok, data = run_apply("status")
        if not ok:
            err = data.get("error", "unknown error")
            return render_template("index.html", data=None, rules=None,
                                   error=err, user=current_user()), 500
        rules, perr = rules_view()
        if perr:
            return render_template("index.html", data=data, rules=None,
                                   error=perr, user=current_user()), 500
        return render_template("index.html", data=data, rules=rules,
                               error=None, user=current_user())

    @app.route("/api/status")
    def api_status():
        ok, data = run_apply("status")
        return (jsonify(data), 200) if ok else (jsonify(data), 500)

    @app.route("/api/apply", methods=["POST"])
    def api_apply():
        body = request.get_json(force=True, silent=True) or {}
        protected = body.get("protected")
        difficulty = body.get("difficulty")
        if not isinstance(protected, list):
            return jsonify({"error": "protected must be a list of domains"}), 400
        protected = [str(d).strip().lower() for d in protected if str(d).strip()]
        args = ["set", "--domains", ",".join(sorted(set(protected)))]
        if difficulty is not None:
            try:
                d = int(difficulty)
            except (TypeError, ValueError):
                return jsonify({"error": "difficulty must be an integer"}), 400
            if not 0 <= d <= 8:
                return jsonify({"error": "difficulty must be between 0 and 8"}), 400
            args += ["--difficulty", str(d)]
        ok, data = run_apply(*args)
        return (jsonify(data), 200) if ok else (jsonify(data), 400)

    @app.route("/api/policy", methods=["GET"])
    def api_policy_get():
        ok, data = run_apply("policy-get")
        return (jsonify(data), 200) if ok else (jsonify(data), 500)

    @app.route("/api/policy", methods=["POST"])
    def api_policy_set():
        body = request.get_json(force=True, silent=True) or {}
        if "rules" in body:
            # structured editor save: merge with current non-bots keys
            ok, data = run_apply("policy-get")
            if not ok:
                return jsonify(data), 500
            import yaml
            try:
                doc = yaml.safe_load(data.get("policy", "")) or {}
            except yaml.YAMLError as e:
                return jsonify({"error": f"current policy unreadable: {e}"}), 500
            try:
                text = build_policy(doc, body["rules"])
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            ok, data = run_apply_stdin("policy-set", text)
            return (jsonify(data), 200) if ok else (jsonify(data), 400)
        policy = body.get("policy")
        if not isinstance(policy, str) or not policy.strip():
            return jsonify({"error": "policy must be a non-empty YAML string"}), 400
        ok, data = run_apply_stdin("policy-set", policy)
        return (jsonify(data), 200) if ok else (jsonify(data), 400)

    @app.route("/api/policy/default", methods=["POST"])
    def api_policy_default():
        ok, data = run_apply("policy-reset")
        return (jsonify(data), 200) if ok else (jsonify(data), 400)

    @app.route("/policy")
    def policy_page():
        # legacy standalone YAML editor: redirect into the main page
        return redirect_main()

    def redirect_main():
        from flask import redirect
        return redirect("/", code=302)

    @app.template_filter("yesno")
    def yesno(v):
        return "yes" if v else "no"

    app.jinja_env.globals.update(app_port=port)
    return app


if __name__ == "__main__":
    create_app().run()
