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


def run_apply(*args):
    """Run the root helper via sudo; returns (ok, parsed_json_or_error)."""
    r = subprocess.run(["sudo", "-n", APPLY_BIN, *args], capture_output=True, text=True, timeout=120)
    out = (r.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {"raw": out}
    if r.returncode != 0:
        data.setdefault("error", (r.stderr or out or "helper failed").strip()[-400:])
        return False, data
    return True, data


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
        # Belt and braces: re-check YunoHost admins membership server-side
        # when possible (the yunohost CLI needs root, so this is best-effort -
        # the SSO permission remains the real gate).
        r = subprocess.run(
            ["yunohost", "user", "group", "list", "--output", "json"],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            try:
                admins = json.loads(r.stdout).get("admins", [])
            except json.JSONDecodeError:
                admins = []
            if admins and user not in admins:
                return "Forbidden - Anubis configuration is restricted to YunoHost admins", 403

    @app.route("/ping")
    def ping():
        return jsonify({"ok": True})

    @app.route("/")
    def index():
        ok, data = run_apply("status")
        if not ok:
            err = data.get("error", "unknown error")
            return render_template("index.html", data=None, error=err,
                                   user=current_user()), 500
        return render_template("index.html", data=data, error=None,
                               user=current_user())

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

    @app.route("/policy")
    def policy_page():
        ok, data = run_apply("policy-get")
        policy = data.get("policy", "") if ok else ""
        err = None if ok else data.get("error", "unknown error")
        return render_template("policy.html", policy=policy, error=err,
                               user=current_user())

    @app.route("/api/policy", methods=["GET"])
    def api_policy_get():
        ok, data = run_apply("policy-get")
        return (jsonify(data), 200) if ok else (jsonify(data), 500)

    @app.route("/api/policy", methods=["POST"])
    def api_policy_set():
        body = request.get_json(force=True, silent=True) or {}
        policy = body.get("policy")
        if not isinstance(policy, str) or not policy.strip():
            return jsonify({"error": "policy must be a non-empty YAML string"}), 400
        proc = subprocess.run(
            ["sudo", "-n", APPLY_BIN, "policy-set"],
            input=policy, capture_output=True, text=True, timeout=180)
        out = (proc.stdout or "").strip()
        try:
            data = json.loads(out) if out else {}
        except json.JSONDecodeError:
            data = {"raw": out}
        if proc.returncode != 0:
            data.setdefault("error", (proc.stderr or out or "helper failed").strip()[-400:])
            return jsonify(data), 400
        return jsonify(data), 200

    @app.template_filter("yesno")
    def yesno(v):
        return "yes" if v else "no"

    app.jinja_env.globals.update(app_port=port)
    return app


if __name__ == "__main__":
    create_app().run()
