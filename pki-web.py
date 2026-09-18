#!/usr/bin/env python3
"""pki-web.py - browser dashboard for the pamperins.lan PKI.

Thin shell over pki-manager.sh: every probe and every action is the same code
the TUI runs, so the two can never drift. Binds 127.0.0.1:7443 by default.

Credentials come from pki.conf via `pki-manager.sh --dump-config` - nothing is
hardcoded here, and the PIV PIN is never accepted over HTTP.
"""
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
from pathlib import Path

try:
    from flask import (Flask, Response, jsonify, render_template, request,
                       session, redirect, url_for, stream_with_context)
except ImportError:
    sys.exit("flask not installed: pip3 install -r requirements.txt")

APP_DIR = Path(__file__).resolve().parent
MANAGER = APP_DIR / "pki-manager.sh"

# ------------------------------------------------------------------ config --

def load_config():
    """Source pki.conf through the shell - one parser, not two."""
    if not MANAGER.is_file():
        sys.exit(f"missing {MANAGER}")
    env = dict(os.environ)
    try:
        out = subprocess.run([str(MANAGER), "--dump-config"], capture_output=True,
                             text=True, timeout=30, env=env, check=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"pki-manager.sh --dump-config failed: {e.stderr.strip()}")
    except subprocess.TimeoutExpired:
        sys.exit("pki-manager.sh --dump-config timed out")
    cfg = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg

CFG = load_config()
HOSTS = CFG.get("HOSTS", "").split()
TTY_ACTIONS = set(CFG.get("PKI_TTY_ACTIONS", "").split())
WEB_TOKEN = CFG.get("WEB_TOKEN", "")

# ---------------------------------------------------------------- catalog --
# label, whether it takes a host, whether it needs confirming, blurb.
# Anything not in here cannot be run from the browser.
ACTIONS = {
    "status":              ("Refresh status",        None,   False, "Re-run every probe"),
    "preflight":           ("Preflight check",       None,   False, "Verify config, CA, tools and ssh"),
    "renew":               ("Renew certificates",    None,   True,  "Runs renew-certs.sh"),
    "deploy":              ("Deploy certs",          "host", True,  "Push service certs for one host"),
    "deploy-all":          ("Deploy to ALL",         None,   True,  "Push service certs everywhere"),
    "trust-push":          ("Push root CA trust",    "host", True,  "Install root CA in the trust store"),
    "trust-push-all":      ("Push trust to ALL",     None,   True,  "Install root CA everywhere"),
    "webmin-push":         ("Push Webmin cert",      "host", True,  "leaf+intermediate to miniserv.cert"),
    "webmin-push-all":     ("Push Webmin to ALL",    None,   True,  "leaf+intermediate everywhere"),
    "webmin-fix":          ("Fix miniserv.conf",     "host", True,  "Repoint Webmin at /etc/webmin"),
    "webmin-fix-all":      ("Fix miniserv.conf ALL", None,   True,  "Repoint Webmin everywhere"),
    "ldap-fix":            ("Fix LDAP trust",        "host", True,  "TLS_CACERT -> root CA"),
    "ldap-fix-all":        ("Fix LDAP trust ALL",    None,   True,  "TLS_CACERT everywhere"),
    "samba-fix":           ("Fix Samba TLS owner",   "host", True,  "chown root:root + restart"),
    "nextcloud-certcheck": ("Nextcloud cert check",  "mode", True,  "auto / enforce / bypass"),
    "issue":               ("Issue cert",            "host", True,  "Re-issue one host's cert now"),
    "issue-all":           ("Issue ALL certs",       None,   True,  "Re-issue every host's cert"),
    "trust-cleanup":       ("Tidy old anchors",      "host", True,  "Remove superseded roots after cutover"),
    "trust-cleanup-all":   ("Tidy anchors ALL",      None,   True,  "Remove superseded roots everywhere"),
    "verify-tls":          ("Verify TLS",            "host?", False, "Probe every TLS endpoint"),
    "logs":                ("View logs",             None,   False, "Tail the renewal logs"),
    "yk-info":             ("YubiKey info",          None,   False, "ykman list + piv info"),
    "yk-slot":             ("Slot certificate",      None,   False, "Cert stored on the key"),
    "yk-export-cert":      ("Export root CA cert",   None,   True,  "Copy the CA cert off the key"),
    "yk-retries":          ("PIN / PUK retries",     None,   False, "Remaining attempts"),
    # PIN/touch actions are deliberately absent - see TTY_ACTIONS.
}

MODES = ("auto", "enforce", "bypass")
SLOT_RE = re.compile(r"^9[acde]$")

app = Flask(__name__, template_folder=str(APP_DIR / "templates"),
            static_folder=str(APP_DIR / "static"))
app.secret_key = os.environ.get("PKI_WEB_SECRET") or secrets.token_hex(32)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True

_action_lock = threading.Lock()   # one privileged action at a time

# ------------------------------------------------------------------- auth --

def authed():
    return not WEB_TOKEN or session.get("ok") is True

@app.before_request
def guard():
    if request.endpoint in ("login", "static"):
        return None
    if not authed():
        if request.path.startswith("/api/"):
            return jsonify(error="not authenticated"), 401
        return redirect(url_for("login"))
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    if not WEB_TOKEN:
        return redirect(url_for("index"))
    err = ""
    if request.method == "POST":
        if secrets.compare_digest(request.form.get("token", ""), WEB_TOKEN):
            session.clear()
            session["ok"] = True
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("index"))
        err = "bad token"
    return render_template("login.html", err=err)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

def csrf_ok(sent):
    return bool(sent) and secrets.compare_digest(sent, session.get("csrf", ""))

# ------------------------------------------------------------- run helpers --

def manager_env():
    env = dict(os.environ)
    env["PKI_NONINTERACTIVE"] = "1"   # refuse anything wanting a PIN prompt
    env["NO_COLOR"] = "1"
    env.setdefault("PKI_CONF", CFG.get("PKI_CONF", ""))
    return env

def validate(action, arg):
    """Returns (argv_arg, error). Mirrors the shell dispatcher's checks."""
    if action in TTY_ACTIONS:
        return None, f"{action} needs a terminal (PIN/touch) - use the TUI on the console"
    if action not in ACTIONS:
        return None, f"unknown action: {action}"
    kind = ACTIONS[action][1]
    if kind == "host":
        if arg not in HOSTS:
            return None, f"pick a host: {' '.join(HOSTS)}"
        return arg, None
    if kind == "host?":
        if arg and arg not in HOSTS:
            return None, f"unknown host: {arg}"
        return arg or "", None
    if kind == "mode":
        if arg not in MODES:
            return None, f"mode must be one of: {' '.join(MODES)}"
        return arg, None
    if action == "yk-slot":
        arg = arg or CFG.get("YUBIKEY_SLOT", "9c")
        if not SLOT_RE.match(arg):
            return None, f"bad slot: {arg}"
        return arg, None
    if action == "logs":
        return str(int(arg)) if str(arg).isdigit() else "80", None
    return "", None

# ------------------------------------------------------------------ routes --

@app.route("/")
def index():
    return render_template("index.html", actions=ACTIONS, hosts=HOSTS, modes=MODES,
                           csrf=csrf_token(), cfg=CFG, tty_actions=sorted(TTY_ACTIONS),
                           auth=bool(WEB_TOKEN))

@app.route("/api/status")
def api_status():
    try:
        p = subprocess.run([str(MANAGER), "--status-json"], capture_output=True,
                           text=True, timeout=180, env=manager_env())
    except subprocess.TimeoutExpired:
        return jsonify(error="status probe timed out"), 504
    if p.returncode != 0 and not p.stdout.strip():
        return jsonify(error=p.stderr.strip() or "status failed"), 500
    return Response(p.stdout, mimetype="application/json")

@app.route("/api/action", methods=["POST"])
def api_action():
    data = request.get_json(silent=True) or {}
    if not csrf_ok(data.get("csrf") or request.headers.get("X-CSRF-Token", "")):
        return jsonify(error="bad csrf token"), 403
    action = str(data.get("action", ""))
    arg = str(data.get("arg", "") or "")
    argv_arg, err = validate(action, arg)
    if err:
        return jsonify(error=err), 400

    cmd = [str(MANAGER), "--run", action]
    if argv_arg:
        cmd.append(argv_arg)

    def stream():
        if not _action_lock.acquire(blocking=False):
            yield "another action is already running\n"
            return
        try:
            yield f"$ pki-manager.sh --run {action} {argv_arg}\n\n"
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    text=True, bufsize=1, env=manager_env())
            try:
                for line in proc.stdout:
                    yield line
                proc.wait(timeout=900)
            except subprocess.TimeoutExpired:
                proc.kill()
                yield "\n-- timed out after 900s, killed --\n"
            yield f"\n-- exit {proc.returncode} --\n"
        finally:
            _action_lock.release()

    return Response(stream_with_context(stream()), mimetype="text/plain",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})

@app.route("/api/logs")
def api_logs():
    n = request.args.get("lines", "80")
    n = n if n.isdigit() else "80"
    p = subprocess.run([str(MANAGER), "--run", "logs", n], capture_output=True,
                       text=True, timeout=60, env=manager_env())
    return Response(p.stdout + p.stderr, mimetype="text/plain")

# -------------------------------------------------------------------- main --

def main():
    bind = os.environ.get("PKI_WEB_BIND") or CFG.get("WEB_BIND") or "127.0.0.1"
    port = int(os.environ.get("PKI_WEB_PORT") or CFG.get("WEB_PORT") or 7443)
    cert, key = CFG.get("WEB_TLS_CERT", ""), CFG.get("WEB_TLS_KEY", "")
    ssl_ctx = None
    if cert and key and Path(cert).is_file() and Path(key).is_file():
        ssl_ctx = (cert, key)
    scheme = "https" if ssl_ctx else "http"

    if bind not in ("127.0.0.1", "localhost", "::1") and not WEB_TOKEN:
        sys.exit(f"refusing to bind {bind} with no WEB_TOKEN set in pki.conf")
    if not shutil.which("bash"):
        sys.exit("bash not found")

    print(f"pki-web  {scheme}://{bind}:{port}   conf={CFG.get('PKI_CONF')}")
    print(f"         auth={'token' if WEB_TOKEN else 'none (localhost only)'}"
          f"  hosts={' '.join(HOSTS)}")
    app.run(host=bind, port=port, ssl_context=ssl_ctx, threaded=True, debug=False)

if __name__ == "__main__":
    main()
