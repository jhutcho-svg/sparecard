#!/usr/bin/env python3
"""
SpareCard — single-file Flask app. Keeps a bootable spare image of your Pi.
Run with: python3 pi_backup_manager.py
Then open: http://<pi-ip>:7823
"""

import base64, hashlib, json, logging, os, re, secrets, shlex, shutil, socket, subprocess, tempfile, threading, time, queue, calendar
import urllib.error, urllib.request
from datetime import datetime
from glob import glob
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, abort, jsonify, make_response, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB body cap -> 413

@app.errorhandler(413)
def _too_large(e):
    return jsonify({"error": "Request body too large (2 MB max)"}), 413

def _body():
    """Parsed JSON object from the request body, or a clean JSON 400.
    Replaces the old get_json(force=True) calls, which leaked an HTML
    traceback page on malformed JSON. force=True keeps tolerating a missing
    Content-Type header; silent=True turns parse errors into None."""
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        abort(make_response(jsonify({"error": "Invalid or missing JSON body"}), 400))
    return data

CONFIG_FILE = Path(os.environ.get("PBM_CONFIG", Path.home() / ".pi-backup-manager.json"))
PORT = int(os.environ.get("PBM_PORT", 7823))
JOB_LOG_DIR = Path(os.environ.get("PBM_LOG_DIR", Path.home() / ".pbm"))  # per-run job logs

# ── Authentication ─────────────────────────────────────────────────────────────
AUTH_FILE = Path(os.environ.get("PBM_AUTH", Path.home() / ".pi-backup-manager-auth.json"))

# Simple in-memory rate limiter: track failed attempts per IP
_auth_failures: dict = {}          # ip -> [timestamp, ...]
_AUTH_MAX_FAILS   = 10             # max attempts in window
_AUTH_WINDOW_SECS = 300            # 5-minute window
_AUTH_LOCKOUT_SECS = 60            # lockout duration after max failures
_AUTH_MAX_IPS      = 1024          # hard cap on tracked IPs (memory bound)

# Verified-credential cache so PBKDF2 does not run on every request.
# Basic Auth re-sends the header each request; we cache the *hash* of a
# verified header for a short TTL and skip the (expensive) KDF on hits.
_auth_cache: dict = {}             # sha256(header) -> expiry ts
_AUTH_CACHE_TTL  = 300
_AUTH_CACHE_MAX  = 512

# Logged once when the server starts handling requests with no auth file.
_setup_warned = False

def _warn_setup_mode_once():
    global _setup_warned
    if not _setup_warned:
        app.logger.warning(
            "AUTH_FILE missing - running in OPEN SETUP mode; anyone who can "
            "reach this server can set the admin credentials.")
        _setup_warned = True

def _auth_cache_key(hdr):
    return hashlib.sha256(hdr.encode()).hexdigest()

def _prune_auth_cache(now):
    for k in [k for k, v in _auth_cache.items() if v <= now]:
        _auth_cache.pop(k, None)
    while len(_auth_cache) > _AUTH_CACHE_MAX:
        _auth_cache.pop(next(iter(_auth_cache)), None)

def _prune_failures(now):
    """Drop stale/empty IP entries and enforce a hard cap (memory bound)."""
    for ip in list(_auth_failures.keys()):
        kept = [t for t in _auth_failures[ip] if now - t < _AUTH_WINDOW_SECS]
        if kept:
            _auth_failures[ip] = kept
        else:
            del _auth_failures[ip]
    if len(_auth_failures) > _AUTH_MAX_IPS:
        victims = sorted(_auth_failures, key=lambda i: _auth_failures[i][-1])
        for ip in victims[: len(_auth_failures) - _AUTH_MAX_IPS]:
            del _auth_failures[ip]

def _csrf_ok():
    """Block cross-site state-changing requests.
    Safe (read-only) methods and the pre-auth setup endpoints are exempt.
    Mutations must carry a custom header that cross-origin HTML forms cannot
    set, and (when present) the Origin must match the request Host."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    if request.path in _SETUP_PATHS:
        return True
    if request.headers.get("X-PBM-CSRF") != "1":
        return False
    origin = request.headers.get("Origin")
    if origin:
        try:
            netloc = urlparse(origin).netloc
        except Exception:
            return False
        if netloc and netloc != request.headers.get("Host", ""):
            return False
    return True

def _hash_password(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    return salt, h

def _is_rate_limited(ip: str) -> bool:
    """Return True if this IP has exceeded the failure threshold."""
    now = time.time()
    _prune_failures(now)
    attempts = _auth_failures.get(ip, [])
    if len(attempts) >= _AUTH_MAX_FAILS:
        # Locked out if the most-recent failure is within lockout window
        return (now - attempts[-1]) < _AUTH_LOCKOUT_SECS
    return False

def _record_failure(ip: str):
    now = time.time()
    attempts = [t for t in _auth_failures.get(ip, []) if now - t < _AUTH_WINDOW_SECS]
    attempts.append(now)
    _auth_failures[ip] = attempts
    _prune_failures(now)

def _verify_basic(auth_header):
    """Return True if the Authorization header matches stored credentials."""
    if not auth_header.startswith("Basic "):
        return False
    ip = request.remote_addr or "unknown"
    if _is_rate_limited(ip):
        return False
    try:
        user, pw = base64.b64decode(auth_header[6:]).decode().split(":", 1)
        creds = json.loads(AUTH_FILE.read_text())
        _, expected = _hash_password(pw, creds["salt"])
        ok = (secrets.compare_digest(user, creds["username"]) and
              secrets.compare_digest(expected, creds["hash"]))
        if not ok:
            _record_failure(ip)
        return ok
    except Exception:
        _record_failure(ip)
        return False

_SETUP_PATHS = {"/setup", "/api/auth/setup"}

@app.before_request
def require_auth():
    if not AUTH_FILE.exists():
        # First run — only allow setup routes
        _warn_setup_mode_once()
        if request.path not in _SETUP_PATHS:
            return Response("", 302, {"Location": "/setup"})
        return
    hdr = request.headers.get("Authorization", "")
    now = time.time()
    key = _auth_cache_key(hdr) if hdr else None
    authed = bool(key and _auth_cache.get(key, 0) > now)
    if not authed and _verify_basic(hdr):
        authed = True
        if key:
            _auth_cache[key] = now + _AUTH_CACHE_TTL
            _prune_auth_cache(now)
    if not authed:
        return Response("Unauthorized", 401,
                        {"WWW-Authenticate": 'Basic realm="SpareCard"'})
    if not _csrf_ok():
        return Response("CSRF validation failed", 403)

# ── Auth routes ────────────────────────────────────────────────────────────────

SETUP_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpareCard — Setup</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--bg2:#111827;--bg3:#1a2234;--border:#1e2d4a;--accent:#3b82f6;--green:#10b981;--red:#ef4444;--text:#c8d0e8;--muted:#4b5a78;--bright:#e8eeff}
html,body{min-height:100vh;background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:14px;display:flex;align-items:center;justify-content:center}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;width:min(420px,92vw)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.logo-icon{width:40px;height:40px;background:linear-gradient(135deg,#3b82f6,#06b6d4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.logo-title{font-family:'Syne',sans-serif;font-weight:800;font-size:17px;color:var(--bright)}
.logo-sub{font-size:11px;color:var(--muted)}
h2{font-family:'Syne',sans-serif;font-weight:700;font-size:15px;color:var(--bright);margin-bottom:6px}
.desc{font-size:12px;color:var(--muted);margin-bottom:24px;line-height:1.6}
.field{margin-bottom:16px}
.lbl{font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px}
input{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-size:13px;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
.btn{width:100%;padding:11px;border-radius:8px;font-size:13px;font-weight:600;font-family:'JetBrains Mono',monospace;cursor:pointer;border:none;background:var(--accent);color:#fff;transition:opacity .15s;margin-top:4px}
.btn:disabled{opacity:.45;cursor:not-allowed}
.msg{padding:10px 14px;border-radius:8px;font-size:12px;margin-top:14px;display:none;border:1px solid;line-height:1.5}
.msg.red{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.25);color:var(--red)}
.msg.green{background:rgba(16,185,129,.07);border-color:rgba(16,185,129,.25);color:var(--green)}
</style></head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">💾</div>
    <div>
      <div class="logo-title">SpareCard</div>
      <div class="logo-sub">First-time setup</div>
    </div>
  </div>
  <h2>Create your login</h2>
  <p class="desc">Set a username and password to secure the portal. You'll use these every time you log in.</p>
  <div class="field">
    <div class="lbl">Username</div>
    <input type="text" id="username" placeholder="e.g. admin" autocomplete="username">
  </div>
  <div class="field">
    <div class="lbl">Password</div>
    <input type="password" id="password" placeholder="Min 8 characters" autocomplete="new-password">
  </div>
  <div class="field" style="margin-bottom:8px">
    <div class="lbl">Confirm Password</div>
    <input type="password" id="confirm" placeholder="Repeat password" autocomplete="new-password">
  </div>
  <button class="btn" id="btn" onclick="doSetup()">Create Login &amp; Continue →</button>
  <div class="msg" id="msg"></div>
</div>
<script>
async function doSetup() {
  const u = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value;
  const c = document.getElementById('confirm').value;
  const btn = document.getElementById('btn');
  document.getElementById('msg').style.display = 'none';
  if (!u || !p || !c) { showMsg('All fields are required.', 'red'); return; }
  if (p !== c) { showMsg('Passwords do not match.', 'red'); return; }
  if (p.length < 8) { showMsg('Password must be at least 8 characters.', 'red'); return; }
  btn.disabled = true; btn.textContent = 'Setting up…';
  try {
    const r = await fetch('/api/auth/setup', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const d = await r.json();
    if (d.ok) {
      showMsg('Login created! Redirecting to the app…', 'green');
      setTimeout(() => { window.location.href = '/'; }, 1500);
    } else {
      showMsg(d.error || 'Setup failed.', 'red');
      btn.disabled = false; btn.textContent = 'Create Login & Continue →';
    }
  } catch(e) {
    showMsg('Request failed.', 'red');
    btn.disabled = false; btn.textContent = 'Create Login & Continue →';
  }
}
function showMsg(t, cls) {
  const el = document.getElementById('msg');
  el.textContent = t; el.className = 'msg ' + cls; el.style.display = 'block';
}
document.addEventListener('keydown', e => { if (e.key === 'Enter') doSetup(); });
</script>
</body></html>"""

@app.route("/setup")
def setup_page():
    if AUTH_FILE.exists():
        return Response("", 302, {"Location": "/"})
    return SETUP_HTML

@app.route("/api/auth/setup", methods=["POST"])
def api_auth_setup():
    if AUTH_FILE.exists():
        return jsonify({"error": "Already configured. Use Change Password instead."}), 400
    d = _body()
    username = d.get("username", "").strip()
    password = d.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    salt, h = _hash_password(password)
    AUTH_FILE.write_text(json.dumps({"username": username, "salt": salt, "hash": h}, indent=2))
    app.logger.info("Admin credentials created via setup.")
    return jsonify({"ok": True})

@app.route("/api/auth/change", methods=["POST"])
def api_auth_change():
    d = _body()
    current_pw = d.get("currentPassword", "")
    new_pw     = d.get("newPassword", "")
    if not current_pw or not new_pw:
        return jsonify({"error": "Current and new password required."}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    try:
        creds = json.loads(AUTH_FILE.read_text())
    except Exception:
        return jsonify({"error": "Auth not configured."}), 500
    _, expected = _hash_password(current_pw, creds["salt"])
    if not secrets.compare_digest(expected, creds["hash"]):
        return jsonify({"error": "Current password is incorrect."}), 403
    salt, h = _hash_password(new_pw)
    creds["salt"] = salt
    creds["hash"] = h
    AUTH_FILE.write_text(json.dumps(creds, indent=2))
    _auth_cache.clear()  # old Basic header must no longer be accepted
    app.logger.info("Admin password changed; auth cache cleared.")
    return jsonify({"ok": True})

# ── streamable background jobs (SSE) ──────────────────────────────────────────

class Job:
    """One streamable background job (backup, verify, compact, …).

    Each connected SSE client gets its OWN queue (fan-out), so multiple
    browser tabs all receive every log line and the correct `done` event —
    the previous single shared queue made tabs steal each other's messages.
    A rolling history buffer is replayed to clients that connect mid-job.
    Every event is also teed to JOB_LOG_DIR/<name>-<YYYYmmdd-HHMMSS>.log
    (flushed per line, so an interrupted restore still leaves a trail).
    """
    HISTORY_MAX = 500
    LOG_KEEP    = 10    # rotated per-run log files kept per job

    def __init__(self, name):
        self.name    = name
        self.status  = {"running": False, "result": None}  # "success"|"failed"|…|None
        self.lock    = threading.Lock()
        self.history = []   # events of the current/last run, for replay on connect
        self._subs   = []   # one queue PER connected client
        self._logf   = None

    @property
    def running(self):
        return self.status["running"]

    def start(self, target, *args):
        """Run target(job, *args) in a daemon thread. False if already running."""
        with self.lock:
            if self.status["running"]:
                return False
            self.status = {"running": True, "result": None}
            self.history = []
            self._open_log()
        threading.Thread(target=self._guard, args=(target, args), daemon=True).start()
        return True

    def _open_log(self):
        """Open this run's log file and rotate old ones. Never raises —
        a failed disk log must not block the job itself."""
        try:
            JOB_LOG_DIR.mkdir(mode=0o700, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            self._logf = open(JOB_LOG_DIR / f"{self.name}-{ts}.log", "a", encoding="utf-8")
            for old in sorted(JOB_LOG_DIR.glob(f"{self.name}-*.log"))[:-self.LOG_KEEP]:
                try: old.unlink()
                except OSError: pass
        except Exception:
            self._logf = None

    def _log_to_disk(self, ev):
        if not self._logf:
            return
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if ev.get("type") == "log":
                line = f"{ts} [{ev.get('level', 'info'):4}] {ev.get('msg', '')}"
            elif ev.get("type") == "done":
                extra = {k: v for k, v in ev.items() if k not in ("type", "result")}
                line = f"{ts} [done] result={ev.get('result')}" + \
                       (f" {json.dumps(extra)}" if extra else "")
            else:
                line = f"{ts} [{ev.get('type')}] {json.dumps(ev)}"
            self._logf.write(line + "\n")
            self._logf.flush()
        except Exception:
            self._close_log()

    def _close_log(self):
        if self._logf:
            try: self._logf.close()
            except Exception: pass
            self._logf = None

    def _guard(self, target, args):
        try:
            target(self, *args)
        except Exception as e:
            self.emit(f"Exception: {e}", "err")
            if self.status["running"]:
                self.finish("failed", error=str(e))
        finally:
            if self.status["running"]:   # target returned without calling finish()
                self.finish("failed")

    def _publish(self, ev):
        with self.lock:
            self.history.append(ev)
            if len(self.history) > self.HISTORY_MAX:
                self.history.pop(0)
            self._log_to_disk(ev)
            subs = list(self._subs)
        for q in subs:
            q.put(ev)

    def emit(self, msg, level="info"):
        self._publish({"type": "log", "msg": msg, "level": level})

    def event(self, ev):
        """Publish a custom event dict, e.g. {"type":"phase","phase":2}."""
        self._publish(ev)

    def finish(self, result, **extra):
        with self.lock:
            self.status = {"running": False, "result": result}
        self._publish({"type": "done", "result": result, **extra})
        with self.lock:
            self._close_log()

    def stream(self):
        """SSE response: replays history, then live events until `done`."""
        q = queue.Queue()
        with self.lock:
            backlog = list(self.history)
            self._subs.append(q)
        def gen():
            try:
                yield 'data: {"type":"connected"}\n\n'
                for ev in backlog:
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev.get("type") == "done":
                        return
                while True:
                    try:
                        ev = q.get(timeout=30)
                    except queue.Empty:
                        yield 'data: {"type":"ping"}\n\n'
                        continue
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev.get("type") == "done":
                        break
            finally:
                with self.lock:
                    try: self._subs.remove(q)
                    except ValueError: pass
        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

backup_job  = Job("backup")
verify_job  = Job("verify")
compact_job = Job("compact")
install_job = Job("install")
imgbak_job  = Job("imgbak")
restore_job = Job("restore")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run(argv, timeout=30, merge=False):
    """Run a command WITHOUT a shell. `argv` is a list, so user-supplied
    values can never be interpreted as shell syntax (no injection).
    `merge=True` folds stderr into stdout (replaces shell '2>&1').
    A missing binary returns rc 127 (mirrors the old shell behaviour) so
    callers that sniff for 'not found' keep working."""
    try:
        r = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge else subprocess.PIPE,
            text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return "", f"{argv[0]}: command not found", 127
    except subprocess.TimeoutExpired:
        return "", f"{argv[0]}: timed out after {timeout}s", 124
    out = (r.stdout or "").strip()
    err = "" if merge else (r.stderr or "").strip()
    return out, err, r.returncode

def sudo_run(argv, timeout=30, merge=False):
    return run(["sudo", *argv], timeout=timeout, merge=merge)

def _df_line(path):
    """Last line of `df -h <path>` (the data row), or '' on failure."""
    out, _, rc = run(["df", "-h", path])
    if rc != 0 or not out:
        return ""
    lines = out.splitlines()
    return lines[-1] if lines else ""

# ── Input validation helpers ──────────────────────────────────────────────────

def _disk_base(dev):
    """Normalise a device/partition path to its base *disk* name (no /dev/).
    Handles sda1->sda, mmcblk0p2->mmcblk0, nvme0n1p3->nvme0n1, loop0p1->loop0."""
    name = (dev or "").strip()
    if name.startswith("/dev/"):
        name = name[len("/dev/"):]
    m = re.match(r'^(mmcblk\d+|nvme\d+n\d+|loop\d+)(p\d+)?$', name)
    if m:
        return m.group(1)
    return re.sub(r'\d+$', '', name)  # sd/vd/hd/xvd style

def _human_size(n):
    """Bytes -> short human string in lsblk style, e.g. 14.9G."""
    n = float(n or 0)
    for unit in ("B", "K", "M", "G", "T", "P"):
        if n < 1024 or unit == "P":
            return f"{n:.0f}{unit}" if n >= 100 or unit == "B" else f"{n:.1f}{unit}"
        n /= 1024

def _image_stats(path):
    """Size info for an image file from a single stat() call — no subprocess.
    Sparse (allocated) size comes from st_blocks, which is exactly what
    `du` reports. The one place for logical/sparse size math."""
    try:
        st = Path(path).stat()
    except OSError:
        return {"exists": False, "logical_bytes": 0, "sparse_bytes": 0,
                "logical_mb": 0, "sparse_mb": 0}
    sparse = st.st_blocks * 512
    return {"exists": True,
            "logical_bytes": st.st_size, "sparse_bytes": sparse,
            "logical_mb": st.st_size // (1024 * 1024),
            "sparse_mb":  sparse // (1024 * 1024)}

def _valid_disk(s):
    """A whole block *disk* (not a partition) usable as a restore target."""
    return bool(s and re.match(
        r'^/dev/(sd[a-z]+|vd[a-z]+|hd[a-z]+|mmcblk\d+|nvme\d+n\d+|loop\d+)$', s))

def _valid_mount_path(path):
    """Absolute path containing only safe characters."""
    return bool(path and re.match(r'^/[a-zA-Z0-9/_.\-]+$', path))

def _valid_hostname(s):
    """Hostname or IP address."""
    return bool(s and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$', s))

def _valid_share(s):
    """SMB share name or NFS export path."""
    return bool(s and re.match(r'^[a-zA-Z0-9/_.\-]+$', s))

def _valid_device(s):
    """Block device path, e.g. /dev/sda1."""
    return bool(s and re.match(r'^/dev/[a-zA-Z0-9]+$', s))

def _valid_iqn(s):
    """iSCSI IQN per RFC 3720."""
    return bool(s and re.match(
        r'^(iqn\.\d{4}-\d{2}\.[a-z0-9.\-]+:[a-zA-Z0-9._:\-]*'
        r'|eui\.[0-9a-fA-F]{16}'
        r'|naa\.[0-9a-fA-F]{16,32})$', s))

def _valid_port(s):
    """Numeric port 1–65535."""
    try:
        return 1 <= int(str(s)) <= 65535
    except (ValueError, TypeError):
        return False

def _valid_fstype(s):
    """Allowlisted filesystem types."""
    return s in {"ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "ntfs", "exfat", "f2fs"}

def _valid_script_path(path):
    """Path must resolve within the user's home directory."""
    try:
        resolved = Path(path).resolve()
        return resolved.is_relative_to(Path.home().resolve())
    except Exception:
        return False

def docker_ok():
    _, _, rc = run(["docker", "info"])
    return rc == 0

def is_mounted(path):
    _, _, rc = run(["mountpoint", "-q", path])
    return rc == 0

# ─────────────────────────────────────────────────────────────────────────────
# API — System
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/system")
def api_system():
    try:
        model = Path("/proc/device-tree/model").read_text(errors="ignore").replace("\x00", "").strip() or "Unknown"
    except Exception:
        model = "Unknown"
    hostname, _, _ = run(["hostname"])
    uptime, _, rc  = run(["uptime", "-p"])
    if rc != 0 or not uptime:
        uptime, _, _ = run(["uptime"])
    return jsonify({"dockerAvailable": docker_ok(), "model": model,
                    "hostname": hostname, "uptime": uptime})

# ─────────────────────────────────────────────────────────────────────────────
# API — Containers
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/containers")
def api_containers():
    if not docker_ok():
        return jsonify({"error": "Docker not available"}), 503
    fmt = "{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}|{{.RunningFor}}|{{.State}}"
    out, err, rc = run(["docker", "ps", "-a", "--format", fmt])
    if rc != 0:
        return jsonify({"error": err or "docker ps failed"}), 500
    rows = []
    for line in out.splitlines():
        p = line.split("|")
        if len(p) >= 6:
            rows.append({"id": p[0][:12], "name": p[1].lstrip("/"),
                         "statusText": p[2], "image": p[3],
                         "uptime": p[4], "status": p[5]})
    return jsonify(rows)

# ─────────────────────────────────────────────────────────────────────────────
# API — Config persistence
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def api_config_get():
    if CONFIG_FILE.exists():
        try:
            return jsonify(json.loads(CONFIG_FILE.read_text()))
        except Exception:
            pass
    return jsonify({})

# Every key the UI's collectConfig() can send, plus legacy keys older config
# files may carry (scriptPath, cronHuman) so a load -> save round-trip survives.
_CONFIG_ALLOWED_KEYS = {
    "version",
    # destination
    "destType", "secondaryDests", "mountPoint", "imageName",
    "iscsiPortal", "iscsiPort", "iscsiIQN", "iscsiDevice",
    "smbServer", "smbShare", "smbUser", "smbDomain", "smbVersion", "smbExtraOpts",
    "nfsServer", "nfsExport", "nfsMountOpts", "nfsCustomOpts",
    "usbDevice", "usbFsType", "localPath",
    # notifications
    "ntfyEnabled", "notifySuccess", "notifyFailure", "notifyStart",
    "ntfyTopic", "ntfyServer",
    # shutdown / containers
    "shutdownMethod", "shutdownFallback", "gracePeriod", "settleTime",
    "healthTimeout", "containerCfg", "tipiDir", "tipiUser", "tipiPass",
    # schedule
    "cronMode", "cronDays", "cronExpr", "cronHuman", "cronFreq",
    "cronHour", "cronMin", "customCron",
    # backup script / logging
    "scriptPath", "maxLogLines", "logPath", "lockFile", "imageHeadroom",
}

@app.route("/api/config", methods=["POST"])
def api_config_post():
    data = _body()
    unknown = sorted(set(data) - _CONFIG_ALLOWED_KEYS)
    if unknown:
        return jsonify({"error": f"Unknown config keys: {', '.join(unknown)}"}), 400
    data["version"] = 1
    try:
        CONFIG_FILE.write_text(json.dumps(data, indent=2))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# API — Mount helpers
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/mount/status")
def api_mount_status():
    path = request.args.get("path", "")
    if not _valid_mount_path(path):
        return jsonify({"error": "Invalid path"}), 400
    mounted = is_mounted(path)
    df = fstype = source = transport = ""
    if mounted:
        df = _df_line(path)
        mnt, _, _ = run(["findmnt", "-n", "-o", "SOURCE,FSTYPE", "--target", path])
        mnt = mnt.splitlines()[0] if mnt else ""
        parts = mnt.split()
        if len(parts) >= 2:
            source, fstype = parts[0], parts[1]
        # Derive base device (e.g. /dev/sdb1 -> sdb) and query transport
        base = _disk_base(source)
        tran, _, _ = run(["lsblk", "-d", "-n", "-o", "TRAN", f"/dev/{base}"])
        transport = tran.strip().lower()
    return jsonify({"mounted": mounted, "path": path, "df": df,
                    "fstype": fstype, "source": source, "transport": transport})

@app.route("/api/mount/do", methods=["POST"])
def api_mount_do():
    d = _body()
    action = d.get("action", "mount")    # "mount" | "unmount"
    path   = d.get("mountPoint", "")

    if not _valid_mount_path(path):
        return jsonify({"error": "Invalid mount path"}), 400

    if action == "unmount":
        _, err, rc = sudo_run(["umount", path])
        return jsonify({"ok": rc == 0, "error": err if rc else ""})

    dest = d.get("destType", "local")
    if dest == "smb":
        server  = d.get("smbServer","")
        share   = d.get("smbShare","")
        user    = d.get("smbUser","")
        pw      = d.get("smbPass","")
        domain  = d.get("smbDomain","WORKGROUP")
        ver     = d.get("smbVersion","3.0")
        extra   = d.get("smbExtraOpts","")
        if not _valid_hostname(server):
            return jsonify({"error": "Invalid SMB server"}), 400
        if not _valid_share(share):
            return jsonify({"error": "Invalid SMB share"}), 400
        # user/pw/domain/ver are NOT shell-escaped — they are passed as a
        # single argv element, so even a password like $(reboot) is inert.
        opts    = f"username={user},password={pw},domain={domain},vers={ver},uid=1000,gid=1000"
        if extra:
            if not re.match(r'^[a-zA-Z0-9=,._\-]+$', extra):
                return jsonify({"error": "Invalid SMB extra options"}), 400
            opts += "," + extra
        sudo_run(["mkdir", "-p", path])
        _, err, rc = sudo_run(["mount", "-t", "cifs", f"//{server}/{share}", path, "-o", opts], timeout=20)
    elif dest == "nfs":
        server  = d.get("nfsServer","")
        export  = d.get("nfsExport","")
        opts    = d.get("nfsMountOpts","vers=4,rw,sync")
        custom  = d.get("nfsCustomOpts","")
        if not _valid_hostname(server):
            return jsonify({"error": "Invalid NFS server"}), 400
        if not _valid_share(export):
            return jsonify({"error": "Invalid NFS export path"}), 400
        if custom:
            if not re.match(r'^[a-zA-Z0-9=,._\-]+$', custom):
                return jsonify({"error": "Invalid NFS custom options"}), 400
            opts += "," + custom
        sudo_run(["mkdir", "-p", path])
        _, err, rc = sudo_run(["mount", "-t", "nfs", f"{server}:{export}", path, "-o", opts], timeout=20)
    elif dest == "usb":
        device = d.get("usbDevice","")
        fstype = d.get("usbFsType","ext4")
        if not _valid_device(device):
            return jsonify({"error": "Invalid device path"}), 400
        if not _valid_fstype(fstype):
            return jsonify({"error": "Unsupported filesystem type"}), 400
        sudo_run(["mkdir", "-p", path])
        _, err, rc = sudo_run(["mount", "-t", fstype, device, path], timeout=15)
    elif dest == "iscsi":
        device = d.get("iscsiDevice","")
        if not _valid_device(device):
            return jsonify({"error": "Invalid device path"}), 400
        sudo_run(["mkdir", "-p", path])
        _, err, rc = sudo_run(["mount", device, path], timeout=15)
    else:
        # local — just verify
        ok = Path(path).is_dir()
        return jsonify({"ok": ok, "error": "" if ok else f"{path} not found"})

    if rc != 0:
        return jsonify({"ok": False, "error": err or "Mount failed"}), 500

    df = _df_line(path)
    return jsonify({"ok": True, "df": df})

@app.route("/api/mount/fstab", methods=["POST"])
def api_fstab():
    """Append an fstab entry (idempotent)."""
    d    = _body()
    line = d.get("line","").strip()
    if not line:
        return jsonify({"error": "No fstab line"}), 400
    fstab = Path("/etc/fstab").read_text()
    if line in fstab:
        return jsonify({"ok": True, "note": "Already present"})
    result = subprocess.run(
        ["sudo", "tee", "-a", "/etc/fstab"],
        input=line + "\n", text=True, capture_output=True
    )
    return jsonify({"ok": result.returncode == 0, "error": result.stderr if result.returncode else ""})

@app.route("/api/mount/fstab/check")
def api_fstab_check():
    """Return whether a mount point has an entry in /etc/fstab."""
    mount_point = request.args.get("path", "").strip()
    if not mount_point:
        return jsonify({"error": "path required"}), 400
    try:
        for line in Path("/etc/fstab").read_text().splitlines():
            s = line.strip()
            if s and not s.startswith("#") and len(s.split()) >= 2 and s.split()[1] == mount_point:
                return jsonify({"present": True, "line": s})
        return jsonify({"present": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mount/fstab/remove", methods=["POST"])
def api_fstab_remove():
    """Remove all fstab entries whose mount point (field 2) matches the given path."""
    mount_point = _body().get("mountPoint", "").strip()
    if not mount_point:
        return jsonify({"error": "mountPoint required"}), 400
    try:
        lines = Path("/etc/fstab").read_text().splitlines(keepends=True)
        kept = []
        removed = 0
        for line in lines:
            s = line.strip()
            fields = s.split()
            if s and not s.startswith("#") and len(fields) >= 2 and fields[1] == mount_point:
                removed += 1
            else:
                kept.append(line)
        new_content = "".join(kept)
        result = subprocess.run(["sudo", "tee", "/etc/fstab"],
                                input=new_content, text=True, capture_output=True)
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr}), 500
        return jsonify({"ok": True, "removed": removed})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# API — iSCSI
# ─────────────────────────────────────────────────────────────────────────────

def _iscsi_devices_by_iqn():
    """Parse 'iscsiadm -m session -P 3' to map IQN → block device path."""
    out, _, rc = sudo_run(["iscsiadm", "-m", "session", "-P", "3"])
    result = {}
    if rc != 0:
        return result
    current_iqn = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Target:"):
            # Line looks like "Target: iqn.… (non-flash)" — keep only the IQN
            parts = s.split("Target:", 1)[-1].split()
            current_iqn = parts[0] if parts else None
        elif "Attached scsi disk" in s and current_iqn:
            parts = s.split()
            try:
                idx = parts.index("disk")
                result[current_iqn] = "/dev/" + parts[idx + 1]
            except (ValueError, IndexError):
                pass
    return result

@app.route("/api/iscsi/discover", methods=["POST"])
def api_iscsi_discover():
    d      = _body()
    portal = d.get("portal","").strip()
    port   = d.get("port","3260")
    if not _valid_hostname(portal):
        return jsonify({"error": "Invalid portal address"}), 400
    if not _valid_port(port):
        return jsonify({"error": "Invalid port"}), 400
    out, err, rc = sudo_run(["iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", f"{portal}:{port}"], timeout=15, merge=True)
    if rc != 0:
        if "not found" in err.lower() or "not found" in out.lower():
            return jsonify({"error": "iscsiadm not found — install open-iscsi via the Destination tab"}), 503
        return jsonify({"error": err or out or "Discovery failed"}), 500
    targets = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            targets.append({"portal": parts[0], "iqn": parts[1]})
    return jsonify({"targets": targets, "raw": out})

@app.route("/api/iscsi/login", methods=["POST"])
def api_iscsi_login():
    d      = _body()
    portal = d.get("portal","").strip()
    iqn    = d.get("iqn","").strip()
    port   = d.get("port","3260")
    if not _valid_hostname(portal):
        return jsonify({"error": "Invalid portal address"}), 400
    if not _valid_iqn(iqn):
        return jsonify({"error": "Invalid IQN format"}), 400
    if not _valid_port(port):
        return jsonify({"error": "Invalid port"}), 400
    out, err, rc = sudo_run(["iscsiadm", "-m", "node", "-T", iqn, "-p", f"{portal}:{port}", "--login"], timeout=20, merge=True)
    if rc != 0 and "already" not in out.lower():
        return jsonify({"error": err or out or "Login failed"}), 500
    # Find the block device for this specific IQN via session detail — retry up to 5s
    device = ""
    for _ in range(5):
        device = _iscsi_devices_by_iqn().get(iqn, "")
        if device:
            break
        time.sleep(1)
    return jsonify({"ok": True, "message": out or "Logged in", "device": device})

@app.route("/api/iscsi/logout", methods=["POST"])
def api_iscsi_logout():
    d   = _body()
    iqn = d.get("iqn","").strip()
    if not _valid_iqn(iqn):
        return jsonify({"error": "Invalid IQN format"}), 400
    out, err, rc = sudo_run(["iscsiadm", "-m", "node", "-T", iqn, "--logout"], timeout=15, merge=True)
    return jsonify({"ok": rc == 0, "message": out, "error": err if rc else ""})

@app.route("/api/iscsi/autostart", methods=["POST"])
def api_iscsi_autostart():
    d      = _body()
    iqn    = d.get("iqn","").strip()
    enable = d.get("enable", True)
    if not _valid_iqn(iqn):
        return jsonify({"error": "Invalid IQN format"}), 400
    value = "automatic" if enable else "manual"
    out, err, rc = sudo_run(["iscsiadm", "-m", "node", "-T", iqn, "--op", "update", "-n", "node.startup", "-v", value], timeout=10, merge=True)
    if rc != 0:
        return jsonify({"ok": False, "error": err or out})
    if enable:
        sudo_run(["systemctl", "enable", "iscsid"], timeout=10, merge=True)
    return jsonify({"ok": True, "message": f"node.startup set to {value}"})

@app.route("/api/iscsi/sessions")
def api_iscsi_sessions():
    out, _, rc = run(["iscsiadm", "-m", "session"])
    sessions = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.strip().split()
            # format: tcp: [sid] portal,tpgt iqn [state]
            if len(parts) >= 4:
                sessions.append({"raw": line.strip(), "portal": parts[2].split(",")[0], "iqn": parts[3]})
    devices_by_iqn = _iscsi_devices_by_iqn()
    for s in sessions:
        s["device"] = devices_by_iqn.get(s["iqn"], "")
    return jsonify({"sessions": sessions, "count": len(sessions)})

# ─────────────────────────────────────────────────────────────────────────────
# API — NFS exports scan
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/nfs/exports", methods=["POST"])
def api_nfs_exports():
    d      = _body()
    server = d.get("server","").strip()
    if not server or not re.match(r'^[\w.\-]+$', server):
        return jsonify({"error": "Invalid or missing server address"}), 400
    out, err, rc = run(["showmount", "-e", server], timeout=10, merge=True)
    if rc != 0:
        return jsonify({"error": err or out or "showmount failed"}), 500
    lines = [l.strip() for l in out.splitlines() if l.startswith("/")]
    return jsonify({"exports": lines, "raw": out})

# ─────────────────────────────────────────────────────────────────────────────
# API — USB / block device scan
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/usb/scan")
def api_usb_scan():
    out, err, rc = run(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT"])
    if rc != 0:
        return jsonify({"error": err or "lsblk failed"}), 500
    try:
        data = json.loads(out)
        # Filter to only external-looking disks (exclude mmcblk = SD card, loop, rom)
        disks = [d for d in data.get("blockdevices",[])
                 if d.get("type") == "disk" and not d["name"].startswith(("mmcblk","loop","sr"))]
        return jsonify({"devices": disks})
    except Exception as e:
        return jsonify({"error": str(e), "raw": out}), 500

@app.route("/api/usb/uuid")
def api_usb_uuid():
    """Return the UUID for a block device, for stable fstab entries."""
    device = request.args.get("device","").strip()
    if not _valid_device(device):
        return jsonify({"error": "Invalid device path"}), 400
    out, _, rc = run(["blkid", "-s", "UUID", "-o", "value", device])
    uuid = out.strip()
    if rc != 0 or not uuid:
        return jsonify({"uuid": None})
    return jsonify({"uuid": uuid})

# ─────────────────────────────────────────────────────────────────────────────
# API — Local path verify
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/local/verify", methods=["POST"])
def api_local_verify():
    path = _body().get("path","").strip()
    p    = Path(path)
    ok   = p.is_dir() and os.access(path, os.W_OK)
    df   = ""
    if ok:
        df = _df_line(path)
    return jsonify({"ok": ok, "writable": ok, "df": df,
                    "error": "" if ok else f"{path} not found or not writable"})

# ─────────────────────────────────────────────────────────────────────────────
# API — Cron
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/cron", methods=["GET"])
def api_cron_get():
    out, _, _ = run(["crontab", "-l"])
    return jsonify({"crontab": out, "hasEntry": "weekly_image.sh" in out})

@app.route("/api/cron", methods=["POST"])
def api_cron_post():
    d           = _body()
    cron_line   = d.get("cronLine","").strip()
    script_path = d.get("scriptPath", str(Path.home() / "weekly_image.sh"))
    log_path    = d.get("logPath",    str(Path.home() / "cron_debug.log"))
    if not cron_line:
        return jsonify({"error": "No cron line"}), 400
    existing, _, _ = run(["crontab", "-l"])
    # match the old "Pi Backup Manager" marker too, so pre-rename installs are cleaned up
    lines = [l for l in existing.splitlines()
             if "weekly_image.sh" not in l and "SpareCard" not in l and "Pi Backup Manager" not in l]
    lines += [f"# SpareCard — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
              f"{cron_line} {script_path} >> {log_path} 2>&1"]
    new_tab = "\n".join(lines) + "\n"
    r = subprocess.run(["crontab", "-"], input=new_tab, text=True, capture_output=True)
    return jsonify({"ok": r.returncode == 0, "error": r.stderr if r.returncode else ""})

@app.route("/api/cron/remove", methods=["POST"])
def api_cron_remove():
    existing, _, _ = run(["crontab", "-l"])
    lines = [l for l in existing.splitlines()
             if "weekly_image.sh" not in l and "SpareCard" not in l and "Pi Backup Manager" not in l]
    new_tab = ("\n".join(lines) + "\n") if lines else "\n"
    r = subprocess.run(["crontab", "-"], input=new_tab, text=True, capture_output=True)
    return jsonify({"ok": r.returncode == 0, "error": r.stderr if r.returncode else ""})

# ─────────────────────────────────────────────────────────────────────────────
# API — Script write
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/script", methods=["GET"])
def api_script_read():
    path = request.args.get("path", str(Path.home() / "weekly_image.sh"))
    if not _valid_script_path(path):
        return jsonify({"error": "Path not allowed"}), 403
    p = Path(path).resolve()
    if not p.exists():
        return jsonify({"error": "Script not found"}), 404
    try:
        return jsonify({"ok": True, "path": str(p), "script": p.read_text()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/script", methods=["POST"])
def api_script():
    d       = _body()
    content = d.get("script","")
    path    = d.get("path", str(Path.home() / "weekly_image.sh"))
    if not content:
        return jsonify({"error": "No script content"}), 400
    if not _valid_script_path(path):
        return jsonify({"error": "Path not allowed"}), 403
    try:
        p = Path(path).resolve()
        p.write_text(content)
        p.chmod(0o755)
        return jsonify({"ok": True, "path": str(p)})
    except PermissionError:
        return jsonify({"error": "Permission denied writing script"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# API — Config defaults (dynamic, based on runtime user)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/config/defaults")
def api_config_defaults():
    home = Path.home()
    return jsonify({
        "scriptPath": str(home / "weekly_image.sh"),
        "logPath":    str(home / "cron_debug.log"),
        "tipiDir":    str(home / "runtipi"),
    })

# ─────────────────────────────────────────────────────────────────────────────
# API — Runtipi API test
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/runtipi/test", methods=["POST"])
def api_runtipi_test():
    d    = _body()
    user = d.get("tipiUser", "").strip()
    pw   = d.get("tipiPass", "").strip()
    if not user or not pw:
        return jsonify({"ok": False, "error": "Username and password are required"}), 400

    # Resolve container IP via docker inspect
    ip_out, _, rc = run(["docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "runtipi"])
    ip = ip_out.strip().split()[0] if ip_out.strip() else ""
    if not ip:
        return jsonify({"ok": False, "error": "runtipi container not found or not running"}), 503

    base_url = f"http://{ip}:3000"

    payload = json.dumps({"username": user, "password": pw}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/auth/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read())
            if body.get("success"):
                return jsonify({"ok": True, "url": base_url, "message": f"Login successful ({base_url})"})
            return jsonify({"ok": False, "error": f"Unexpected response: {body}"})
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return jsonify({"ok": False, "error": f"HTTP {e.code}: {body[:200]}"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

# ─────────────────────────────────────────────────────────────────────────────
# API — SMB connection test
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/smb/test", methods=["POST"])
def api_smb_test():
    d      = _body()
    server = d.get("smbServer","").strip()
    user   = d.get("smbUser","").strip()
    pw     = d.get("smbPass","").strip()
    if not server or not re.match(r'^[\w.\-]+$', server):
        return jsonify({"ok": False, "error": "Invalid server address"}), 400
    # Write credentials to a temp file so the password never appears in the process list
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cred', delete=False) as tf:
            tf.write(f"username={user}\npassword={pw}\n")
            cred_file = tf.name
        out, err, rc = run(["smbclient", "-L", f"//{server}", "-A", cred_file, "-N"], timeout=10, merge=True)
    finally:
        try:
            os.unlink(cred_file)
        except Exception:
            pass
    if rc != 0:
        return jsonify({"ok": False, "error": err or out}), 500
    shares = [l.strip() for l in out.splitlines() if "Disk" in l]
    return jsonify({"ok": True, "shares": shares, "raw": out})

@app.route("/api/smb/credentials", methods=["POST"])
def api_smb_credentials():
    """Write SMB credentials to /etc/samba/credentials (mode 600, root-owned)."""
    d    = _body()
    user = d.get("smbUser","").strip()
    pw   = d.get("smbPass","").strip()
    if not user:
        return jsonify({"error": "smbUser required"}), 400
    content = f"username={user}\npassword={pw}\n"
    # Write via sudo tee so root owns the file
    result = subprocess.run(
        ["sudo", "tee", "/etc/samba/credentials"],
        input=content, text=True, capture_output=True
    )
    if result.returncode != 0:
        return jsonify({"ok": False, "error": result.stderr}), 500
    sudo_run(["chmod", "600", "/etc/samba/credentials"], timeout=5)
    sudo_run(["chown", "root:root", "/etc/samba/credentials"], timeout=5)
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────────────────────────
# API — Image ownership marker
# ─────────────────────────────────────────────────────────────────────────────
# A sidecar file <image>.sparecard.json records which host wrote the image.
# Backups refuse to touch an existing image without this Pi's marker, so a
# pre-existing image at a destination is never silently overwritten. The
# generated backup script enforces the same rule (and updates the marker).

def _image_marker_path(image_path):
    return Path(str(image_path) + ".sparecard.json")

def _ownership_args():
    """Resolve mount point + image name from request args/body, falling back
    to the saved config."""
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    src = request.args if request.method == "GET" else (_body() or {})
    mp  = (src.get("path") or cfg.get("mountPoint", "/mnt/backups")).strip()
    img = (src.get("image") or cfg.get("imageName", "pi_backup.img")).strip()
    if not mp.startswith("/") or "/" in img or ".." in img or not img:
        return None, None
    return mp, img

@app.route("/api/image/ownership")
def api_image_ownership():
    mp, img = _ownership_args()
    if not mp:
        return jsonify({"error": "Invalid path or image name"}), 400
    image  = Path(mp) / img
    info   = {"path": str(image), "imageExists": image.exists(), "sizeH": "",
              "mtime": 0, "markerExists": False, "markerHost": "",
              "ours": False, "host": socket.gethostname()}
    if info["imageExists"]:
        try:
            st = image.stat()
            info["sizeH"]  = _human_size(st.st_size)
            info["mtime"]  = int(st.st_mtime)
        except Exception:
            pass
        marker = _image_marker_path(image)
        if marker.exists():
            info["markerExists"] = True
            try:
                info["markerHost"] = json.loads(marker.read_text()).get("hostname", "")
            except Exception:
                pass
            info["ours"] = bool(info["markerHost"]) and info["markerHost"] == info["host"]
    return jsonify(info)

@app.route("/api/image/adopt", methods=["POST"])
def api_image_adopt():
    """Mark an existing image as owned by this host, so backups may update it."""
    mp, img = _ownership_args()
    if not mp:
        return jsonify({"error": "Invalid path or image name"}), 400
    image = Path(mp) / img
    if not image.exists():
        return jsonify({"error": f"{image} not found"}), 404
    content = json.dumps({"hostname": socket.gethostname(),
                          "adopted": int(time.time())}) + "\n"
    # sudo tee — the mounted destination is usually root-owned
    result = subprocess.run(["sudo", "tee", str(_image_marker_path(image))],
                            input=content, text=True, capture_output=True)
    if result.returncode != 0:
        return jsonify({"ok": False, "error": result.stderr}), 500
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────────────────────────
# API — Manual backup run (SSE stream)
# ─────────────────────────────────────────────────────────────────────────────

_BACKUP_PHASE_PATTERNS = [
    (0, "Pi Backup Starting"),
    (1, "STARTING IMAGE CREATION"),
    (2, "BACKUP SUCCESSFUL"),
    (3, "All done"),
]

def _run_backup_thread(job, script_path):
    proc = subprocess.Popen(
        ["bash", script_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    for line in proc.stdout:
        stripped = line.rstrip()
        job.emit(stripped)
        for phase, kw in _BACKUP_PHASE_PATTERNS:
            if kw in stripped:
                job.event({"type": "phase", "phase": phase})
                break
    proc.wait()
    result = "success" if proc.returncode == 0 else "failed"
    job.finish(result, code=proc.returncode)

@app.route("/api/backup/run", methods=["POST"])
def api_backup_run():
    if backup_job.running:
        return jsonify({"error": "Backup already running"}), 409
    d           = _body()
    script_path = d.get("scriptPath", str(Path.home() / "weekly_image.sh"))
    if not Path(script_path).exists():
        return jsonify({"error": f"Script not found: {script_path}. Generate and save it first."}), 404
    if not backup_job.start(_run_backup_thread, script_path):
        return jsonify({"error": "Backup already running"}), 409
    return jsonify({"ok": True})

@app.route("/api/backup/stream")
def api_backup_stream():
    """Server-Sent Events stream of live backup log lines."""
    return backup_job.stream()

@app.route("/api/backup/status")
def api_backup_status():
    return jsonify(backup_job.status)

def _parse_log_ts(s):
    """Parse 'Sun  8 Mar 03:06:48 AEDT 2026' → unix timestamp (local time), or None."""
    if not s:
        return None
    try:
        s = ' '.join(s.split())                    # normalise whitespace
        s = re.sub(r' [A-Z]{2,5} ', ' ', s)        # strip TZ abbrev (AEDT, UTC …)
        dt = datetime.strptime(s, "%a %d %b %H:%M:%S %Y")
        return int(dt.timestamp())
    except Exception:
        return None

def _apply_sentinel_fallback(cfg, out):
    """If .image_initialised sentinel exists, populate out with inferred success."""
    try:
        mount_point = cfg.get("mountPoint", "/mnt/backups")
        image_name  = cfg.get("imageName",  "pi_backup.img")
        sentinel    = Path(mount_point) / ".image_initialised"
        image_path  = Path(mount_point) / image_name
        if sentinel.exists():
            out["result"] = "success"
            out["inferred"] = True
            # Use image mtime if available, else sentinel mtime
            ref = image_path if image_path.exists() else sentinel
            out["finished_ts"] = int(ref.stat().st_mtime)
    except Exception:
        pass

@app.route("/api/backup/last")
def api_backup_last():
    """Parse the backup log file to return the last backup result and timing."""
    cfg = {}
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception:
        pass
    return jsonify(_compute_last_backup(cfg))

def _compute_last_backup(cfg):
    """Last backup result/timing parsed from the log file, as a plain dict —
    shared by the route above and the dashboard (which used to re-enter the
    route through a fake test_request_context)."""
    log_path = cfg.get("logPath", str(Path.home() / "cron_debug.log"))

    out = {"result": None, "started": None, "finished": None,
           "elapsed": None, "finished_ts": None, "running": backup_job.running,
           "log_lines": []}

    try:
        # Read only the last 4000 lines to avoid slow scans on large log files
        result = subprocess.run(["tail", "-n", "4000", log_path],
                                capture_output=True, text=True)
        lines = result.stdout.splitlines(keepends=True) if result.returncode == 0 else []
        if not lines:
            _apply_sentinel_fallback(cfg, out)
            return out
    except Exception:
        _apply_sentinel_fallback(cfg, out)
        return out

    # Find the last "Weekly Image Backup" start marker
    start_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if "--- Weekly Image Backup" in lines[i]:
            start_idx = i
            break
    if start_idx is None:
        _apply_sentinel_fallback(cfg, out)
        return out

    line = lines[start_idx]
    sep = ": ---"
    out["started"] = line[:line.index(sep)].strip() if sep in line else None
    out["started_ts"] = _parse_log_ts(out["started"])

    # Scan forward from start for success or failure markers
    end_idx = len(lines)
    for i in range(start_idx, len(lines)):
        line = lines[i].rstrip()
        if "All done." in line:
            out["result"] = "success"
            sep2 = ": All done"
            out["finished"] = line[:line.index(sep2)].strip() if sep2 in line else None
            if "Total elapsed:" in line:
                out["elapsed"] = line.split("Total elapsed:")[-1].strip()
            end_idx = i + 1
            break
        if "ERROR - image-backup" in line or "FATAL -" in line:
            out["result"] = "failed"
            idx = line.index(": ") if ": " in line else -1
            out["finished"] = line[:idx].strip() if idx > 0 else None
            end_idx = i + 1
            break

    out["finished_ts"] = _parse_log_ts(out["finished"])

    # If still running, scan backwards for the previous run's elapsed time (for ETA)
    if out["result"] is None:
        for i in range(start_idx - 1, -1, -1):
            if "All done." in lines[i] and "Total elapsed:" in lines[i]:
                out["prev_elapsed"] = lines[i].split("Total elapsed:")[-1].strip()
                break

    # Collect deduplicated log lines from this run (skip consecutive duplicates)
    snippet, prev = [], None
    for raw in lines[start_idx:end_idx]:
        s = raw.rstrip()
        if s and s != prev:
            snippet.append(s)
            prev = s
    out["log_lines"] = snippet[-40:]

    # Sentinel fallback: if log gave no result, check .image_initialised on disk
    if not out["result"]:
        _apply_sentinel_fallback(cfg, out)

    return out

# ─────────────────────────────────────────────────────────────────────────────
# API — Image verify (losetup + fsck, SSE stream)
# ─────────────────────────────────────────────────────────────────────────────

def _run_verify_thread(job, image_path):
    emit = job.emit
    loop_dev = None

    try:
        if not Path(image_path).exists():
            emit(f"Image not found: {image_path}", "err")
            job.finish("failed")
            return

        emit(f"► Attaching loop device for {image_path} …", "cmd")
        out, err, rc = sudo_run(["losetup", "-fP", "--show", image_path], timeout=30)
        loop_dev = out.strip()
        if rc != 0 or not loop_dev:
            emit(f"losetup failed — {err or out}", "err")
            job.finish("failed")
            return
        emit(f"Loop device: {loop_dev}", "ok")

        part_results = {}
        for part, label in [("p1", "boot / FAT32"), ("p2", "root / ext4")]:
            dev = f"{loop_dev}{part}"
            emit("", "info")
            emit(f"► Checking {label} — {dev}", "cmd")
            proc = subprocess.Popen(
                ["sudo", "fsck", "-n", "-v", dev],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                lvl = ("err"  if any(x in line for x in ("ERROR","FATAL","corrupt")) else
                       "warn" if any(x in line for x in ("WARNING","warning","bad")) else
                       "ok"   if any(x in line.lower() for x in ("clean","no problems","no error")) else
                       "info")
                emit(line, lvl)
            proc.wait()
            part_results[part] = proc.returncode
            emit(f"fsck exit code: {proc.returncode} "
                 f"({'clean' if proc.returncode == 0 else 'errors found' if proc.returncode == 1 else 'check failed'})",
                 "ok" if proc.returncode == 0 else "warn" if proc.returncode == 1 else "err")

        emit("", "info")
        emit(f"► Detaching {loop_dev} …", "cmd")
        sudo_run(["losetup", "-d", loop_dev], timeout=10)
        loop_dev = None
        emit("Loop device detached.", "ok")

        # fsck -n: 0=clean, 1=errors found (not fixed), >=4=operational failure
        p2 = part_results.get("p2", 8)
        p1 = part_results.get("p1", 8)
        if p2 == 0 and p1 in (0, 1):
            result = "success"
        elif p2 == 1:
            result = "warning"
        else:
            result = "failed"

        job.finish(result)

    finally:
        if loop_dev:
            sudo_run(["losetup", "-d", loop_dev], timeout=10)

@app.route("/api/verify/run", methods=["POST"])
def api_verify_run():
    if verify_job.running:
        return jsonify({"error": "Verify already running"}), 409
    if backup_job.running:
        return jsonify({"error": "Backup is running — wait for it to finish"}), 409
    d = _body()
    image_path = d.get("imagePath", "")
    if not image_path:
        return jsonify({"error": "No imagePath provided"}), 400
    if not verify_job.start(_run_verify_thread, image_path):
        return jsonify({"error": "Verify already running"}), 409
    return jsonify({"ok": True})

@app.route("/api/verify/stream")
def api_verify_stream():
    return verify_job.stream()

# ─────────────────────────────────────────────────────────────────────────────
# API — Image status & compact (sparsify)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/image-status")
def api_image_status():
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    mount_point = cfg.get("mountPoint", "/mnt/backups")
    image_name  = cfg.get("imageName",  "pi_backup.img")
    headroom_mb = int(cfg.get("imageHeadroom", 5000))
    image_path  = f"{mount_point}/{image_name}"

    result = {
        "image_path": image_path, "exists": False,
        "logical_mb": 0, "sparse_mb": 0, "source_used_mb": 0,
        "headroom_mb": headroom_mb, "wasted_mb": 0,
        "compact_recommended": False,
    }
    stats = _image_stats(image_path)
    if not stats["exists"]:
        return jsonify(result)

    result["exists"]     = True
    result["logical_mb"] = stats["logical_mb"]
    result["sparse_mb"]  = stats["sparse_mb"]
    try:
        result["source_used_mb"] = shutil.disk_usage("/").used // (1024 * 1024)
    except OSError:
        pass

    wasted = result["sparse_mb"] - result["source_used_mb"] - headroom_mb
    result["wasted_mb"]           = max(0, wasted)
    result["compact_recommended"] = wasted > result["source_used_mb"] * 0.40
    return jsonify(result)


def _run_compact_thread(job, image_path):
    emit = job.emit
    loop_dev = None
    mnt = "/tmp/pbm_compact_mnt"

    try:
        if not Path(image_path).exists():
            emit(f"Image not found: {image_path}", "err")
            job.finish("failed")
            return

        before = _image_stats(image_path)
        before_bytes, before_sparse = before["logical_bytes"], before["sparse_bytes"]

        emit(f"► Image: {image_path}", "cmd")
        emit(f"  Logical size : {before_bytes // (1024*1024):,} MB", "info")
        emit(f"  Actual usage : {before_sparse // (1024*1024):,} MB (sparse holes counted)", "info")
        emit("", "info")

        emit("► Step 1: Attach loop device …", "cmd")
        out, err, rc = sudo_run(["losetup", "-fP", "--show", image_path], timeout=30)
        loop_dev = out.strip()
        if rc != 0 or not loop_dev:
            emit(f"losetup failed: {err or out}", "err")
            job.finish("failed")
            return
        emit(f"  Loop device: {loop_dev}", "ok")
        emit("", "info")

        emit("► Step 2: e2fsck on root partition …", "cmd")
        proc = subprocess.Popen(
            ["sudo", "e2fsck", "-fy", f"{loop_dev}p2"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line: emit(line, "info")
        proc.wait()
        emit(f"  e2fsck exit: {proc.returncode}", "ok" if proc.returncode in (0, 1) else "warn")
        emit("", "info")

        if shutil.which("zerofree"):
            emit("► Step 3: Zeroing free blocks with zerofree …", "cmd")
            proc = subprocess.Popen(
                ["sudo", "zerofree", "-v", f"{loop_dev}p2"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line: emit(line, "info")
            proc.wait()
            emit(f"  zerofree exit: {proc.returncode}", "ok" if proc.returncode == 0 else "warn")
        else:
            emit("► Step 3: zerofree not found — using mount + zero-fill method …", "cmd")
            sudo_run(["mkdir", "-p", mnt])
            _, err_mnt, rc_mnt = sudo_run(["mount", f"{loop_dev}p2", mnt], timeout=30)
            if rc_mnt != 0:
                emit(f"  mount failed ({err_mnt}) — skipping zero-fill, holes may be limited", "warn")
            else:
                emit("  Writing zeros to free space — this may take several minutes …", "info")
                sudo_run(["dd", "if=/dev/zero", f"of={mnt}/zero.tmp", "bs=1M"], timeout=3600)
                sudo_run(["rm", "-f", f"{mnt}/zero.tmp"])
                sudo_run(["umount", mnt], timeout=30)
                emit("  Zero-fill complete.", "ok")
        emit("", "info")

        emit("► Step 4: Detach loop device …", "cmd")
        sudo_run(["losetup", "-d", loop_dev], timeout=10)
        loop_dev = None
        emit("  Detached.", "ok")
        emit("", "info")

        emit("► Step 5: Punch holes (fallocate --dig-holes) …", "cmd")
        _, err, rc = sudo_run(["fallocate", "--dig-holes", image_path], timeout=120)
        if rc != 0:
            emit(f"  fallocate warning: {err}", "warn")
        else:
            emit("  Holes punched.", "ok")

        after_sparse = _image_stats(image_path)["sparse_bytes"]

        saved_mb = (before_sparse - after_sparse) // (1024 * 1024)
        emit("", "info")
        emit("✓ Compact complete!", "ok")
        emit(f"  Before : {before_sparse // (1024*1024):,} MB on disk", "info")
        emit(f"  After  : {after_sparse  // (1024*1024):,} MB on disk", "info")
        emit(f"  Saved  : {saved_mb:,} MB", "ok" if saved_mb > 0 else "info")

        job.finish("success", saved_mb=saved_mb)

    finally:
        if loop_dev:
            sudo_run(["losetup", "-d", loop_dev], timeout=10)
        sudo_run(["umount", mnt], timeout=10)
        sudo_run(["rm", "-rf", mnt], timeout=10)


@app.route("/api/compact/run", methods=["POST"])
def api_compact_run():
    if compact_job.running:
        return jsonify({"error": "Compact already running"}), 409
    if backup_job.running:
        return jsonify({"error": "Backup is running — wait for it to finish"}), 409
    if verify_job.running:
        return jsonify({"error": "Verify is running — wait for it to finish"}), 409
    d = _body()
    image_path = d.get("imagePath", "")
    if not image_path:
        return jsonify({"error": "No imagePath provided"}), 400
    if not compact_job.start(_run_compact_thread, image_path):
        return jsonify({"error": "Compact already running"}), 409
    return jsonify({"ok": True})


@app.route("/api/compact/stream")
def api_compact_stream():
    return compact_job.stream()


_dashboard_cache = {"ts": 0.0, "payload": None}
_DASHBOARD_TTL   = 3.0   # seconds; ~10 subprocesses saved per cached hit

@app.route("/api/dashboard")
def api_dashboard():
    """Aggregate status for dashboard: last backup, image, mount, cron.
    Served from a short TTL cache so rapid reloads / polling don't fork
    tail/du/findmnt/flock/crontab on every request."""
    now = time.monotonic()
    if _dashboard_cache["payload"] is not None and now - _dashboard_cache["ts"] < _DASHBOARD_TTL:
        return jsonify(_dashboard_cache["payload"])
    payload = _compute_dashboard()
    _dashboard_cache["payload"] = payload
    _dashboard_cache["ts"]      = now
    return jsonify(payload)

def _compute_dashboard():
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    mount_point = cfg.get("mountPoint", "/mnt/backups")
    image_name  = cfg.get("imageName",  "pi_backup.img")
    log_path    = cfg.get("logPath",    str(Path.home() / "cron_debug.log"))
    lock_file   = cfg.get("lockFile",   "/tmp/weekly_image.lock")

    # ── Last backup (reuse existing logic) ───────────────────────────────────
    last_raw = _compute_last_backup(cfg)

    # ── Image status ──────────────────────────────────────────────────────────
    stats = _image_stats(Path(mount_point) / image_name)
    image_info = {"exists": False}
    if stats["exists"]:
        image_info = {
            "exists": True,
            "logical_mb": stats["logical_mb"],
            "sparse_mb":  stats["sparse_mb"],
            "wasted_mb":  stats["logical_mb"] - stats["sparse_mb"],
            "compact_recommended": (stats["logical_mb"] - stats["sparse_mb"]) > 500,
        }

    # ── Sentinel / lock ───────────────────────────────────────────────────────
    sentinel_exists = (Path(mount_point) / ".image_initialised").exists()
    lock_exists     = Path(lock_file).exists()
    # flock only releases on process exit; file persists — test if lock is held
    lock_held = False
    if lock_exists:
        _, _, _flock_rc = run(["flock", "-n", lock_file, "true"])
        lock_held = (_flock_rc != 0)

    # ── Mount status ──────────────────────────────────────────────────────────
    mount_info = {"mounted": False}
    try:
        out, _, rc = run(["findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE", mount_point])
        if rc == 0 and out.strip():
            parts = out.strip().split()
            mount_info = {
                "mounted": True,
                "source":  parts[1] if len(parts) > 1 else "",
                "fstype":  parts[2] if len(parts) > 2 else "",
            }
    except Exception:
        pass

    # ── Cron schedule ─────────────────────────────────────────────────────────
    cron_info = {"installed": False, "expr": "", "human": ""}
    try:
        script_path = cfg.get("scriptPath", str(Path.home() / "weekly_image.sh"))
        out, _, rc  = run(["crontab", "-l"])
        for line in (out or "").splitlines():
            if script_path in line and not line.strip().startswith("#"):
                parts = line.strip().split()
                cron_info = {
                    "installed": True,
                    "expr":  " ".join(parts[:5]) if len(parts) >= 5 else line.strip(),
                    "human": cfg.get("cronHuman", ""),
                }
                break
        if not cron_info["human"]:
            cron_info["human"] = cfg.get("cronExpr", "")
    except Exception:
        pass

    return {
        "last":     last_raw,
        "image":    image_info,
        "mount":    mount_info,
        "cron":     cron_info,
        "sentinel": sentinel_exists,
        "lock":     lock_exists,
        "running":  backup_job.running or lock_held,
    }


@app.route("/api/cleanup", methods=["POST"])
def api_cleanup():
    """Delete selected backup artefacts: sentinel, lock file, compact temp, image file."""
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    mount_point = cfg.get("mountPoint", "/mnt/backups")
    image_name  = cfg.get("imageName",  "pi_backup.img")
    lock_file   = cfg.get("lockFile",   "/tmp/weekly_image.lock")
    d = request.get_json(force=True, silent=True) or {}
    targets = d.get("targets", [])
    results = {}
    if "sentinel" in targets:
        p = str(Path(mount_point) / ".image_initialised")
        _, _, rc = sudo_run(["rm", "-f", p], timeout=10)
        results["sentinel"] = "deleted" if rc == 0 else "not found or error"
    if "lock" in targets:
        _, _, rc = sudo_run(["rm", "-f", lock_file], timeout=10)
        results["lock"] = "deleted" if rc == 0 else "not found or error"
    if "compact_tmp" in targets:
        sudo_run(["umount", "-l", "/tmp/pbm_compact_mnt"], timeout=15)
        _, _, rc = sudo_run(["rm", "-rf", "/tmp/pbm_compact_mnt"], timeout=15)
        results["compact_tmp"] = "cleaned" if rc == 0 else "cleaned (best-effort)"
    if "image" in targets:
        mnt = Path(mount_point)
        imgs = list(mnt.glob("*.img"))
        if not imgs:
            results["image"] = "not found"
        else:
            # Remove ownership markers with their images, so a future foreign
            # image at the same path isn't silently trusted
            doomed = imgs + [m for p in imgs if (m := _image_marker_path(p)).exists()]
            _, _, rc = sudo_run(["rm", "-f", *[str(p) for p in doomed]], timeout=30)
            results["image"] = f"deleted {len(imgs)} file(s)" if rc == 0 else "error"
    return jsonify({"ok": True, "results": results})

# ─────────────────────────────────────────────────────────────────────────────
# API — Dependency check & install
# ─────────────────────────────────────────────────────────────────────────────

def _detect_pkg_mgr():
    for mgr in ["apt-get", "pacman", "dnf", "yum", "zypper", "apk", "xbps-install"]:
        path = shutil.which(mgr)
        if path:
            return mgr, path
    return "apt-get", "/usr/bin/apt-get"

_PKG_MGR, _PKG_BIN = _detect_pkg_mgr()

# Install command args per package manager (binary path + these args + package name)
_PKG_INSTALL_ARGS = {
    "apt-get":      ["install", "-y"],
    "pacman":       ["-S", "--noconfirm", "--needed"],
    "dnf":          ["install", "-y"],
    "yum":          ["install", "-y"],
    "zypper":       ["install", "-y"],
    "apk":          ["add"],
    "xbps-install": ["-y"],
}

# Canonical name (what the frontend sends) → distro-specific package name
_PKG_NAME_MAP = {
    "open-iscsi": {
        "apt-get": "open-iscsi",
        "pacman":  "open-iscsi",
        "dnf":     "iscsi-initiator-utils",
        "yum":     "iscsi-initiator-utils",
        "zypper":  "open-iscsi",
        "apk":     "open-iscsi",
        "xbps-install": "open-iscsi",
    },
    "cifs-utils": {
        "apt-get": "cifs-utils",
        "pacman":  "cifs-utils",
        "dnf":     "cifs-utils",
        "yum":     "cifs-utils",
        "zypper":  "cifs-utils",
        "apk":     "cifs-utils",
        "xbps-install": "cifs-utils",
    },
    "smbclient": {
        "apt-get": "smbclient",
        "pacman":  "smbclient",
        "dnf":     "samba-client",
        "yum":     "samba-client",
        "zypper":  "samba-client",
        "apk":     "samba-client",
        "xbps-install": "samba",
    },
    "nfs-common": {
        "apt-get": "nfs-common",
        "pacman":  "nfs-utils",
        "dnf":     "nfs-utils",
        "yum":     "nfs-utils",
        "zypper":  "nfs-client",
        "apk":     "nfs-utils",
        "xbps-install": "nfs-utils",
    },
}

# Binary → canonical package name (frontend uses canonical names)
_DEP_PKGS = {
    "iscsiadm":   "open-iscsi",
    "mount.cifs": "cifs-utils",
    "smbclient":  "smbclient",
    "showmount":  "nfs-common",
    "mount.nfs":  "nfs-common",
}
_ALLOWED_PKGS = set(_PKG_NAME_MAP.keys())

@app.route("/api/deps/check")
def api_deps_check():
    result = {}
    for binary in _DEP_PKGS:
        result[binary] = shutil.which(binary) is not None
    result["image-backup"] = Path("/usr/local/sbin/image-backup").exists()
    result["fsck"] = shutil.which("fsck") is not None
    return jsonify(result)

def _run_install_thread(job, canonical_pkg):
    distro_pkg = _PKG_NAME_MAP.get(canonical_pkg, {}).get(_PKG_MGR, canonical_pkg)
    cmd = ["sudo", _PKG_BIN] + _PKG_INSTALL_ARGS.get(_PKG_MGR, ["install", "-y"]) + [distro_pkg]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    for line in proc.stdout:
        job.emit(line.rstrip())
    proc.wait()
    result = "success" if proc.returncode == 0 else "failed"
    job.finish(result, code=proc.returncode)

@app.route("/api/deps/install", methods=["POST"])
def api_deps_install():
    if install_job.running:
        return jsonify({"error": "Install already running"}), 409
    pkg = _body().get("package", "").strip()
    if pkg not in _ALLOWED_PKGS:
        return jsonify({"error": f"Package '{pkg}' is not in the allowed list"}), 400
    if not install_job.start(_run_install_thread, pkg):
        return jsonify({"error": "Install already running"}), 409
    return jsonify({"ok": True})

@app.route("/api/deps/stream")
def api_deps_stream():
    return install_job.stream()

# ─────────────────────────────────────────────────────────────────────────────
# API — image-backup guided install
# ─────────────────────────────────────────────────────────────────────────────

_IMGBAK_REPO = Path.home() / "RonR-RPi-image-utils"

def _run_imgbak_thread(job, update=False):
    emit, done = job.emit, job.finish

    try:
        # Step 1 — ensure git is available
        emit("► Checking for git…", "cmd")
        if shutil.which("git") is None:
            emit("git not found — installing via apt…", "warn")
            out, err, rc2 = sudo_run(["apt-get", "install", "-y", "git"], timeout=120, merge=True)
            for l in (out + "\n" + err).splitlines():
                if l.strip(): emit(l, "info")
            if rc2 != 0:
                emit("Failed to install git.", "err"); done("failed"); return
            emit("git installed ✓", "ok")
        else:
            emit("git found ✓", "ok")

        # Step 2 — clone or update
        if update and _IMGBAK_REPO.exists():
            emit(f"► Updating existing clone at {_IMGBAK_REPO}…", "cmd")
            emit(f"git -C {_IMGBAK_REPO} pull", "cmd")
            out, err, rc = run(["git", "-C", str(_IMGBAK_REPO), "pull"], timeout=120, merge=True)
            for l in (out + "\n" + err).splitlines():
                if l.strip(): emit(l, "info")
            if rc != 0:
                emit("git pull failed.", "err"); done("failed"); return
            emit("Repository updated ✓", "ok")
        else:
            if _IMGBAK_REPO.exists():
                emit(f"Removing old directory {_IMGBAK_REPO}…", "info")
                run(["rm", "-rf", str(_IMGBAK_REPO)])
            emit("► Cloning RonR-RPi-image-utils from GitHub…", "cmd")
            emit("git clone https://github.com/seamusdemora/RonR-RPi-image-utils.git", "cmd")
            out, err, rc = run(
                ["git", "clone", "https://github.com/seamusdemora/RonR-RPi-image-utils.git", str(_IMGBAK_REPO)],
                timeout=120, merge=True)
            for l in (out + "\n" + err).splitlines():
                if l.strip(): emit(l, "info")
            if rc != 0:
                emit("Clone failed — check internet connectivity.", "err"); done("failed"); return
            emit("Clone complete ✓", "ok")

        # Step 3 — install binaries
        emit("► Installing image-* utilities to /usr/local/sbin…", "cmd")
        emit(f"sudo install --mode=755 {_IMGBAK_REPO}/image-* /usr/local/sbin", "cmd")
        img_bins = sorted(glob(str(_IMGBAK_REPO / "image-*")))
        if not img_bins:
            emit("No image-* utilities found in the clone.", "err"); done("failed"); return
        out, err, rc = sudo_run(["install", "--mode=755", *img_bins, "/usr/local/sbin"], timeout=30, merge=True)
        for l in (out + "\n" + err).splitlines():
            if l.strip(): emit(l, "info")
        if rc != 0:
            emit("Install step failed.", "err"); done("failed"); return

        # Step 4 — verify
        emit("► Verifying installation…", "cmd")
        if Path("/usr/local/sbin/image-backup").exists():
            emit("✓ image-backup installed successfully at /usr/local/sbin/image-backup", "ok")
            emit("✓ All done! You can now generate and run backups.", "ok")
            done("success")
        else:
            emit("Verification failed — /usr/local/sbin/image-backup not found.", "err")
            done("failed")

    except Exception as e:
        emit(f"Exception: {e}", "err")
        done("failed")

@app.route("/api/imgbak/install", methods=["POST"])
def api_imgbak_install():
    if imgbak_job.running:
        return jsonify({"error": "Install already running"}), 409
    update = _body().get("update", False)
    if not imgbak_job.start(_run_imgbak_thread, update):
        return jsonify({"error": "Install already running"}), 409
    return jsonify({"ok": True})

@app.route("/api/imgbak/stream")
def api_imgbak_stream():
    return imgbak_job.stream()

# ─────────────────────────────────────────────────────────────────────────────
# API — Restore
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/restore/devices")
def api_restore_devices():
    """List block devices suitable as restore targets, flagging the boot device."""
    boot_src, _, _ = run(["findmnt", "-n", "-o", "SOURCE", "/"])
    boot_base = _disk_base(boot_src)
    out, _, rc = run(["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,TRAN,HOTPLUG"])
    devices = []
    if rc == 0:
        try:
            for d in json.loads(out).get("blockdevices", []):
                if d.get("type") != "disk" or d["name"].startswith(("loop", "sr")):
                    continue
                try:
                    size_bytes = int(d.get("size") or 0)
                except (TypeError, ValueError):
                    size_bytes = 0
                devices.append({
                    "name":        f"/dev/{d['name']}",
                    "size":        _human_size(size_bytes),
                    "sizeBytes":   size_bytes,
                    "model":       (d.get("model") or "").strip(),
                    "tran":        (d.get("tran")  or "").strip(),
                    "hotplug":     str(d.get("hotplug", "0")).lower() in ("1", "true"),
                    "isBootDevice": d["name"] == boot_base,
                    "partitions":  [c.get("name","") for c in (d.get("children") or [])],
                })
        except Exception:
            pass
    return jsonify({"devices": devices, "bootDevice": f"/dev/{boot_base}"})

@app.route("/api/restore/verify", methods=["POST"])
def api_restore_verify():
    """Check that an image file exists and return its size."""
    path = _body().get("imagePath", "").strip()
    p = Path(path)
    if not p.exists():
        return jsonify({"ok": False, "error": f"File not found: {path}"})
    size_bytes = p.stat().st_size
    size_gb    = round(size_bytes / (1024**3), 2)
    return jsonify({"ok": True, "path": path, "sizeBytes": size_bytes, "sizeGb": size_gb})

def _run_restore_thread(job, image_path, target_device):
    emit, done = job.emit, job.finish

    try:
        emit("=" * 60, "info")
        emit("  RESTORE OPERATION — READ-ONLY: IMAGE → DEVICE", "warn")
        emit("=" * 60, "info")
        emit(f"  Source : {image_path}", "info")
        emit(f"  Target : {target_device}  ← ALL DATA WILL BE ERASED", "warn")
        emit("=" * 60, "info")
        emit("", "info")

        # Verify image file
        emit("► Verifying image file…", "cmd")
        if not Path(image_path).exists():
            emit(f"Image not found: {image_path}", "err"); done("failed"); return
        size_gb = Path(image_path).stat().st_size / (1024**3)
        emit(f"Image: {image_path}  ({size_gb:.2f} GB) ✓", "ok")

        # Safety: refuse to write to the boot device. Both sides are reduced
        # to a normalised base-disk name with the SAME helper, so mmcblk/nvme
        # naming cannot slip past (the old digit-stripping was bypassable).
        emit("► Safety check: verifying target is not the boot device…", "cmd")
        boot_src, _, _ = run(["findmnt", "-n", "-o", "SOURCE", "/"])
        boot_base   = _disk_base(boot_src)
        target_base = _disk_base(target_device)
        if not target_base:
            emit(f"ABORTED: could not parse target device {target_device}.", "err")
            done("failed"); return
        if target_base == boot_base:
            emit(f"ABORTED: {target_device} resolves to the boot disk (/dev/{boot_base}). Refusing to overwrite.", "err")
            done("failed"); return
        emit(f"Target /dev/{target_base} is not the boot disk (/dev/{boot_base}) ✓", "ok")

        # Unmount any partitions on target if mounted
        emit("► Checking for mounted partitions on target…", "cmd")
        mounts, _, _ = run(["lsblk", "-n", "-o", "MOUNTPOINT", target_device])
        for mp in mounts.splitlines():
            mp = mp.strip()
            if mp:
                emit(f"Unmounting {mp}…", "warn")
                sudo_run(["umount", mp], merge=True)
        emit("Target is clear ✓", "ok")
        emit("", "info")

        # Choose restore tool
        if Path("/usr/local/sbin/image-restore").exists():
            emit("► Using image-restore (RonR RPi image-utils)…", "cmd")
            cmd = ["sudo", "/usr/local/sbin/image-restore", image_path, target_device]
        else:
            emit("► image-restore not found — using dd…", "warn")
            cmd = ["sudo", "dd", f"if={image_path}", f"of={target_device}",
                   "bs=4M", "status=progress", "conv=fsync"]

        emit(f"$ {' '.join(cmd)}", "cmd")
        emit("", "info")
        emit("⚠ Writing image — DO NOT unplug device or interrupt this process…", "warn")
        emit("", "info")

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                emit(line, "info")
        proc.wait()

        if proc.returncode == 0:
            emit("", "info")
            emit("► Syncing filesystem buffers…", "cmd")
            run(["sync"])
            sync_run = run(["sync"]); _ = sync_run
            emit("✓ Image written and verified successfully!", "ok")
            emit(f"✓ {target_device} is ready — safely remove and use as a standby Pi.", "ok")
            done("success")
        else:
            emit(f"Restore failed — exit code {proc.returncode}", "err")
            done("failed")

    except Exception as e:
        emit(f"Exception: {e}", "err")
        done("failed")

@app.route("/api/restore/run", methods=["POST"])
def api_restore_run():
    if restore_job.running:
        return jsonify({"error": "Restore already running"}), 409
    d = _body()
    image_path    = d.get("imagePath", "").strip()
    target_device = d.get("targetDevice", "").strip()
    confirm       = d.get("confirmDevice", "").strip()
    if not image_path or not target_device:
        return jsonify({"error": "imagePath and targetDevice required"}), 400
    if not _valid_disk(target_device):
        return jsonify({"error": "Target must be a whole block disk, e.g. /dev/sda (not a partition)"}), 400
    if confirm != target_device:
        return jsonify({"error": "Confirmation device does not match target. This destructive write was not confirmed."}), 400
    if not Path(image_path).exists():
        return jsonify({"error": f"Image not found: {image_path}"}), 404
    # Reject the boot disk up-front (the thread re-checks again before writing).
    boot_src, _, _ = run(["findmnt", "-n", "-o", "SOURCE", "/"])
    if _disk_base(target_device) == _disk_base(boot_src):
        return jsonify({"error": "Refusing to restore onto the boot disk."}), 400
    # Reject an image larger than the target — a raw write would be truncated.
    out, _, rc = run(["lsblk", "-b", "-d", "-n", "-o", "SIZE", target_device])
    try:
        target_bytes = int(out.strip()) if rc == 0 else 0
    except ValueError:
        target_bytes = 0
    image_bytes = Path(image_path).stat().st_size
    if target_bytes and image_bytes > target_bytes:
        return jsonify({"error": f"Image ({_human_size(image_bytes)}) is larger than target device "
                                 f"({_human_size(target_bytes)}). Refusing a truncated restore."}), 400
    if not restore_job.start(_run_restore_thread, image_path, target_device):
        return jsonify({"error": "Restore already running"}), 409
    return jsonify({"ok": True})

@app.route("/api/restore/stream")
def api_restore_stream():
    return restore_job.stream()

@app.route("/api/restore/status")
def api_restore_status():
    return jsonify(restore_job.status)

# ─────────────────────────────────────────────────────────────────────────────
# Frontend — single embedded HTML page
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpareCard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--bg2:#111827;--bg3:#1a2234;--bg4:#0d1424;
  --border:#1e2d4a;--accent:#3b82f6;--cyan:#06b6d4;
  --green:#10b981;--red:#ef4444;--orange:#f59e0b;--purple:#8b5cf6;
  --text:#c8d0e8;--muted:#4b5a78;--bright:#e8eeff;
}
html,body{min-height:100vh;background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:14px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
select option{background:var(--bg3)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}

/* Layout */
.hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 32px}
.hdr-inner{max-width:1160px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;height:64px}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,#3b82f6,#06b6d4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.logo-title{font-family:'Syne',sans-serif;font-weight:800;font-size:16px;color:var(--bright)}
.logo-sub{font-size:11px;color:var(--muted)}
.hdr-meta{display:flex;align-items:center;gap:16px}

.tabbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 32px}
.tabbar-inner{max-width:1160px;margin:0 auto;display:flex;gap:4px;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}.tabbar-inner::-webkit-scrollbar{display:none}
.tab-btn{padding:14px 20px;background:transparent;border:none;border-bottom:2px solid transparent;color:var(--muted);font-size:13px;font-weight:600;font-family:'JetBrains Mono',monospace;cursor:pointer;display:flex;align-items:center;gap:7px;transition:color .15s;letter-spacing:.02em;white-space:nowrap}
.tab-btn.active{border-bottom-color:var(--accent);color:var(--accent)}
.tab-btn:hover:not(.active){color:var(--text)}

.content{max-width:1160px;margin:0 auto;padding:28px 32px}
.pane{display:none;animation:fadeIn .25s ease}.pane.active{display:block}

/* Cards */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.card-title{display:flex;align-items:center;gap:10px;font-family:'Syne',sans-serif;font-weight:700;font-size:15px;color:var(--bright);letter-spacing:.02em}
.card-title .icon{font-size:17px}

/* Form */
.field{margin-bottom:16px}
.lbl{font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px}
.hint{font-size:11px;color:var(--muted);margin-top:5px;line-height:1.5}
input[type=text],input[type=password],input[type=number],select,textarea{
  width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:10px 14px;color:var(--text);font-size:13px;font-family:'JetBrains Mono',monospace;
  outline:none;transition:border-color .15s}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;line-height:1.6}
.input-wrap{position:relative;display:flex;align-items:center}
.input-prefix{position:absolute;left:12px;font-size:12px;color:var(--muted);pointer-events:none;z-index:1}
.input-wrap input{padding-left:28px}

/* Toggle */
.toggle{width:40px;height:22px;border-radius:11px;cursor:pointer;position:relative;transition:all .2s;flex-shrink:0;user-select:none}
.toggle.on{background:var(--accent);border:1px solid var(--accent)}
.toggle.off{background:#1e2d4a;border:1px solid #2a3a5a}
.toggle-k{position:absolute;top:2px;width:16px;height:16px;border-radius:50%;transition:left .2s}
.toggle.on .toggle-k{left:18px;background:#fff}
.toggle.off .toggle-k{left:2px;background:var(--muted)}

/* Buttons */
.btn{padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;font-family:'JetBrains Mono',monospace;cursor:pointer;border:1px solid;transition:opacity .15s;letter-spacing:.02em;white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.sm{padding:6px 12px;font-size:11px}
.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn.secondary{background:transparent;color:var(--text);border-color:var(--border)}
.btn.success{background:rgba(16,185,129,.12);color:var(--green);border-color:var(--green)}
.btn.danger{background:rgba(239,68,68,.12);color:var(--red);border-color:var(--red)}
.btn.ghost{background:transparent;color:var(--muted);border-color:transparent}
.btn.cyan{background:rgba(6,182,212,.12);color:var(--cyan);border-color:var(--cyan)}
.spinner{width:12px;height:12px;border:2px solid currentColor;border-top-color:transparent;border-radius:50%;animation:spin .7s linear infinite;display:inline-block;flex-shrink:0}

/* Badge */
.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.05em;border:1px solid;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
/* status dots render a glyph, so state is conveyed by shape as well as colour
   (colourblind / screen-magnifier friendly; matches the ✓/✗/⚠ used in logs) */
.badge .dot{width:auto;height:auto;border-radius:0;background:none!important;line-height:1}
.badge.green .dot::before{content:"✓"}
.badge.red .dot::before{content:"✗"}
.badge.orange .dot::before{content:"⚠"}
.badge.blue .dot::before{content:"ℹ"}
.badge.muted .dot::before{content:"·"}
.badge.green{background:rgba(16,185,129,.14);border-color:var(--green);color:var(--green)}
.badge.green .dot{background:var(--green)}
.badge.red{background:rgba(239,68,68,.14);border-color:var(--red);color:var(--red)}
.badge.red .dot{background:var(--red)}
.badge.blue{background:rgba(59,130,246,.14);border-color:var(--accent);color:var(--accent)}
.badge.blue .dot{background:var(--accent)}
.badge.orange{background:rgba(245,158,11,.14);border-color:var(--orange);color:var(--orange)}
.badge.orange .dot{background:var(--orange)}
.badge.muted{background:rgba(75,90,120,.2);border-color:var(--muted);color:var(--muted)}
.badge.muted .dot{background:var(--muted)}

/* Info boxes */
.info{padding:12px 14px;border-radius:8px;font-size:12px;line-height:1.7;border:1px solid}
.info.blue{background:rgba(59,130,246,.07);border-color:rgba(59,130,246,.25);color:var(--accent)}
.info.green{background:rgba(16,185,129,.07);border-color:rgba(16,185,129,.25);color:var(--green)}
.info.orange{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.25);color:var(--orange)}
.info.red{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.25);color:var(--red)}
.info.cyan{background:rgba(6,182,212,.07);border-color:rgba(6,182,212,.25);color:var(--cyan)}

/* Grid helpers */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.row{display:flex;align-items:center;gap:10px}
.divider{border:none;border-top:1px solid var(--border);margin:20px 0}

/* Status dot */
.sdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sdot.green{background:var(--green);box-shadow:0 0 6px var(--green)}
.sdot.red{background:var(--red);box-shadow:0 0 6px var(--red)}
.sdot.orange{background:var(--orange);box-shadow:0 0 6px var(--orange)}

/* Dest picker */
.dest-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}
.dest-card{background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:14px 10px;cursor:pointer;text-align:center;transition:all .15s}
.dest-card:hover{border-color:var(--accent)}
.dest-card .d-icon{font-size:24px;margin-bottom:6px}
.dest-card .d-label{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.04em}

/* Step circles */
.step-circle{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}

/* Sub-panels */
.sub-panel{background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:12px}

/* Target list */
.target-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;margin-bottom:6px;cursor:pointer;border:1px solid var(--border);background:var(--bg);transition:all .15s}
.target-item.active{background:rgba(59,130,246,.1);border-color:var(--accent)}
.radio-outer{width:14px;height:14px;border-radius:50%;border:2px solid var(--muted);display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:border-color .15s}
.target-item.active .radio-outer{border-color:var(--accent)}
.radio-inner{width:6px;height:6px;border-radius:50%;background:var(--accent);display:none}
.target-item.active .radio-inner{display:block}

/* Container table */
.ct-head,.ct-row{display:grid;grid-template-columns:1fr 95px 70px 80px 130px 80px;gap:0;padding:10px 16px;align-items:center}
.ct-head{background:var(--bg4);border-radius:8px 8px 0 0;border:1px solid var(--border);border-bottom:none}
.ct-head span{font-size:10px;font-weight:700;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}
.ct-body{border:1px solid var(--border);border-radius:0 0 8px 8px;overflow:hidden}
.ct-row{border-bottom:1px solid var(--border)}
.ct-row:last-child{border-bottom:none}
.ct-row:nth-child(even){background:rgba(255,255,255,.012)}
.ct-name{font-size:12px;color:var(--bright);font-weight:500;word-break:break-all}
.ct-img{font-size:10px;color:var(--muted);margin-top:2px;word-break:break-all}
.pri-select{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:5px 8px;font-size:11px;font-family:'JetBrains Mono',monospace;outline:none;cursor:pointer;width:100%;color:var(--text)}

/* Day picker */
.day-btn{width:48px;height:48px;border-radius:8px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-weight:700;font-size:12px;transition:all .15s;border:1px solid;user-select:none;font-family:'JetBrains Mono',monospace}
.day-btn.on{background:rgba(59,130,246,.18);border-color:var(--accent);color:var(--accent)}
.day-btn.off{background:var(--bg3);border-color:var(--border);color:var(--muted)}

/* Terminal log */
.term-box{background:var(--bg4);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.7}
.term-line{display:flex;gap:8px;padding:1px 0}
.term-prefix{flex-shrink:0;width:10px}
.t-cmd{color:#a5b4fc}.t-ok{color:var(--green)}.t-err{color:var(--red)}.t-warn{color:var(--orange)}.t-info{color:var(--text)}

/* Code output */
.code-out{background:var(--bg4);border:1px solid var(--border);border-radius:8px;padding:16px;max-height:440px;overflow-y:auto}
.code-out pre{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#7dd3fc;line-height:1.7;white-space:pre-wrap;word-break:break-word}

/* Run progress bar */
.phase-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
.phase-item{display:flex;flex-direction:column;align-items:center;gap:4px}
.phase-track{width:100%;height:3px;border-radius:2px;background:var(--border);transition:background .4s}
.phase-label{font-size:10px;letter-spacing:.05em;color:var(--muted);font-weight:600;transition:color .4s}

/* Toast */
#toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:10px;font-size:13px;font-weight:600;z-index:999;opacity:0;transition:opacity .3s;pointer-events:none;border:1px solid}
#toast.show{opacity:1}
#toast.ok{background:rgba(16,185,129,.15);border-color:var(--green);color:var(--green)}
#toast.err{background:rgba(239,68,68,.15);border-color:var(--red);color:var(--red)}

@media(max-width:640px){
  .hdr{padding:0 12px}
  .hdr-inner{height:52px}
  .tabbar{padding:0 12px}
  .content{padding:16px 12px}
  .card{padding:16px}
  .g2,.g3{grid-template-columns:1fr}
  .dest-grid{grid-template-columns:repeat(3,1fr)}
  .ct-head{display:none}
  .ct-row{grid-template-columns:1fr 1fr;gap:4px;padding:10px 12px}
  .phase-bar{grid-template-columns:repeat(2,1fr)}
  .cl-row-wrap{flex-wrap:wrap}
  .g-stack{grid-template-columns:1fr!important}
  .target-item{flex-wrap:wrap}
  .term-box{overflow-x:auto}
}
@media(max-width:420px){
  .dest-grid{grid-template-columns:repeat(2,1fr)}
  .day-btn{width:40px;height:40px}
  .ct-row{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div id="app">

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-inner">
    <div class="logo">
      <div class="logo-icon">💾</div>
      <div>
        <div class="logo-title">SpareCard</div>
        <div class="logo-sub" id="hdr-sub">Raspberry Pi image backup</div>
      </div>
    </div>
    <div class="hdr-meta">
      <div class="row"><div class="sdot orange" id="docker-dot"></div><span style="font-size:11px;color:var(--muted)" id="docker-lbl">Checking…</span></div>
      <div class="row"><div class="sdot green" id="run-dot"></div><span style="font-size:11px;color:var(--muted)" id="run-lbl">— containers</span></div>
      <span class="badge muted" id="last-backup-badge" title="Click for details" style="cursor:pointer" onclick="showLastBackupModal()"><span class="dot"></span><span id="last-backup-txt">—</span></span>
      <button class="btn secondary sm" onclick="showChangePwModal()" title="Change Password" style="padding:5px 11px;font-size:11px">🔑 Password</button>
      <span class="badge blue" id="dest-badge" style="display:none"></span>
    </div>
  </div>
</div>

<!-- TABBAR -->
<div class="tabbar">
  <div class="tabbar-inner">
    <button class="tab-btn" data-tab="dashboard">📊 Dashboard</button>
    <button class="tab-btn active" data-tab="destination">🗄️ Destination</button>
    <button class="tab-btn" data-tab="containers">🐳 Containers</button>
    <button class="tab-btn" data-tab="schedule">📅 Schedule</button>
    <button class="tab-btn" data-tab="generate">⚡ Generate</button>
    <button class="tab-btn" data-tab="restore" style="color:var(--red)">⏪ Restore</button>
  </div>
</div>

<!-- CONTENT -->
<div class="content">

<!-- ═══════════════════════ DASHBOARD TAB ═══════════════════════ -->
<div class="pane" id="tab-dashboard">

  <!-- Row 1: Last Backup + Mount -->
  <div class="g2">
    <!-- Last Backup -->
    <div class="card" style="margin-bottom:0">
      <div class="card-hdr" style="margin-bottom:14px">
        <div class="card-title"><span class="icon">💾</span> Last Backup</div>
        <span id="db-backup-badge" class="badge muted"><span class="dot"></span><span id="db-backup-badge-txt">—</span></span>
      </div>
      <div style="font-size:13px;display:flex;flex-direction:column;gap:8px">
        <div class="row" style="gap:10px">
          <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Started</span>
          <span id="db-started">—</span>
        </div>
        <div class="row" style="gap:10px">
          <span id="db-finished-lbl" style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Finished</span>
          <span id="db-finished">—</span>
        </div>
        <div class="row" style="gap:10px">
          <span id="db-elapsed-lbl" style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Duration</span>
          <span id="db-elapsed">—</span>
        </div>
        <div class="row" style="gap:10px">
          <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Mode</span>
          <span id="db-mode">—</span>
        </div>
      </div>
      <div id="db-log-wrap" style="display:none;margin-top:14px">
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px;font-weight:600;letter-spacing:.06em;text-transform:uppercase">Last log lines</div>
        <div class="term-box" id="db-log" style="max-height:160px;overflow-y:auto;font-size:11px"></div>
      </div>
    </div>

    <!-- Mount + Image -->
    <div style="display:flex;flex-direction:column;gap:20px">
      <div class="card" style="margin-bottom:0">
        <div class="card-hdr" style="margin-bottom:14px">
          <div class="card-title"><span class="icon">💿</span> Mount</div>
          <span id="db-mount-badge" class="badge muted"><span class="dot"></span><span id="db-mount-badge-txt">—</span></span>
        </div>
        <div style="font-size:13px;display:flex;flex-direction:column;gap:7px">
          <div class="row" style="gap:10px">
            <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Source</span>
            <code id="db-mount-src" style="font-size:12px;word-break:break-all">—</code>
          </div>
          <div class="row" style="gap:10px">
            <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">FS Type</span>
            <span id="db-mount-fs">—</span>
          </div>
        </div>
      </div>

      <div class="card" style="margin-bottom:0">
        <div class="card-hdr" style="margin-bottom:14px">
          <div class="card-title"><span class="icon">🗂️</span> Image</div>
          <span id="db-image-badge" class="badge muted"><span class="dot"></span><span id="db-image-badge-txt">—</span></span>
        </div>
        <div style="font-size:13px;display:flex;flex-direction:column;gap:7px">
          <div class="row" style="gap:10px">
            <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Logical</span>
            <span id="db-img-logical">—</span>
          </div>
          <div class="row" style="gap:10px">
            <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">On disk</span>
            <span id="db-img-sparse">—</span>
          </div>
          <div class="row" style="gap:10px">
            <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Sentinel</span>
            <span id="db-sentinel">—</span>
          </div>
          <div id="db-compact-warn" style="display:none;margin-top:4px" class="info orange">⚠️ Compaction recommended — significant sparse space reclaimed.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Row 2: Schedule + State pills -->
  <div class="g2" style="margin-top:20px">
    <div class="card" style="margin-bottom:0">
      <div class="card-hdr" style="margin-bottom:14px">
        <div class="card-title"><span class="icon">📅</span> Schedule</div>
        <span id="db-cron-badge" class="badge muted"><span class="dot"></span><span id="db-cron-badge-txt">—</span></span>
      </div>
      <div style="font-size:13px;display:flex;flex-direction:column;gap:7px">
        <div class="row" style="gap:10px">
          <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Cron</span>
          <code id="db-cron-expr" style="font-size:12px">—</code>
        </div>
        <div class="row" style="gap:10px">
          <span style="color:var(--muted);min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.07em">Next run</span>
          <span id="db-cron-next">—</span>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:0">
      <div class="card-hdr" style="margin-bottom:14px">
        <div class="card-title"><span class="icon">⚙️</span> State</div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;font-size:12px">
        <span id="db-pill-running"  class="badge muted">Backup idle</span>
        <span id="db-pill-lock"     class="badge muted">No lock</span>
        <span id="db-pill-sentinel" class="badge muted">No sentinel</span>
      </div>
    </div>
  </div>

  <!-- Refresh -->
  <div style="margin-top:20px;display:flex;align-items:center;gap:12px">
    <button class="btn secondary sm" onclick="loadDashboard()">🔄 Refresh</button>
    <span id="db-refresh-ts" style="font-size:11px;color:var(--muted)"></span>
  </div>

</div>

<!-- ═══════════════════════ DESTINATION TAB ═══════════════════════ -->
<div class="pane active" id="tab-destination">
  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🗄️</span> Backup Destination</div>
    </div>
    <div class="dest-grid">
      <div class="dest-card" data-dest="iscsi" style="border-color:var(--accent);background:rgba(59,130,246,.1)">
        <div class="d-icon">🔌</div><div class="d-label" style="color:var(--accent)">iSCSI</div>
        <div id="iscsi-card-dot" style="display:none;width:7px;height:7px;border-radius:50%;background:var(--green);margin:5px auto 0;box-shadow:0 0 5px var(--green)"></div>
      </div>
      <div class="dest-card" data-dest="smb"><div class="d-icon">🌐</div><div class="d-label">SMB / CIFS</div>
        <div id="smb-card-dot" style="display:none;width:7px;height:7px;border-radius:50%;background:var(--green);margin:5px auto 0;box-shadow:0 0 5px var(--green)"></div>
      </div>
      <div class="dest-card" data-dest="nfs"><div class="d-icon">📡</div><div class="d-label">NFS</div>
        <div id="nfs-card-dot" style="display:none;width:7px;height:7px;border-radius:50%;background:var(--green);margin:5px auto 0;box-shadow:0 0 5px var(--green)"></div>
      </div>
      <div class="dest-card" data-dest="usb"><div class="d-icon">💾</div><div class="d-label">External HDD</div>
        <div id="usb-card-dot" style="display:none;width:7px;height:7px;border-radius:50%;background:var(--green);margin:5px auto 0;box-shadow:0 0 5px var(--green)"></div>
      </div>
      <div class="dest-card" data-dest="local"><div class="d-icon">📂</div><div class="d-label">Local Path</div></div>
    </div>

    <hr class="divider">

    <!-- Shared fields -->
    <div class="g2" style="margin-bottom:20px">
      <div class="field"><div class="lbl">Image Filename</div><input type="text" id="imageName" placeholder="pi_backup.img" oninput="updatePreviews()"></div>
      <div class="field"><div class="lbl">Mount Point</div><input type="text" id="mountPoint" value="/mnt/backups" oninput="updatePreviews()"></div>
    </div>

    <!-- iSCSI panel -->
    <div id="panel-iscsi" class="dest-panel" style="animation:fadeIn .3s ease">
      <div id="dep-banner-iscsi" style="display:none;padding:12px 16px;border-radius:8px;border:1px solid rgba(245,158,11,.35);background:rgba(245,158,11,.07);margin-bottom:12px"></div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px"><div class="step-circle" style="background:rgba(59,130,246,.2);border:1px solid var(--accent);color:var(--accent)">1</div><strong style="color:var(--bright);font-size:13px">Discover iSCSI Targets</strong></div>
        <div class="g-stack" style="display:grid;grid-template-columns:1fr 80px auto;gap:10px;align-items:end">
          <div class="field" style="margin:0"><div class="lbl">Portal IP</div><input type="text" id="iscsiPortal" placeholder="192.168.1.100" oninput="scheduleDiscover()"></div>
          <div class="field" style="margin:0"><div class="lbl">Port</div><input type="text" id="iscsiPort" value="3260" style="width:80px"></div>
          <button class="btn cyan" onclick="iscsiDiscover()"><span id="disc-sp" class="spinner" style="display:none"></span>🔍 Discover</button>
        </div>
        <div id="disc-log" class="term-box" style="margin-top:10px;display:none"></div>
        <div id="disc-targets" style="margin-top:12px;display:none">
          <div class="lbl" style="margin-bottom:8px">Discovered Targets</div>
          <div id="targets-list"></div>
        </div>
      </div>
      <div class="sub-panel" id="iscsi-step2" style="opacity:.4;transition:opacity .2s">
        <div class="row" style="margin-bottom:14px"><div class="step-circle" style="background:rgba(59,130,246,.2);border:1px solid var(--accent);color:var(--accent)">2</div><strong style="color:var(--bright);font-size:13px">Login to Target</strong></div>
        <div class="field"><div class="lbl">Selected IQN</div><input type="text" id="iscsiIQN" placeholder="iqn.2020-01.com.example:target"></div>
        <button class="btn primary" onclick="iscsiLogin()"><span id="login-sp" class="spinner" style="display:none"></span>🔑 Login</button>
        <div id="login-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
      <div class="sub-panel" id="iscsi-step3" style="opacity:.4;transition:opacity .2s">
        <div class="row" style="margin-bottom:14px;justify-content:space-between">
          <div class="row"><div class="step-circle" style="background:rgba(59,130,246,.2);border:1px solid var(--accent);color:var(--accent)">3</div><strong style="color:var(--bright);font-size:13px">Mount Volume</strong></div>
          <span id="iscsi-mnt-pill" class="badge muted"><span class="dot"></span>Not Mounted</span>
        </div>
        <div class="g2" style="margin-bottom:12px">
          <div class="field" style="margin:0"><div class="lbl">Block Device</div><input type="text" id="iscsiDevice" placeholder="/dev/sdb1"></div>
          <div class="field" style="margin:0"><div class="lbl">Mount Point</div><input type="text" id="iscsiMountPoint" value="/mnt/backups" oninput="syncMountPoints(this)"></div>
        </div>
        <div id="iscsi-mount-banner" style="display:none;margin-bottom:10px"></div>
        <div id="iscsi-image-banner" style="display:none;margin-bottom:10px"></div>
        <div id="iscsi-session-banner" style="display:none;margin-bottom:10px"></div>
        <div class="row">
          <button class="btn success" id="iscsi-mnt-btn" onclick="doMount('iscsi')"><span id="iscsi-mnt-sp" class="spinner" style="display:none"></span>⬆ Mount</button>
          <div class="row" style="gap:7px;margin-left:4px">
            <div class="toggle off" id="iscsi-fstab-tog" onclick="toggleFstab('iscsi')" title="Mount automatically on boot"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)">Mount on boot</span>
          </div>
          <div class="row" style="gap:7px;margin-left:8px;padding-left:8px;border-left:1px solid var(--border)">
            <div class="toggle off" id="iscsi-secondary-tog" onclick="toggleSecondaryDest('iscsi')" title="Also backup to this destination"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)" id="iscsi-secondary-lbl">Also back up here</span>
          </div>
        </div>
        <div id="iscsi-mnt-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
    </div>

    <!-- SMB panel -->
    <div id="panel-smb" class="dest-panel" style="display:none;animation:fadeIn .3s ease">
      <div id="dep-banner-smb" style="display:none;padding:12px 16px;border-radius:8px;border:1px solid rgba(245,158,11,.35);background:rgba(245,158,11,.07);margin-bottom:12px"></div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px"><div class="step-circle" style="background:rgba(6,182,212,.2);border:1px solid var(--cyan);color:var(--cyan)">1</div><strong style="color:var(--bright);font-size:13px">Server &amp; Credentials</strong></div>
        <div class="g2">
          <div class="field"><div class="lbl">Server Address</div><input type="text" id="smbServer" placeholder="192.168.1.50 or nas.local"></div>
          <div class="field"><div class="lbl">Share Name</div><div class="input-wrap"><span class="input-prefix">/</span><input type="text" id="smbShare" placeholder="backups"></div></div>
          <div class="field"><div class="lbl">Username</div><input type="text" id="smbUser" placeholder="backup_user"></div>
          <div class="field"><div class="lbl">Password</div><input type="password" id="smbPass" placeholder="••••••••"><div class="hint" style="color:var(--orange)">⚠ Password is not saved to config — re-enter after each page reload.</div></div>
          <div class="field"><div class="lbl">Domain / Workgroup</div><input type="text" id="smbDomain" value="WORKGROUP"></div>
          <div class="field"><div class="lbl">SMB Version</div>
            <select id="smbVersion"><option value="3.0" selected>SMB 3.0 (recommended)</option><option value="3.1.1">SMB 3.1.1</option><option value="2.1">SMB 2.1</option><option value="2.0">SMB 2.0</option><option value="1.0">SMB 1.0 (legacy)</option></select>
          </div>
        </div>
        <button class="btn cyan" onclick="smbTest()"><span id="smb-test-sp" class="spinner" style="display:none"></span>📡 Test Connection</button>
        <div id="smb-test-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px;justify-content:space-between">
          <div class="row"><div class="step-circle" style="background:rgba(6,182,212,.2);border:1px solid var(--cyan);color:var(--cyan)">2</div><strong style="color:var(--bright);font-size:13px">Mount Options</strong></div>
          <span id="smb-mnt-pill" class="badge muted"><span class="dot"></span>Not Mounted</span>
        </div>
        <div class="g2" style="margin-bottom:12px">
          <div class="field" style="margin:0"><div class="lbl">Mount Point</div><input type="text" id="smbMountPoint" value="/mnt/backups" oninput="syncMountPoints(this)"></div>
          <div class="field" style="margin:0"><div class="lbl">Extra Options</div><input type="text" id="smbExtraOpts" placeholder="uid=1000,gid=1000"></div>
        </div>
        <div id="smb-mount-banner" style="display:none;margin-bottom:10px"></div>
        <div id="smb-image-banner" style="display:none;margin-bottom:10px"></div>
        <div class="row">
          <button class="btn success" id="smb-mnt-btn" onclick="doMount('smb')"><span id="smb-mnt-sp" class="spinner" style="display:none"></span>⬆ Mount</button>
          <div class="row" style="gap:7px;margin-left:4px">
            <div class="toggle off" id="smb-fstab-tog" onclick="toggleFstab('smb')" title="Mount automatically on boot"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)">Mount on boot</span>
          </div>
          <div class="row" style="gap:7px;margin-left:8px;padding-left:8px;border-left:1px solid var(--border)">
            <div class="toggle off" id="smb-secondary-tog" onclick="toggleSecondaryDest('smb')" title="Also backup to this destination"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)" id="smb-secondary-lbl">Also back up here</span>
          </div>
          <button class="btn ghost" style="font-size:11px" onclick="saveCredentials()">🔒 Save credentials</button>
        </div>
        <div id="smb-mnt-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
    </div>

    <!-- NFS panel -->
    <div id="panel-nfs" class="dest-panel" style="display:none;animation:fadeIn .3s ease">
      <div id="dep-banner-nfs" style="display:none;padding:12px 16px;border-radius:8px;border:1px solid rgba(245,158,11,.35);background:rgba(245,158,11,.07);margin-bottom:12px"></div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px"><div class="step-circle" style="background:rgba(139,92,246,.2);border:1px solid var(--purple);color:var(--purple)">1</div><strong style="color:var(--bright);font-size:13px">NFS Server</strong></div>
        <div class="g-stack" style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:end">
          <div class="field" style="margin:0"><div class="lbl">Server IP / Hostname</div><input type="text" id="nfsServer" placeholder="192.168.1.50" onblur="nfsScan()"></div>
          <button class="btn cyan" onclick="nfsScan()"><span id="nfs-scan-sp" class="spinner" style="display:none"></span>🔍 Scan Exports</button>
        </div>
        <div id="nfs-exports" style="margin-top:12px;display:none"></div>
        <div id="nfs-scan-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px;justify-content:space-between">
          <div class="row"><div class="step-circle" style="background:rgba(139,92,246,.2);border:1px solid var(--purple);color:var(--purple)">2</div><strong style="color:var(--bright);font-size:13px">Mount</strong></div>
          <span id="nfs-mnt-pill" class="badge muted"><span class="dot"></span>Not Mounted</span>
        </div>
        <div class="g2" style="margin-bottom:12px">
          <div class="field" style="margin:0"><div class="lbl">Export Path</div><input type="text" id="nfsExport" placeholder="/volume1/backups"></div>
          <div class="field" style="margin:0"><div class="lbl">Mount Point</div><input type="text" id="nfsMountPoint" value="/mnt/backups" oninput="syncMountPoints(this)"></div>
          <div class="field" style="margin:0"><div class="lbl">Mount Options</div>
            <select id="nfsMountOpts"><option value="vers=4,rw,sync" selected>NFSv4, rw, sync (recommended)</option><option value="vers=4,rw,async">NFSv4, rw, async</option><option value="vers=3,rw,sync">NFSv3, rw, sync</option><option value="vers=4,ro">NFSv4, read-only</option></select>
          </div>
          <div class="field" style="margin:0"><div class="lbl">Custom Options</div><input type="text" id="nfsCustomOpts" placeholder="timeo=14,retrans=2"></div>
        </div>
        <div id="nfs-mount-banner" style="display:none;margin-bottom:10px"></div>
        <div id="nfs-image-banner" style="display:none;margin-bottom:10px"></div>
        <div class="row">
          <button class="btn success" id="nfs-mnt-btn" onclick="doMount('nfs')"><span id="nfs-mnt-sp" class="spinner" style="display:none"></span>⬆ Mount</button>
          <div class="row" style="gap:7px;margin-left:4px">
            <div class="toggle off" id="nfs-fstab-tog" onclick="toggleFstab('nfs')" title="Mount automatically on boot"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)">Mount on boot</span>
          </div>
          <div class="row" style="gap:7px;margin-left:8px;padding-left:8px;border-left:1px solid var(--border)">
            <div class="toggle off" id="nfs-secondary-tog" onclick="toggleSecondaryDest('nfs')" title="Also backup to this destination"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)" id="nfs-secondary-lbl">Also back up here</span>
          </div>
        </div>
        <div id="nfs-mnt-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
    </div>

    <!-- USB panel -->
    <div id="panel-usb" class="dest-panel" style="display:none;animation:fadeIn .3s ease">
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px;justify-content:space-between">
          <div class="row"><div class="step-circle" style="background:rgba(245,158,11,.2);border:1px solid var(--orange);color:var(--orange)">1</div><strong style="color:var(--bright);font-size:13px">Detect Block Devices</strong></div>
          <button class="btn cyan sm" onclick="usbScan()"><span id="usb-scan-sp" class="spinner" style="display:none"></span>🔍 Scan Devices</button>
        </div>
        <div id="usb-empty" style="text-align:center;padding:20px 0;color:var(--muted);font-size:12px">Click Scan Devices to detect connected USB drives</div>
        <div id="usb-list"></div>
        <div id="usb-scan-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
      <div class="sub-panel">
        <div class="row" style="margin-bottom:14px;justify-content:space-between">
          <div class="row"><div class="step-circle" style="background:rgba(245,158,11,.2);border:1px solid var(--orange);color:var(--orange)">2</div><strong style="color:var(--bright);font-size:13px">Mount</strong></div>
          <span id="usb-mnt-pill" class="badge muted"><span class="dot"></span>Not Mounted</span>
        </div>
        <div class="g3" style="margin-bottom:12px">
          <div class="field" style="margin:0"><div class="lbl">Device</div><input type="text" id="usbDevice" placeholder="/dev/sda1"></div>
          <div class="field" style="margin:0"><div class="lbl">Filesystem</div>
            <select id="usbFsType"><option value="ext4" selected>ext4</option><option value="exfat">exFAT</option><option value="ntfs">NTFS</option><option value="btrfs">btrfs</option><option value="xfs">xfs</option><option value="fat32">FAT32</option></select>
          </div>
          <div class="field" style="margin:0"><div class="lbl">Mount Point</div><input type="text" id="usbMountPoint" value="/mnt/backups" oninput="syncMountPoints(this)"></div>
        </div>
        <div id="usb-mount-banner" style="display:none;margin-bottom:10px"></div>
        <div id="usb-image-banner" style="display:none;margin-bottom:10px"></div>
        <div class="row">
          <button class="btn success" id="usb-mnt-btn" onclick="doMount('usb')"><span id="usb-mnt-sp" class="spinner" style="display:none"></span>⬆ Mount</button>
          <div class="row" style="gap:7px;margin-left:4px">
            <div class="toggle off" id="usb-fstab-tog" onclick="toggleFstab('usb')" title="Mount automatically on boot"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)">Mount on boot</span>
          </div>
          <div class="row" style="gap:7px;margin-left:8px;padding-left:8px;border-left:1px solid var(--border)">
            <div class="toggle off" id="usb-secondary-tog" onclick="toggleSecondaryDest('usb')" title="Also backup to this destination"><div class="toggle-k"></div></div>
            <span style="font-size:11px;color:var(--muted)" id="usb-secondary-lbl">Also back up here</span>
          </div>
        </div>
        <div id="usb-mnt-log" class="term-box" style="margin-top:10px;display:none"></div>
      </div>
    </div>

    <!-- Local panel -->
    <div id="panel-local" class="dest-panel" style="display:none;animation:fadeIn .3s ease">
      <div class="sub-panel">
        <div class="field"><div class="lbl">Backup Directory Path</div>
          <div class="row"><input type="text" id="localPath" placeholder="/media/backup_drive" oninput="document.getElementById('mountPoint').value=this.value;updatePreviews()">
            <button class="btn cyan sm" onclick="localVerify()"><span id="local-sp" class="spinner" style="display:none"></span>Verify</button>
          </div>
          <div class="hint">Must be an accessible, writable path</div>
        </div>
        <div id="local-result" style="display:none"></div>
      </div>
    </div>
  </div>


  <!-- Notifications -->
  <div class="card">
    <div class="card-hdr"><div class="card-title"><span class="icon">🔔</span> Notifications</div></div>
    <div class="g2">
      <div>
        <div class="row" style="margin-bottom:16px">
          <div class="toggle off" id="toggle-ntfyEnabled" data-key="ntfyEnabled" onclick="toggleClick(this)"><div class="toggle-k"></div></div>
          <span>Enable ntfy.sh notifications</span>
        </div>
        <div id="ntfy-fields">
          <div class="field"><div class="lbl">ntfy Topic</div><input type="text" id="ntfyTopic" placeholder="your-ntfy-topic"></div>
          <div class="field"><div class="lbl">ntfy Server</div><input type="text" id="ntfyServer" value="https://ntfy.sh"></div>
        </div>
      </div>
      <div>
        <div class="lbl" style="margin-bottom:12px">Notify On</div>
        <div class="row" style="margin-bottom:12px"><div class="toggle on" id="toggle-notifySuccess" data-key="notifySuccess" onclick="toggleClick(this)"><div class="toggle-k"></div></div><span>✅ Success</span></div>
        <div class="row" style="margin-bottom:12px"><div class="toggle on" id="toggle-notifyFailure" data-key="notifyFailure" onclick="toggleClick(this)"><div class="toggle-k"></div></div><span>❌ Failure / Error</span></div>
        <div class="row"><div class="toggle off" id="toggle-notifyStart" data-key="notifyStart" onclick="toggleClick(this)"><div class="toggle-k"></div></div><span>⏳ Backup Start</span></div>
      </div>
    </div>
  </div>
  <button class="btn primary" onclick="saveConfig()">💾 Save Configuration</button>
</div>

<!-- ═══════════════════════ CONTAINERS TAB ═══════════════════════ -->
<div class="pane" id="tab-containers">
  <div class="card">
    <div class="card-hdr"><div class="card-title"><span class="icon">⚙️</span> Shutdown Behaviour</div></div>
    <div class="g2">
      <div>
        <div class="field"><div class="lbl">Primary Shutdown Method</div>
          <select id="shutdownMethod"><option value="runtipi" selected>Runtipi CLI (graceful)</option><option value="compose">Docker Compose down</option><option value="docker">docker stop (all)</option><option value="manual">Manual order only</option></select>
        </div>
        <div class="field"><div class="lbl">Fallback If Primary Fails</div>
          <select id="shutdownFallback"><option value="force" selected>Force stop remaining</option><option value="abort">Abort backup</option><option value="proceed">Proceed anyway (risky)</option></select>
        </div>
      </div>
      <div>
        <div class="field"><div class="lbl">Grace Period (seconds)</div><input type="number" id="gracePeriod" value="30"><div class="hint">Wait before force-stopping</div></div>
        <div class="field"><div class="lbl">Post-Shutdown Settle (seconds)</div><input type="number" id="settleTime" value="3"></div>
        <div class="field"><div class="lbl">Health Check Timeout (seconds)</div><input type="number" id="healthTimeout" value="120"></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🐳</span> Detected Containers</div>
      <div class="row" style="flex-wrap:wrap;gap:6px">
        <button class="btn sm primary" id="filter-all" onclick="setCtFilter('all')">All</button>
        <button class="btn sm ghost" id="filter-running" onclick="setCtFilter('running')">Running</button>
        <button class="btn sm ghost" id="filter-exited" onclick="setCtFilter('exited')">Stopped</button>
        <button class="btn sm ghost" onclick="selectAllContainers(true)" title="Set all to stop + restart">☑ All</button>
        <button class="btn sm ghost" onclick="selectAllContainers(false)" title="Clear all stop + restart">☐ None</button>
        <button class="btn sm secondary" onclick="loadContainers()"><span id="ct-refresh-sp" class="spinner" style="display:none"></span>🔄 Refresh</button>
      </div>
    </div>
    <div id="ct-loading" class="row" style="padding:20px 0;justify-content:center">
      <div class="spinner"></div><span style="color:var(--muted);font-size:13px;margin-left:10px">Loading containers…</span>
    </div>
    <div id="ct-error" class="info red" style="display:none"></div>
    <div id="ct-wrap" style="display:none">
      <div class="ct-head">
        <span>Container / Image</span><span>Status</span><span>Stop</span><span>Restart</span><span>Priority</span><span>Uptime</span>
      </div>
      <div class="ct-body" id="ct-body"></div>
      <div class="info orange" style="margin-top:12px">⚠️ <strong>Foundation</strong> containers (DBs, VPN) start first with a settle delay before network-dependent apps restart.</div>
    </div>
  </div>
  <button class="btn primary" onclick="saveConfig()">💾 Save Configuration</button>
</div>

<!-- ═══════════════════════ SCHEDULE TAB ═══════════════════════ -->
<div class="pane" id="tab-schedule">
  <div class="card">
    <div class="card-hdr"><div class="card-title"><span class="icon">📅</span> Schedule Configuration</div></div>
    <div class="row" style="margin-bottom:20px">
      <button class="btn primary sm" id="mode-builder" onclick="setCronMode('builder')">🛠️ Visual Builder</button>
      <button class="btn secondary sm" id="mode-custom" onclick="setCronMode('custom')">✏️ Raw Cron</button>
    </div>
    <div id="cron-builder">
      <div class="g3">
        <div class="field"><div class="lbl">Frequency</div>
          <select id="cronFreq" onchange="buildCron()"><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly" selected>Weekly</option><option value="monthly">Monthly (1st)</option></select>
        </div>
        <div class="field" id="field-hour"><div class="lbl">Hour</div>
          <select id="cronHour" onchange="buildCron()"></select>
        </div>
        <div class="field"><div class="lbl">Minute</div><input type="number" id="cronMin" value="0" min="0" max="59" oninput="buildCron()"></div>
      </div>
      <div class="field" id="field-days"><div class="lbl" style="margin-bottom:10px">Days of Week</div>
        <div class="row" style="flex-wrap:wrap;gap:8px" id="day-grid"></div>
      </div>
    </div>
    <div id="cron-custom" style="display:none">
      <div class="field"><div class="lbl">Cron Expression</div>
        <input type="text" id="cronCustom" placeholder="0 3 * * 1" oninput="buildCron()">
        <div class="hint">min hour day month weekday</div>
      </div>
    </div>
    <div class="info blue" style="margin-top:8px">
      <div style="font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px">Schedule Preview</div>
      <div id="cron-human" style="font-family:'Syne',sans-serif;font-weight:800;font-size:20px;color:var(--bright);margin-bottom:4px">Every Monday at 03:00</div>
      <div style="font-size:12px;color:var(--muted)">cron: <code id="cron-expr" style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 6px;border-radius:3px">0 3 * * 1</code></div>
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">📋</span> Crontab Entry</div>
      <div class="row">
        <button class="btn sm secondary" onclick="copyCron()">📋 Copy</button>
        <button class="btn sm success" onclick="installCron()"><span id="cron-inst-sp" class="spinner" style="display:none"></span>✅ Install</button>
        <button class="btn sm danger" onclick="removeCron()">🗑 Remove</button>
      </div>
    </div>
    <div class="term-box" style="line-height:2"><span id="crontab-line" style="color:var(--cyan)"></span></div>
    <div id="cron-status" style="margin-top:12px;display:none"></div>
    <div id="cron-next-run" style="margin-top:10px;display:none"></div>
  </div>

  <div class="card">
    <div class="card-hdr"><div class="card-title"><span class="icon">🔧</span> Additional Options</div></div>
    <div class="g2">
      <div>
        <div class="field"><div class="lbl">Max Log Lines</div><input type="number" id="maxLogLines" value="2000"><div class="hint">Log trimmed on each run</div></div>
        <div class="field"><div class="lbl">Log File Path</div><input type="text" id="logPath" placeholder="~/cron_debug.log"></div>
        <div class="field"><div class="lbl">Image Headroom (MB)</div><input type="number" id="imageHeadroom" value="5000" min="500" max="20000"><div class="hint">Space the image must have beyond source data size. Auto-resize triggers if image capacity &lt; source used + headroom. Increase for large app backups (Immich etc). Default 5000 MB.</div></div>
      </div>
      <div>
        <div class="field"><div class="lbl">Lock File Path</div><input type="text" id="lockFile" value="/tmp/weekly_image.lock"><div class="hint">Prevents concurrent runs</div></div>
        <div class="field"><div class="lbl">Runtipi Directory</div><input type="text" id="tipiDir" placeholder="~/runtipi"></div>
        <div class="field"><div class="lbl">Runtipi Username</div><input type="text" id="tipiUser" placeholder="admin"></div>
        <div class="field"><div class="lbl">Runtipi Password</div><input type="password" id="tipiPass" placeholder="(enables API restart fallback)"><div class="hint">Stored in generated script — keep script file permissions tight</div></div>
        <div class="field" style="flex-direction:row;align-items:center;gap:10px;flex-wrap:wrap">
          <button class="btn" style="font-size:12px;padding:6px 14px" onclick="testRuntipiApi()">🔗 Test Runtipi API</button>
          <span id="tipi-test-status" style="font-size:12px;color:var(--muted)"></span>
        </div>
      </div>
    </div>
  </div>
  <button class="btn primary" onclick="saveConfig()">💾 Save Configuration</button>
</div>

<!-- ═══════════════════════ GENERATE TAB ═══════════════════════ -->
<div class="pane" id="tab-generate">
  <!-- image-backup status card -->
  <div id="imgbak-missing-card" class="card" style="display:none;border-color:rgba(239,68,68,.4);margin-bottom:20px">
    <div class="card-hdr" style="margin-bottom:14px">
      <div class="card-title"><span class="icon">⚠️</span> <span style="color:var(--red)">image-backup not installed</span></div>
      <span class="badge red"><span class="dot"></span>Missing</span>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.7">
      <code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 5px;border-radius:3px">image-backup</code>
      is a Raspberry Pi imaging utility by RonR, required to create incremental SD card image backups.
      It is not available via <code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 5px;border-radius:3px">apt</code> — the guided installer below will clone it from GitHub and install it automatically.
    </p>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px;font-size:12px;line-height:1.8">
      <div style="color:var(--muted);font-weight:700;letter-spacing:.06em;font-size:11px;margin-bottom:10px">WHAT THE INSTALLER WILL DO</div>
      <div class="row" style="gap:8px;margin-bottom:6px"><span style="color:var(--accent)">1.</span><span>Check / install <code style="color:var(--cyan)">git</code> if missing</span></div>
      <div class="row" style="gap:8px;margin-bottom:6px"><span style="color:var(--accent)">2.</span><span>Clone <code style="color:var(--cyan)">https://github.com/seamusdemora/RonR-RPi-image-utils</code></span></div>
      <div class="row" style="gap:8px;margin-bottom:6px"><span style="color:var(--accent)">3.</span><span>Run <code style="color:var(--cyan)">sudo install --mode=755 image-* /usr/local/sbin</code></span></div>
      <div class="row" style="gap:8px"><span style="color:var(--accent)">4.</span><span>Verify <code style="color:var(--cyan)">/usr/local/sbin/image-backup</code> exists</span></div>
    </div>
    <div class="row">
      <button class="btn primary" onclick="openImgbakModal(false)">📦 Install image-backup</button>
      <a href="https://github.com/seamusdemora/RonR-RPi-image-utils" target="_blank" rel="noopener" class="btn secondary" style="text-decoration:none">📖 View on GitHub</a>
    </div>
  </div>
  <div id="imgbak-ok-card" class="card" style="display:none;border-color:rgba(16,185,129,.3);margin-bottom:20px">
    <div class="row" style="justify-content:space-between">
      <div class="row" style="gap:10px">
        <span class="badge green"><span class="dot"></span>Installed</span>
        <span style="font-size:13px;color:var(--bright)">image-backup is installed at <code style="color:var(--cyan);font-size:12px">/usr/local/sbin/image-backup</code></span>
      </div>
      <button class="btn ghost sm" onclick="openImgbakModal(true)" title="Pull latest from GitHub and reinstall">🔄 Update</button>
    </div>
  </div>
  <div class="card">
    <div class="card-hdr"><div class="card-title"><span class="icon">⚡</span> Generate Script</div></div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:20px;line-height:1.7">Generates a complete bash script from your configuration across all tabs — destination, containers, schedule, and notifications.</p>
    <div class="row">
      <button class="btn primary" onclick="generateScript()">⚡ Generate Script</button>
      <button class="btn ghost" onclick="viewScript()">👁 View Script</button>
      <button class="btn secondary" id="btn-copy" style="display:none" onclick="copyScript()">📋 Copy</button>
      <button class="btn success" id="btn-write" style="display:none" onclick="writeScript()"><span id="write-sp" class="spinner" style="display:none"></span>💾 Write Script to Disk</button>
    </div>
  </div>
  <div class="card" id="script-card" style="display:none">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">📄</span> <span id="script-card-title">Generated Script</span></div>
      <span class="badge green" id="script-badge"><span class="dot"></span>Ready</span>
    </div>
    <div class="code-out"><pre id="script-out"></pre></div>
    <div id="write-status" style="display:none;margin-top:12px"></div>
    <div class="info blue" style="margin-top:12px">
      <strong>Deploy:</strong> Write to disk → install cron in Schedule tab → done.
      <span style="color:var(--orange)">⚡ First run</span> uses <code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 5px;border-radius:3px">-i</code> flag automatically via sentinel.
    </div>
  </div>

  <!-- Cleanup / Reset -->
  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🧹</span> Reset &amp; Cleanup</div>
    </div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:14px;line-height:1.7">Delete backup artefacts to rebase to a fresh image or recover from a failed run. Select what to remove then click Clean Up.</p>
    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px;font-size:13px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;padding-bottom:6px;border-bottom:1px solid var(--border,#334)">
        <input type="checkbox" id="cl-all" onchange="clToggleAll(this.checked)" style="flex-shrink:0"> <span style="color:var(--muted)">Select all</span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
        <input type="checkbox" id="cl-sentinel" onchange="clSyncAll()" style="flex-shrink:0;margin-top:2px"> <span><strong>Sentinel file</strong> <code style="word-break:break-all">.image_initialised</code> — forces a full rebase on next backup run</span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
        <input type="checkbox" id="cl-lock" onchange="clSyncAll()" style="flex-shrink:0;margin-top:2px"> <span><strong>Lock file</strong> — clears a stuck lock from a previously aborted run</span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
        <input type="checkbox" id="cl-compact-tmp" onchange="clSyncAll()" style="flex-shrink:0;margin-top:2px"> <span><strong>Compact temp mount</strong> <code style="word-break:break-all">/tmp/pbm_compact_mnt</code> — cleans up orphaned loop mounts</span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;color:var(--red,#f87171)">
        <input type="checkbox" id="cl-image" onchange="clSyncAll()" style="flex-shrink:0;margin-top:2px"> <span><strong>Image file</strong> <code id="cl-image-label" style="word-break:break-all"></code> — permanently deletes the backup image ⚠️</span>
      </label>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
      <button class="btn" style="background:var(--orange)" onclick="runCleanup()">🧹 Clean Up Selected</button>
      <span id="cleanup-status" style="font-size:12px"></span>
    </div>
  </div>

  <!-- Manual Run -->
  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">▶️</span> Run Backup Now</div>
      <span id="run-result-badge" style="display:none"></span>
    </div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;line-height:1.7">Trigger a backup immediately — useful for testing your configuration or taking a manual snapshot outside the schedule.</p>

    <div id="phase-bar" style="display:none;margin-bottom:16px">
      <div class="phase-bar" id="phases">
        <div class="phase-item"><div class="phase-track" id="ph0"></div><div class="phase-label" id="phl0">Stopping</div></div>
        <div class="phase-item"><div class="phase-track" id="ph1"></div><div class="phase-label" id="phl1">Image</div></div>
        <div class="phase-item"><div class="phase-track" id="ph2"></div><div class="phase-label" id="phl2">Restarting</div></div>
        <div class="phase-item"><div class="phase-track" id="ph3"></div><div class="phase-label" id="phl3">Done</div></div>
      </div>
      <div id="phase-status" class="row" style="margin-top:6px;display:none">
        <div class="sdot orange" id="phase-dot" style="animation:pulse 1.2s ease infinite"></div>
        <span id="phase-lbl" style="font-size:12px;color:var(--orange);font-weight:600"></span>
      </div>
    </div>

    <div id="confirm-panel" style="display:none;margin-bottom:16px;padding:16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:10px">
      <div style="font-size:13px;color:var(--red);font-weight:600;margin-bottom:8px">⚠️ This will stop all running containers</div>
      <div style="font-size:12px;color:var(--text);line-height:1.7;margin-bottom:14px">All containers will be gracefully stopped, a backup image created, then containers restarted in priority order. This may take <strong style="color:var(--bright)">10–20 minutes</strong>.</div>
      <div class="row">
        <button class="btn danger" onclick="startBackup()">Yes, run backup now</button>
        <button class="btn secondary" onclick="document.getElementById('confirm-panel').style.display='none'">Cancel</button>
      </div>
    </div>

    <div class="row" id="run-btns">
      <button class="btn danger" id="run-btn" onclick="document.getElementById('confirm-panel').style.display='block'">▶️ Run Backup Now</button>
      <button class="btn ghost" id="clear-btn" style="display:none" onclick="clearRunLog()">Clear</button>
    </div>

    <div id="run-log-wrap" style="display:none;margin-top:16px">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase">
          Live Output <span id="live-dot" style="color:var(--accent);animation:pulse 1s infinite">●</span>
          <span id="run-elapsed" style="color:var(--cyan);margin-left:10px;font-size:11px"></span>
        </div>
        <div class="row" style="gap:6px">
          <button class="btn ghost sm" onclick="copyLog('run-log')" title="Copy log">📋 Copy</button>
          <button class="btn ghost sm" onclick="toggleExpandLog('run-log')" id="run-expand-btn" title="Expand log" aria-label="Expand log">⛶</button>
        </div>
      </div>
      <div id="run-log" class="term-box" style="max-height:340px;overflow-y:auto"></div>
      <div id="run-result-box" style="display:none;margin-top:10px"></div>
    </div>
  </div>

  <!-- Verify Image -->
  <div class="card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🔍</span> Verify Backup Image</div>
      <span id="verify-result-badge" style="display:none"></span>
    </div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;line-height:1.7">Attaches the image as a loop device and runs <code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 5px;border-radius:3px">fsck -n</code> on both partitions. Non-destructive — no changes are written to the image.</p>
    <div class="info orange" style="margin-bottom:16px;font-size:12px">⚠️ The root partition may show exit code 1 (journal unclean) — this is normal for a backup taken while the system was live and does not affect restorability.</div>
    <div class="field" style="margin-bottom:12px">
      <div class="lbl">Image Path to Verify</div>
      <input type="text" id="verifyImagePath" placeholder="auto-filled from Destination settings">
      <div class="hint">Defaults to <strong>Mount Point / Image Filename</strong> from the Destination tab. Override here to verify a different file.</div>
    </div>
    <div class="row" id="verify-btns">
      <button class="btn cyan" id="verify-btn" onclick="startVerify()">🔍 Verify Image</button>
      <button class="btn ghost" id="verify-clear-btn" style="display:none" onclick="clearVerifyLog()">Clear</button>
    </div>
    <div id="verify-log-wrap" style="display:none;margin-top:16px">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase">
          Output <span id="verify-live-dot" style="color:var(--accent);animation:pulse 1s infinite">●</span>
        </div>
        <button class="btn ghost sm" onclick="copyLog('verify-log')" title="Copy log">📋 Copy</button>
      </div>
      <div id="verify-log" class="term-box" style="max-height:380px;overflow-y:auto"></div>
      <div id="verify-result-box" style="display:none;margin-top:10px"></div>
    </div>
  </div>

  <!-- Compact Image -->
  <div class="card" id="compact-card">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🗜️</span> Compact Image</div>
      <span id="compact-result-badge" style="display:none"></span>
    </div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:12px;line-height:1.7">Reclaims disk space when source data has shrunk. Zeros freed blocks inside the image then punches sparse holes — actual disk usage drops without changing the logical file size or affecting future backups.</p>

    <!-- Stats grid -->
    <div id="compact-stats" style="display:none;margin-bottom:14px;padding:12px 14px;background:var(--surface2);border-radius:8px;font-size:13px">
      <div class="g-stack" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px">
        <div><div style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em">Image (logical)</div><div id="cstat-logical" style="font-weight:600;margin-top:3px;font-size:15px">—</div></div>
        <div><div style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em">Disk usage (actual)</div><div id="cstat-sparse" style="font-weight:600;margin-top:3px;font-size:15px">—</div></div>
        <div><div style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em">Source used</div><div id="cstat-source" style="font-weight:600;margin-top:3px;font-size:15px">—</div></div>
      </div>
      <div id="cstat-wasted" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)"></div>
    </div>

    <!-- Compact recommended banner -->
    <div id="compact-banner" style="display:none;margin-bottom:14px" class="info orange">
      ⚠️ <strong>Compact recommended</strong> — <span id="compact-banner-msg"></span>.
      <button class="btn ghost sm" style="margin-left:8px;padding:2px 8px" onclick="dismissCompactBanner()">✕ Dismiss</button>
    </div>

    <div class="row" style="gap:8px;flex-wrap:wrap;align-items:center">
      <button class="btn cyan" id="compact-btn" onclick="startCompact()">
        <span id="compact-spinner" class="spinner" style="display:none"></span>🗜️ Compact Image
      </button>
      <button class="btn ghost" id="compact-check-btn" onclick="checkImageStatus()">↻ Refresh Stats</button>
      <button class="btn ghost" id="compact-clear-btn" style="display:none" onclick="clearCompactLog()">Clear</button>
      <span id="compact-wasted-badge" style="display:none;font-size:12px;color:var(--orange);font-weight:600"></span>
    </div>
    <div class="hint" style="margin-top:6px">Uses the same image path as Verify above. Install <code>zerofree</code> (<code>apt install zerofree</code>) for faster compaction — otherwise uses a mount + zero-fill fallback.</div>

    <div id="compact-log-wrap" style="display:none;margin-top:16px">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase">
          Output <span id="compact-live-dot" style="color:var(--accent);animation:pulse 1s infinite;display:none">●</span>
        </div>
        <button class="btn ghost sm" onclick="copyLog('compact-log')" title="Copy log">📋 Copy</button>
      </div>
      <div id="compact-log" class="term-box" style="max-height:340px;overflow-y:auto"></div>
      <div id="compact-result-box" style="display:none;margin-top:10px"></div>
    </div>
  </div>
</div>

<!-- ═══════════════════════ RESTORE TAB ════════════════════════ -->
<div class="pane" id="tab-restore">

  <!-- Danger banner — dismissable via localStorage -->
  <div id="restore-danger-banner" style="background:rgba(239,68,68,.1);border:2px solid rgba(239,68,68,.5);border-radius:12px;padding:20px 24px;margin-bottom:20px">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:12px">
        <span style="font-size:22px">⚠️</span>
        <strong style="font-family:'Syne',sans-serif;font-size:15px;color:var(--red)">RESTORE MODE — DESTRUCTIVE OPERATION</strong>
      </div>
      <button class="btn ghost sm" onclick="dismissRestoreBanner()" title="Dismiss — I understand" style="flex-shrink:0">✕ Dismiss</button>
    </div>
    <div style="font-size:12px;color:var(--text);line-height:1.9">
      This tab writes a disk image <strong style="color:var(--bright)">directly onto a physical block device</strong>.<br>
      <strong style="color:var(--red)">This is the OPPOSITE of backup:</strong> you are reading <em>from</em> the <code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 5px;border-radius:3px">.img</code> file and writing <em>to</em> a device.<br>
      <strong style="color:var(--red)">ALL existing data on the target device will be permanently erased.</strong><br>
      The result is a ready-to-boot standby Pi clone — just plug the restored device in.
    </div>
  </div>

  <!-- Step 1: Image source -->
  <div class="card" style="border-color:rgba(139,92,246,.3)">
    <div class="card-hdr" style="margin-bottom:16px">
      <div class="card-title">
        <div class="step-circle" style="background:rgba(139,92,246,.2);border:1px solid var(--purple);color:var(--purple)">1</div>
        Image Source
      </div>
      <span style="font-size:11px;color:var(--muted)">The .img file to restore FROM</span>
    </div>

    <!-- Backup source mount status -->
    <div class="sub-panel" style="margin-bottom:14px">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <div class="row" style="gap:8px">
          <strong style="font-size:12px;color:var(--bright)">Backup Source Mount</strong>
          <span id="restore-src-pill" class="badge muted"><span class="dot"></span>Checking…</span>
        </div>
        <div class="row" style="gap:6px">
          <button class="btn success sm" id="restore-src-mount-btn" onclick="restoreSourceMount()" style="display:none"><span id="restore-src-mnt-sp" class="spinner" style="display:none"></span>⬆ Mount</button>
          <button class="btn ghost sm" id="restore-src-unmount-btn" onclick="restoreSourceUnmount()" style="display:none">⬇ Unmount</button>
          <button class="btn secondary sm" onclick="checkRestoreSourceMount()">↻ Refresh</button>
        </div>
      </div>
      <div id="restore-src-info" style="font-size:11px;color:var(--muted);margin-bottom:6px"></div>
      <!-- Mount config summary — shown when not mounted -->
      <div id="restore-src-cfg" style="display:none">
        <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Using saved destination config:</div>
        <div id="restore-src-cfg-detail" style="font-size:11px;color:var(--cyan);background:var(--bg4);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font-family:'JetBrains Mono',monospace"></div>
      </div>
      <div id="restore-src-log" class="term-box" style="display:none;margin-top:8px;max-height:120px;overflow-y:auto"></div>
    </div>

    <div class="g2" style="margin-bottom:12px">
      <div class="field" style="margin:0">
        <div class="lbl">Image File Path</div>
        <input type="text" id="restoreImagePath" placeholder="/mnt/backups/pi_backup.img">
      </div>
      <div class="field" style="margin:0;display:flex;flex-direction:column;justify-content:flex-end">
        <button class="btn cyan" onclick="verifyRestoreImage()"><span id="restore-verify-sp" class="spinner" style="display:none"></span>🔍 Verify Image</button>
      </div>
    </div>
    <div id="restore-img-status" style="display:none"></div>
  </div>

  <!-- Step 2: Target device -->
  <div class="card" style="border-color:rgba(245,158,11,.3)">
    <div class="card-hdr" style="margin-bottom:16px">
      <div class="card-title">
        <div class="step-circle" style="background:rgba(245,158,11,.2);border:1px solid var(--orange);color:var(--orange)">2</div>
        Restore Target Device
      </div>
      <button class="btn cyan sm" onclick="scanRestoreDevices()"><span id="restore-scan-sp" class="spinner" style="display:none"></span>🔍 Scan Devices</button>
    </div>
    <div class="info orange" style="margin-bottom:14px;font-size:12px">
      ⚠️ Only <strong>USB drives and SD card readers</strong> can be selected as restore targets.
      The Pi's boot disk and fixed internal disks appear locked and cannot be chosen.
      Plug in your device first, then click <strong>Scan Devices</strong>.
      Double-check the size matches what you expect before selecting.
    </div>
    <div class="info blue" style="margin-bottom:14px;font-size:12px">
      💡 <strong>Tip:</strong> To restore to an SD card, plug it into a USB SD card reader connected to the Pi.
      The card will appear as a <code style="color:var(--cyan)">/dev/sdX</code> device when detected.
    </div>
    <div id="restore-dev-empty" style="text-align:center;padding:20px;color:var(--muted);font-size:12px">Plug in your USB drive or SD card reader, then click Scan Devices</div>
    <div id="restore-dev-list"></div>
    <input type="hidden" id="restoreTargetDevice">
  </div>

  <!-- Step 3: Confirm -->
  <div class="card" id="restore-confirm-card" style="display:none;border-color:rgba(239,68,68,.4)">
    <div class="card-hdr" style="margin-bottom:16px">
      <div class="card-title">
        <div class="step-circle" style="background:rgba(239,68,68,.2);border:1px solid var(--red);color:var(--red)">3</div>
        <span style="color:var(--red)">Confirm — Read Carefully</span>
      </div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px">
      <div style="font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.08em;margin-bottom:8px">RESTORE SUMMARY</div>
      <div id="restore-summary" style="font-size:12px;line-height:1.8;word-break:break-all"></div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px">
      <div style="font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.08em;margin-bottom:8px">COMMAND THAT WILL RUN</div>
      <code id="restore-cmd-preview" style="font-size:12px;color:var(--cyan);line-height:1.8;word-break:break-all"></code>
    </div>
    <div style="margin-bottom:16px">
      <label style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;cursor:pointer;font-size:13px">
        <input type="checkbox" id="restore-chk1" style="margin-top:2px;width:auto;accent-color:var(--red)">
        <span>I understand that <strong id="restore-chk1-dev" style="color:var(--red)"></strong> will be <strong style="color:var(--red)">completely and permanently erased</strong></span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;font-size:13px">
        <input type="checkbox" id="restore-chk2" style="margin-top:2px;width:auto;accent-color:var(--red)">
        <span>I have confirmed this is <strong>NOT</strong> my running Pi's SD card, and I have the correct device selected</span>
      </label>
    </div>
    <button class="btn danger" id="restore-start-btn" onclick="startRestore()" disabled style="font-size:14px;padding:12px 24px">
      ⏪ Start Restore — Erase &amp; Write Image
    </button>
  </div>

  <!-- Step 4: Live output -->
  <div class="card" id="restore-output-card" style="display:none;border-color:rgba(139,92,246,.3)">
    <div class="card-hdr" style="margin-bottom:12px">
      <div class="card-title"><span class="icon">📺</span> Restore Progress</div>
      <span id="restore-result-badge" style="display:none"></span>
    </div>
    <div class="phase-bar" style="margin-bottom:12px">
      <div class="phase-item"><div class="phase-track" id="rph0"></div><div class="phase-label" id="rphl0">Verify</div></div>
      <div class="phase-item"><div class="phase-track" id="rph1"></div><div class="phase-label" id="rphl1">Safety</div></div>
      <div class="phase-item"><div class="phase-track" id="rph2"></div><div class="phase-label" id="rphl2">Writing</div></div>
      <div class="phase-item"><div class="phase-track" id="rph3"></div><div class="phase-label" id="rphl3">Done</div></div>
    </div>
    <div id="restore-log" class="term-box" style="max-height:400px;overflow-y:auto"></div>
    <div id="restore-result-box" style="display:none;margin-top:12px"></div>
  </div>

</div><!-- /tab-restore -->

</div><!-- /content -->

<!-- Install Deps Modal -->
<div id="install-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:102;align-items:center;justify-content:center" onclick="if(event.target===this)this.style.display='none'">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(600px,92vw);max-height:80vh;overflow-y:auto;animation:fadeIn .2s ease">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
      <div class="card-title"><span class="icon">📦</span> <span id="install-title">Installing…</span></div>
      <button class="btn ghost sm" onclick="document.getElementById('install-modal').style.display='none'" title="Close" aria-label="Close">✕</button>
    </div>
    <div id="install-log" class="term-box" style="max-height:340px;overflow-y:auto;margin-bottom:12px"></div>
    <div id="install-result" style="display:none"></div>
  </div>
</div>

<!-- Last Backup Modal -->
<div id="last-backup-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:100;align-items:center;justify-content:center" onclick="if(event.target===this)this.style.display='none'">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(660px,92vw);max-height:82vh;overflow-y:auto;animation:fadeIn .2s ease">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
      <div class="card-title"><span class="icon">🕐</span> Last Backup Details</div>
      <button class="btn ghost sm" onclick="document.getElementById('last-backup-modal').style.display='none'" title="Close" aria-label="Close">✕</button>
    </div>
    <div id="lbm-content"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
  </div>
</div>

<!-- image-backup Install Modal -->
<div id="imgbak-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:104;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(680px,92vw);max-height:85vh;overflow-y:auto;animation:fadeIn .2s ease">
    <div class="card-hdr" style="margin-bottom:16px">
      <div class="card-title"><span class="icon">📦</span> <span id="imgbak-modal-title">Installing image-backup…</span></div>
      <button class="btn ghost sm" id="imgbak-modal-close" onclick="document.getElementById('imgbak-modal').style.display='none'" disabled title="Close" aria-label="Close">✕</button>
    </div>
    <!-- Step progress -->
    <div class="phase-bar" style="margin-bottom:16px">
      <div class="phase-item"><div class="phase-track" id="ib-step1-track"></div><div class="phase-label" id="ib-step1-lbl">1. Git</div></div>
      <div class="phase-item"><div class="phase-track" id="ib-step2-track"></div><div class="phase-label" id="ib-step2-lbl">2. Clone / Pull</div></div>
      <div class="phase-item"><div class="phase-track" id="ib-step3-track"></div><div class="phase-label" id="ib-step3-lbl">3. Install</div></div>
      <div class="phase-item"><div class="phase-track" id="ib-step4-track"></div><div class="phase-label" id="ib-step4-lbl">4. Verify</div></div>
    </div>
    <div class="term-box" id="imgbak-log" style="min-height:200px;max-height:360px;overflow-y:auto"></div>
    <div id="imgbak-result" style="display:none;margin-top:14px"></div>
    <div class="row" style="justify-content:flex-end;margin-top:14px;gap:8px">
      <button class="btn secondary" id="imgbak-modal-close2" onclick="document.getElementById('imgbak-modal').style.display='none'" disabled>Close</button>
    </div>
  </div>
</div>

<!-- Change Password Modal -->
<div id="changepw-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:103;align-items:center;justify-content:center" onclick="if(event.target===this)this.style.display='none'">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(420px,92vw);animation:fadeIn .2s ease">
    <div class="card-hdr">
      <div class="card-title"><span class="icon">🔑</span> Change Password</div>
      <button class="btn ghost sm" onclick="document.getElementById('changepw-modal').style.display='none'" title="Close" aria-label="Close">✕</button>
    </div>
    <div class="field">
      <div class="lbl">Current Password</div>
      <input type="password" id="cp-current" placeholder="Your current password" autocomplete="current-password">
    </div>
    <div class="field">
      <div class="lbl">New Password</div>
      <input type="password" id="cp-new" placeholder="Min 8 characters" autocomplete="new-password">
    </div>
    <div class="field" style="margin-bottom:14px">
      <div class="lbl">Confirm New Password</div>
      <input type="password" id="cp-confirm" placeholder="Repeat new password" autocomplete="new-password">
    </div>
    <div id="cp-msg" style="display:none;margin-bottom:14px"></div>
    <div class="row" style="justify-content:flex-end;gap:8px">
      <button class="btn secondary" onclick="document.getElementById('changepw-modal').style.display='none'">Cancel</button>
      <button class="btn primary" id="cp-btn" onclick="doChangePassword()">Update Password</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ─── CSRF: attach a custom header to every same-origin mutating request.
// Cross-site HTML forms cannot set this header, so this blocks CSRF while
// the server rejects any /api mutation that lacks it. (SSE/GET are exempt.)
(function () {
  const _fetch = window.fetch.bind(window);
  window.fetch = function (url, opts) {
    opts = opts || {};
    const sameOrigin = typeof url === "string" && (url.startsWith("/") || url.startsWith(window.location.origin));
    if (sameOrigin) {
      opts.headers = Object.assign({}, opts.headers, { "X-PBM-CSRF": "1" });
    }
    return _fetch(url, opts);
  };
})();

// ─── State ────────────────────────────────────────────────────────────────────
const S = {
  destType: "iscsi",
  secondaryDests: [],     // additional dest types to rsync image to
  mountStates: {},        // destType -> bool
  containers: [],
  containerCfg: {},       // id -> {stopOnBackup, restartAfter, priority}
  ctFilter: "all",
  cronMode: "builder",
  cronDays: [1],
  toggles: { ntfyEnabled:false, notifySuccess:true, notifyFailure:true, notifyStart:false },
  generatedScript: "",
  backupRunning: false,
  runPhase: -1,
  deps: {},
  defaults: { scriptPath:"~/weekly_image.sh", logPath:"~/cron_debug.log", tipiDir:"~/runtipi" },
};

// ─── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type="ok") {
  const el = document.getElementById("toast");
  el.textContent = msg; el.className = `show ${type}`;
  setTimeout(() => el.className = "", 3000);
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    // Autosave before leaving the current tab
    saveConfig().catch(() => {});
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ─── Toggles ──────────────────────────────────────────────────────────────────
function toggleClick(el) {
  const key = el.dataset.key;
  S.toggles[key] = !S.toggles[key];
  el.classList.toggle("on",  S.toggles[key]);
  el.classList.toggle("off", !S.toggles[key]);
  if (key === "ntfyEnabled") {
    document.getElementById("ntfy-fields").style.opacity = S.toggles[key] ? "1" : "0.4";
  }
}

// ─── Destination picker ───────────────────────────────────────────────────────
const DEST_COLORS = { iscsi:"var(--accent)", smb:"var(--cyan)", nfs:"var(--purple)", usb:"var(--orange)", local:"var(--green)" };
document.querySelectorAll(".dest-card").forEach(card => {
  card.addEventListener("click", () => {
    const dt = card.dataset.dest;
    document.querySelectorAll(".dest-card").forEach(c => {
      c.style.borderColor = ""; c.style.background = "";
      c.querySelector(".d-label").style.color = "";
    });
    card.style.borderColor = DEST_COLORS[dt];
    card.style.background  = `${DEST_COLORS[dt]}1a`;
    card.querySelector(".d-label").style.color = DEST_COLORS[dt];
    document.querySelectorAll(".dest-panel").forEach(p => p.style.display = "none");
    document.getElementById("panel-" + dt).style.display = "";
    S.destType = dt;
    const db = document.getElementById("dest-badge");
    db.textContent = dt.toUpperCase(); db.style.display = "";
    updatePreviews();
    checkDestDeps(dt);
    checkFstab(dt);
    checkMountStatus(dt);
    updateSecondaryLabels();
  });
});

function syncMountPoints(src) {
  document.getElementById("mountPoint").value = src.value;
  ["iscsiMountPoint","smbMountPoint","nfsMountPoint","usbMountPoint"].forEach(id => {
    const el = document.getElementById(id);
    if (el && el !== src) el.value = src.value;
  });
  updatePreviews();
}

function getMountPoint() {
  return document.getElementById("mountPoint").value || "/mnt/backups";
}
function getImageName() {
  return document.getElementById("imageName").value || "pi_backup.img";
}

function updatePreviews() {
  const mp  = getMountPoint() || "/mnt/backups";
  const img = getImageName()  || "pi_backup.img";
  const full = mp.replace(/\/$/, "") + "/" + img;
  // Update verify path placeholder; clear stale user-edited value if it no longer matches any real path
  const vip = document.getElementById("verifyImagePath");
  if (vip) {
    if (!vip.dataset.userEdited) {
      vip.placeholder = full;
    } else if (vip.value.trim() && !vip.value.trim().endsWith(img)) {
      // User had typed an explicit path for a different image name — clear it so the new name is used
      vip.value = "";
      delete vip.dataset.userEdited;
      vip.placeholder = full;
    }
  }
  // Update restore image path placeholder
  const rip = document.getElementById("restoreImagePath");
  if (rip && !rip.value) rip.placeholder = full;
  // Update cleanup image label (wildcard — image name may vary)
  const cl = document.getElementById("cl-image-label");
  if (cl) cl.textContent = (getMountPoint() || "/mnt/backups").replace(/\/$/, "") + "/*.img";
}
updatePreviews();

// ─── Term log helper ──────────────────────────────────────────────────────────
function termLine(msg, type="info") {
  const pmap = { cmd:"$", ok:"✓", err:"✗", warn:"⚠", info:"›" };
  return `<div class="term-line"><span class="term-prefix t-${type}">${pmap[type]||"›"}</span><span class="t-${type}">${esc(msg)}</span></div>`;
}
function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
const TERM_MAX_LINES = 1000;
function trimTermBox(box) {
  // Cap terminal DOM nodes so a multi-thousand-line stream can't bloat memory
  while (box.children.length > TERM_MAX_LINES) box.removeChild(box.firstChild);
}
function appendLog(boxId, msg, type="info") {
  const el = $c(boxId);
  if (!el) return;
  el.style.display = "";
  const wrapper = document.createElement("div");
  wrapper.innerHTML = termLine(msg, type);
  el.appendChild(wrapper.firstChild);
  trimTermBox(el);
  el.scrollTop = el.scrollHeight;
}
function clearLog(boxId) {
  const el = document.getElementById(boxId);
  if (el) { el.innerHTML = ""; el.style.display = "none"; }
}
const $ = id => document.getElementById(id);
const _elCache = {};
// Memoised lookup for STATIC nodes hit on every streamed log line
// (phase bars, terminal boxes). Never use for re-rendered elements.
const $c = id => _elCache[id] || (_elCache[id] = document.getElementById(id));
// Delegated click handling for rows that are re-rendered on every scan/refresh
// (replaces per-row inline onclick attributes)
document.addEventListener("click", e => {
  const el = e.target.closest("[data-action]");
  if (!el) return;
  switch (el.dataset.action) {
    case "select-restore-dev": selectRestoreDevice(el.dataset.name, el.dataset.size, el.dataset.model); break;
    case "select-nfs-export":  selectNfsExport(el, el.dataset.path); break;
    case "select-usb-part":    selectUsbPart(el, el.dataset.dev, el.dataset.fstype); break;
    case "toggle-ct":          toggleCtField(el); break;
    case "open-install-modal": openInstallModal(JSON.parse(el.dataset.pkgs)); break;
  }
});
function _copyText(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text)
      .then(() => toast("Copied to clipboard"))
      .catch(() => _copyFallback(text));
  } else {
    _copyFallback(text);
  }
}
function _copyFallback(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.cssText = "position:fixed;opacity:0;top:0;left:0;width:1px;height:1px";
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try { document.execCommand("copy"); toast("Copied to clipboard"); }
  catch(e) { toast("Copy unavailable — select text manually", "warn"); }
  document.body.removeChild(ta);
}
function copyLog(boxId) {
  const el = document.getElementById(boxId);
  if (!el) return;
  const text = Array.from(el.querySelectorAll(".term-line"))
    .map(l => l.textContent.trim()).join("\n");
  _copyText(text);
}
function toggleExpandLog(boxId) {
  const el  = document.getElementById(boxId);
  const btn = document.getElementById(boxId.replace("-log", "-expand-btn") + "");
  if (!el) return;
  const expanded = el.dataset.expanded === "1";
  el.style.maxHeight = expanded ? "340px" : "70vh";
  el.dataset.expanded = expanded ? "" : "1";
  if (btn) btn.textContent = expanded ? "⛶" : "⊡";
}
function spin(id, on) {
  const el = document.getElementById(id);
  if (el) el.style.display = on ? "inline-block" : "none";
}
function setMountPill(pillId, btnId, mounted) {
  const pill = document.getElementById(pillId);
  const btn  = document.getElementById(btnId);
  if (pill) {
    pill.className = `badge ${mounted ? "green" : "muted"}`;
    pill.innerHTML = `<span class="dot"></span>${mounted ? "Mounted" : "Not Mounted"}`;
  }
  if (btn) {
    btn.className = mounted ? "btn danger" : "btn success";
    btn.textContent = mounted ? "⏏ Unmount" : "⬆ Mount";
  }
}

// ─── iSCSI ────────────────────────────────────────────────────────────────────
let discoverTimer = null;
function scheduleDiscover() {
  clearTimeout(discoverTimer);
  const v = document.getElementById("iscsiPortal").value;
  if (v.length > 6) discoverTimer = setTimeout(iscsiDiscover, 800);
}

async function iscsiDiscover() {
  const portal = document.getElementById("iscsiPortal").value.trim();
  if (!portal) return;
  spin("disc-sp", true);
  clearLog("disc-log");
  appendLog("disc-log", `iscsiadm -m discovery -t sendtargets -p ${portal}:3260`, "cmd");
  appendLog("disc-log", `Connecting to ${portal}:3260…`, "info");
  try {
    const r = await fetch("/api/iscsi/discover", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ portal, port: document.getElementById("iscsiPort").value || "3260" }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    appendLog("disc-log", `Discovery complete — ${d.targets.length} target(s) found`, "ok");
    renderTargets(d.targets, portal);
  } catch (e) {
    appendLog("disc-log", e.message, "err");
  }
  spin("disc-sp", false);
}

function renderTargets(targets, portal) {
  const wrap = document.getElementById("disc-targets");
  const list = document.getElementById("targets-list");
  wrap.style.display = targets.length ? "" : "none";
  list.innerHTML = "";
  targets.forEach((t, i) => {
    const el = document.createElement("div");
    el.className = "target-item" + (i === 0 ? " active" : "");
    el.innerHTML = `<div class="radio-outer"><div class="radio-inner"></div></div><div><div style="font-size:12px;font-weight:500;color:var(--bright)">${esc(t.iqn)}</div><div style="font-size:10px;color:var(--muted)">${esc(t.portal)}</div></div>`;
    el.addEventListener("click", () => {
      document.querySelectorAll(".target-item").forEach(x => x.classList.remove("active"));
      el.classList.add("active");
      document.getElementById("iscsiIQN").value = t.iqn;
      document.getElementById("iscsi-step2").style.opacity = "1";
      appendLog("disc-log", `Selected: ${t.iqn}`, "ok");
    });
    list.appendChild(el);
  });
  if (targets.length) {
    document.getElementById("iscsiIQN").value = targets[0].iqn;
    document.getElementById("iscsi-step2").style.opacity = "1";
  }
}

async function iscsiLogin() {
  const iqn    = document.getElementById("iscsiIQN").value.trim();
  const portal = document.getElementById("iscsiPortal").value.trim();
  if (!iqn) return;
  spin("login-sp", true);
  clearLog("login-log");
  appendLog("login-log", `iscsiadm -m node -T ${iqn} -p ${portal}:3260 --login`, "cmd");
  try {
    const r = await fetch("/api/iscsi/login", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ portal, iqn, port: document.getElementById("iscsiPort").value || "3260" }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    appendLog("login-log", d.message || "Login successful", "ok");
    if (d.device) {
      appendLog("login-log", `Block device: ${d.device}`, "info");
      document.getElementById("iscsiDevice").value = d.device;
    } else {
      appendLog("login-log", "⚠ Could not detect block device — enter it manually", "warn");
    }
    document.getElementById("iscsi-step3").style.opacity = "1";
  } catch(e) {
    appendLog("login-log", e.message, "err");
  }
  spin("login-sp", false);
}

// ─── Mount / Unmount ──────────────────────────────────────────────────────────
async function doMount(dest) {
  const mounted = S.mountStates[dest];
  const logId   = `${dest}-mnt-log`;
  spin(`${dest}-mnt-sp`, true);
  clearLog(logId);

  const mp = getMountPoint();

  if (mounted) {
    appendLog(logId, `sudo umount ${mp}`, "cmd");
    try {
      const r = await fetch("/api/mount/do", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ action:"unmount", mountPoint:mp }) });
      const d = await r.json();
      if (!r.ok || !d.ok) throw new Error(d.error || "Unmount failed");
      appendLog(logId, `Unmounted ${mp}`, "ok");
      S.mountStates[dest] = false;
      setMountPill(`${dest}-mnt-pill`, `${dest}-mnt-btn`, false);
    } catch(e) { appendLog(logId, e.message, "err"); }
  } else {
    const body = buildMountBody(dest, mp);
    appendLog(logId, mountCmd(dest, body), "cmd");
    try {
      const r = await fetch("/api/mount/do", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok || !d.ok) throw new Error(d.error || "Mount failed");
      appendLog(logId, `Mounted at ${mp}`, "ok");
      if (d.df) appendLog(logId, d.df, "info");
      S.mountStates[dest] = true;
      setMountPill(`${dest}-mnt-pill`, `${dest}-mnt-btn`, true);
      checkImageOwnership(dest);
    } catch(e) { appendLog(logId, e.message, "err"); }
  }
  spin(`${dest}-mnt-sp`, false);
}

function buildMountBody(dest, mp) {
  const g = id => (document.getElementById(id)||{}).value || "";
  if (dest === "smb")   return { destType:"smb",   mountPoint:mp, smbServer:g("smbServer"), smbShare:g("smbShare"), smbUser:g("smbUser"), smbPass:g("smbPass"), smbDomain:g("smbDomain"), smbVersion:g("smbVersion"), smbExtraOpts:g("smbExtraOpts") };
  if (dest === "nfs")   return { destType:"nfs",   mountPoint:mp, nfsServer:g("nfsServer"), nfsExport:g("nfsExport"), nfsMountOpts:g("nfsMountOpts"), nfsCustomOpts:g("nfsCustomOpts") };
  if (dest === "usb")   return { destType:"usb",   mountPoint:mp, usbDevice:g("usbDevice"), usbFsType:g("usbFsType") };
  if (dest === "iscsi") return { destType:"iscsi", mountPoint:mp, iscsiDevice:g("iscsiDevice") };
  return { destType:"local", mountPoint:mp };
}
function mountCmd(dest, b) {
  if (dest === "smb")   return `sudo mount -t cifs //${b.smbServer}/${b.smbShare} ${b.mountPoint} -o username=${b.smbUser},vers=${b.smbVersion}`;
  if (dest === "nfs")   return `sudo mount -t nfs ${b.nfsServer}:${b.nfsExport} ${b.mountPoint} -o ${b.nfsMountOpts}`;
  if (dest === "usb")   return `sudo mount -t ${b.usbFsType} ${b.usbDevice} ${b.mountPoint}`;
  if (dest === "iscsi") return `sudo mount ${b.iscsiDevice} ${b.mountPoint}`;
  return `# local path — no mount needed`;
}

function buildFstabLine(dest, mp) {
  const b = buildMountBody(dest, mp);
  if (dest === "smb")   return `//${b.smbServer}/${b.smbShare} ${mp} cifs credentials=/etc/samba/credentials,vers=${b.smbVersion},_netdev 0 0`;
  if (dest === "nfs")   return `${b.nfsServer}:${b.nfsExport} ${mp} nfs ${b.nfsMountOpts},_netdev 0 0`;
  if (dest === "usb")   return `${b.usbDevice} ${mp} ${b.usbFsType} defaults 0 2`;
  if (dest === "iscsi") return `${b.iscsiDevice} ${mp} auto defaults,_netdev 0 2`;
  return "";
}

function setFstabToggle(dest, on) {
  const tog = document.getElementById(`${dest}-fstab-tog`);
  if (tog) tog.className = `toggle ${on ? "on" : "off"}`;
}

async function checkFstab(dest) {
  const mp = getMountPoint();
  if (!mp || dest === "local") return;
  setFstabToggle(dest, false); // reset while checking
  try {
    const r = await fetch(`/api/mount/fstab/check?path=${encodeURIComponent(mp)}`);
    const d = await r.json();
    if (!d.present) return;
    // Verify the entry's filesystem type matches this destination
    const fields = (d.line || "").trim().split(/\s+/);
    const fstype = (fields[2] || "").toLowerCase();
    let matches = false;
    if (dest === "smb")   matches = fstype === "cifs";
    else if (dest === "nfs")   matches = fstype === "nfs" || fstype.startsWith("nfs");
    else if (dest === "iscsi") matches = d.line.includes("_netdev") && fstype !== "cifs" && !fstype.startsWith("nfs");
    else if (dest === "usb")   matches = fstype !== "cifs" && !fstype.startsWith("nfs") && !d.line.includes("_netdev");
    setFstabToggle(dest, matches);
  } catch(e) {}
}

// ─── Image ownership (never silently overwrite a foreign image) ──────────────
async function checkImageOwnership(dest) {
  const banner = document.getElementById(`${dest}-image-banner`);
  if (!banner) return;
  banner.style.display = "none";
  try {
    const r = await fetch(`/api/image/ownership?path=${encodeURIComponent(getMountPoint())}&image=${encodeURIComponent(getImageName())}`);
    const d = await r.json();
    if (!d.imageExists || d.ours) return;
    const when = d.mtime ? new Date(d.mtime * 1000).toLocaleString() : "unknown";
    const who  = d.markerExists ? `last written by <strong>${esc(d.markerHost)}</strong>` : "of unknown origin (no SpareCard marker)";
    banner.innerHTML = `<div class="info orange">⚠️ <strong>${esc(getImageName())}</strong> already exists at this destination (${esc(d.sizeH)}, modified ${esc(when)}) — ${who}.<br>
      Backups update the image in place and will refuse to run until this is resolved. If this file is another Pi's backup, change the Image Name in Settings before backing up here.<br>
      <button class="btn sm secondary" style="margin-top:8px" onclick="adoptImage('${dest}')">✓ It's this Pi's image — adopt it</button></div>`;
    banner.style.display = "";
  } catch(e) {}
}

async function adoptImage(dest) {
  try {
    const r = await fetch("/api/image/adopt", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ path: getMountPoint(), image: getImageName() }) });
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || "Adopt failed");
    toast("Image adopted — backups will update it in place", "ok");
    checkImageOwnership(dest);
  } catch(e) { toast(e.message, "err"); }
}

// ─── Mount detection ──────────────────────────────────────────────────────────
const DEST_FSTYPE = { smb:"cifs", nfs:"nfs", iscsi:"_netdev_check", usb:"block" };

async function checkMountStatus(dest) {
  const mp = document.getElementById(`${dest}MountPoint`)?.value || getMountPoint();
  if (!mp || dest === "local") return;
  const banner = document.getElementById(`${dest}-mount-banner`);
  if (banner) banner.style.display = "none";
  const imgBanner = document.getElementById(`${dest}-image-banner`);
  if (imgBanner) imgBanner.style.display = "none";

  try {
    const r = await fetch(`/api/mount/status?path=${encodeURIComponent(mp)}`);
    const d = await r.json();
    if (!d.mounted) return;

    // Determine if the mount type matches this destination
    const fs   = (d.fstype    || "").toLowerCase();
    const tran = (d.transport || "").toLowerCase();
    let matches = false;
    if (dest === "smb")        matches = fs === "cifs";
    else if (dest === "nfs")   matches = fs.startsWith("nfs");
    else if (dest === "iscsi") matches = tran === "iscsi";
    else if (dest === "usb")   matches = tran !== "iscsi" && fs !== "cifs" && !fs.startsWith("nfs");

    // Update the mount pill to green
    setMountPill(`${dest}-mnt-pill`, `${dest}-mnt-btn`, true);
    S.mountStates[dest] = true;
    checkImageOwnership(dest);

    if (matches && banner) {
      const src = d.source ? ` <span style="color:var(--muted)">(${esc(d.source)})</span>` : "";
      const df  = d.df     ? ` — ${esc(d.df.trim())}`                                       : "";
      banner.innerHTML = `<div class="info green">✅ Already mounted at <strong>${esc(mp)}</strong>${src}${df} — this destination is active.</div>`;
      banner.style.display = "";
    }
  } catch(e) {}

  // Extra: for iSCSI show active sessions and auto-populate fields
  if (dest === "iscsi") {
    const sb = document.getElementById("iscsi-session-banner");
    if (!sb) return;
    try {
      const r = await fetch("/api/iscsi/sessions");
      const d = await r.json();
      if (d.count > 0) {
        const s0 = d.sessions[0];
        // Auto-populate IQN field if empty
        const iqnEl = document.getElementById("iscsiIQN");
        if (iqnEl && !iqnEl.value && s0.iqn) {
          iqnEl.value = s0.iqn;
          document.getElementById("iscsi-step2").style.opacity = "1";
          document.getElementById("iscsi-step3").style.opacity = "1";
        }
        // Auto-populate block device field if empty
        const devEl = document.getElementById("iscsiDevice");
        if (devEl && !devEl.value && s0.device) {
          devEl.value = s0.device;
        }
        const devInfo = s0.device ? ` → <strong style="color:var(--green)">${esc(s0.device)}</strong>` : "";
        sb.innerHTML = `<div class="info blue">🔌 ${d.count} active iSCSI session${d.count>1?"s":""}: <strong>${esc(s0.iqn)}</strong> @ ${esc(s0.portal)}${devInfo}</div>`;
        sb.style.display = "";
      } else {
        sb.style.display = "none";
      }
    } catch(e) {}
  }
}

// ─── Secondary destinations ───────────────────────────────────────────────────
function setSecondaryToggle(dest, on) {
  const tog = document.getElementById(`${dest}-secondary-tog`);
  const lbl = document.getElementById(`${dest}-secondary-lbl`);
  const dot = document.getElementById(`${dest}-card-dot`);
  if (tog) tog.className = `toggle ${on ? "on" : "off"}`;
  if (lbl) lbl.style.color = on ? "var(--green)" : "";
  if (dot) dot.style.display = on ? "" : "none";
}

function updateSecondaryLabels() {
  ["iscsi","smb","nfs","usb"].forEach(dt => {
    const lbl = document.getElementById(`${dt}-secondary-lbl`);
    if (!lbl) return;
    const isPrimary = dt === S.destType;
    const isSecondary = S.secondaryDests.includes(dt);
    if (isPrimary) {
      lbl.textContent = "Primary destination";
      lbl.style.color = "var(--accent)";
      const tog = document.getElementById(`${dt}-secondary-tog`);
      if (tog) { tog.className = "toggle on"; tog.style.opacity = "0.5"; tog.style.pointerEvents = "none"; }
      const dot = document.getElementById(`${dt}-card-dot`);
      if (dot) { dot.style.display = ""; dot.style.background = "var(--accent)"; dot.style.boxShadow = "0 0 5px var(--accent)"; }
    } else {
      lbl.textContent = "Also back up here";
      lbl.style.color = isSecondary ? "var(--green)" : "";
      const tog = document.getElementById(`${dt}-secondary-tog`);
      if (tog) { tog.style.opacity = ""; tog.style.pointerEvents = ""; }
      const dot = document.getElementById(`${dt}-card-dot`);
      if (dot) { dot.style.background = "var(--green)"; dot.style.boxShadow = "0 0 5px var(--green)"; }
      setSecondaryToggle(dt, isSecondary);
    }
  });
}

function toggleSecondaryDest(dest) {
  if (dest === S.destType) return; // primary can't be toggled off
  const idx = S.secondaryDests.indexOf(dest);
  if (idx === -1) S.secondaryDests.push(dest);
  else S.secondaryDests.splice(idx, 1);
  updateSecondaryLabels();
}

async function toggleFstab(dest) {
  const tog = document.getElementById(`${dest}-fstab-tog`);
  if (!tog) return;
  const isOn = tog.classList.contains("on");
  const mp = getMountPoint();
  if (isOn) {
    // Remove from fstab
    try {
      const r = await fetch("/api/mount/fstab/remove", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({mountPoint: mp}) });
      const d = await r.json();
      if (d.ok) {
        setFstabToggle(dest, false);
        toast("Removed from /etc/fstab", "ok");
        if (dest === "iscsi") {
          const iqn = (document.getElementById("iscsiIQN")||{}).value||"";
          if (iqn) await fetch("/api/iscsi/autostart", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({iqn, enable:false}) });
        }
      } else toast(d.error || "Failed to remove from fstab", "err");
    } catch(e) { toast(e.message, "err"); }
  } else {
    // Add to fstab
    if (dest === "iscsi") {
      const iqn = (document.getElementById("iscsiIQN")||{}).value||"";
      if (!iqn) { toast("Login to an iSCSI target first", "err"); return; }
      try {
        const ar = await fetch("/api/iscsi/autostart", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({iqn, enable:true}) });
        const ad = await ar.json();
        if (!ad.ok) { toast("Failed to set iSCSI auto-login: " + (ad.error||""), "err"); return; }
      } catch(e) { toast(e.message, "err"); return; }
    }
    if (dest === "smb") {
      // Save credentials file so password is not stored in fstab
      const user = document.getElementById("smbUser").value;
      const pass = document.getElementById("smbPass").value;
      try {
        const cr = await fetch("/api/smb/credentials", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({smbUser:user, smbPass:pass}) });
        const cd = await cr.json();
        if (!cd.ok) { toast("Failed to save SMB credentials: " + (cd.error||""), "err"); return; }
      } catch(e) { toast(e.message, "err"); return; }
    }
    let line = buildFstabLine(dest, mp);
    if (!line) { toast("Fill in destination details first", "err"); return; }
    if (dest === "usb") {
      const dev = document.getElementById("usbDevice").value;
      try {
        const ur = await fetch(`/api/usb/uuid?device=${encodeURIComponent(dev)}`);
        const ud = await ur.json();
        if (ud.uuid) line = line.replace(dev, `UUID=${ud.uuid}`);
      } catch(e) { /* fall back to device path */ }
    }
    try {
      const r = await fetch("/api/mount/fstab", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({line}) });
      const d = await r.json();
      if (d.ok || d.note) { setFstabToggle(dest, true); toast("Added to /etc/fstab — will mount on boot", "ok"); }
      else toast(d.error || "Failed to add to fstab", "err");
    } catch(e) { toast(e.message, "err"); }
  }
}

async function saveCredentials() {
  const user = document.getElementById("smbUser").value;
  const pass = document.getElementById("smbPass").value;
  try {
    const r = await fetch("/api/smb/credentials", { method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ smbUser:user, smbPass:pass }) });
    const d = await r.json();
    if (d.ok) toast("Credentials saved to /etc/samba/credentials", "ok");
    else toast(d.error || "Failed to save credentials", "err");
  } catch(e) { toast(e.message, "err"); }
}

// ─── SMB test ─────────────────────────────────────────────────────────────────
async function testRuntipiApi() {
  const el = document.getElementById("tipi-test-status");
  el.style.color = "var(--muted)";
  el.textContent = "Testing…";
  try {
    const r = await fetch("/api/runtipi/test", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ tipiUser: document.getElementById("tipiUser").value,
                             tipiPass: document.getElementById("tipiPass").value }) });
    const d = await r.json();
    if (d.ok) {
      el.style.color = "var(--green)";
      el.textContent = "✓ " + d.message;
    } else {
      el.style.color = "var(--red)";
      el.textContent = "✗ " + d.error;
    }
  } catch(e) {
    el.style.color = "var(--red)";
    el.textContent = "✗ " + e.message;
  }
}

async function smbTest() {
  spin("smb-test-sp", true);
  clearLog("smb-test-log");
  const server = document.getElementById("smbServer").value;
  const user   = document.getElementById("smbUser").value;
  appendLog("smb-test-log", `smbclient -L //${server} -U ${user}`, "cmd");
  try {
    const r = await fetch("/api/smb/test", { method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ smbServer:server, smbUser:user, smbPass:document.getElementById("smbPass").value }) });
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error(d.error || "Test failed");
    appendLog("smb-test-log", "Connection successful", "ok");
    d.shares.forEach(s => appendLog("smb-test-log", s, "info"));
  } catch(e) { appendLog("smb-test-log", e.message, "err"); }
  spin("smb-test-sp", false);
}

// ─── NFS scan ─────────────────────────────────────────────────────────────────
async function nfsScan() {
  const server = document.getElementById("nfsServer").value.trim();
  if (!server) return;
  spin("nfs-scan-sp", true);
  clearLog("nfs-scan-log");
  appendLog("nfs-scan-log", `showmount -e ${server}`, "cmd");
  try {
    const r = await fetch("/api/nfs/exports", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ server }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    appendLog("nfs-scan-log", `${d.exports.length} export(s) found`, "ok");
    d.exports.forEach(e => appendLog("nfs-scan-log", e, "info"));
    renderNfsExports(d.exports);
  } catch(e) { appendLog("nfs-scan-log", e.message, "err"); }
  spin("nfs-scan-sp", false);
}

function renderNfsExports(exports) {
  const wrap = document.getElementById("nfs-exports");
  wrap.style.display = exports.length ? "" : "none";
  wrap.innerHTML = `<div class="lbl" style="margin-bottom:8px">Available Exports</div>` +
    exports.map(ex => {
      const path = ex.split(" ")[0];
      return `<div class="target-item" data-action="select-nfs-export" data-path="${esc(path)}"
        style="border-color:var(--border)">
        <div class="radio-outer"><div class="radio-inner"></div></div>
        <span style="font-size:12px;font-family:monospace;color:var(--text)">${esc(ex)}</span>
      </div>`;
    }).join("");
}
function selectNfsExport(el, path) {
  document.querySelectorAll("#nfs-exports .target-item").forEach(x => {
    x.classList.remove("active"); x.style.borderColor="var(--border)"; x.style.background="var(--bg)";
  });
  el.classList.add("active"); el.style.borderColor="var(--purple)"; el.style.background="rgba(139,92,246,.1)";
  document.getElementById("nfsExport").value = path;
}

// ─── USB scan ─────────────────────────────────────────────────────────────────
const FS_ICONS = { ext4:"🐧", exfat:"🪟", ntfs:"🪟", fat32:"💾", btrfs:"🌲", xfs:"⚡" };

async function usbScan() {
  spin("usb-scan-sp", true);
  clearLog("usb-scan-log");
  appendLog("usb-scan-log", "lsblk -J -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT", "cmd");
  try {
    const r = await fetch("/api/usb/scan");
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    appendLog("usb-scan-log", `${d.devices.length} disk(s) found`, "ok");
    renderUsbDevices(d.devices);
  } catch(e) { appendLog("usb-scan-log", e.message, "err"); }
  spin("usb-scan-sp", false);
}

function renderUsbDevices(devices) {
  const list = document.getElementById("usb-list");
  const empty = document.getElementById("usb-empty");
  empty.style.display = devices.length ? "none" : "";
  list.innerHTML = devices.map(disk => {
    const parts = (disk.children || []).filter(c => c.type === "part");
    const partsHtml = parts.map(p => `
      <div data-action="select-usb-part" data-dev="/dev/${esc(p.name)}" data-fstype="${esc(p.fstype||'ext4')}"
        style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;background:var(--bg4);border:1px solid var(--border);border-radius:0 0 8px 8px;transition:all .15s">
        <div style="width:12px;height:12px;border-radius:50%;border:2px solid var(--muted);flex-shrink:0"></div>
        <span style="font-size:14px">${FS_ICONS[p.fstype]||"💿"}</span>
        <span style="font-size:12px;color:var(--bright);font-weight:500">/dev/${esc(p.name)}</span>
        ${p.label ? `<span style="font-size:11px;color:var(--muted)">${esc(p.label)}</span>` : ""}
        <span class="badge orange" style="margin-left:auto">${esc(p.fstype||"unknown")}</span>
        <span class="badge muted">${esc(p.size)}</span>
        ${p.mountpoint ? `<span class="badge green">mounted</span>` : ""}
      </div>`).join("");
    return `<div style="margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-bottom:none;border-radius:8px 8px 0 0">
        <span style="font-size:14px">💿</span>
        <span style="font-size:12px;font-weight:600;color:var(--bright)">/dev/${esc(disk.name)}</span>
        <span class="badge muted">${esc(disk.size)}</span>
      </div>
      ${partsHtml}
    </div>`;
  }).join("");
}
function selectUsbPart(el, dev, fstype) {
  document.querySelectorAll("#usb-list [data-action]").forEach(x => {
    x.style.background = "var(--bg4)"; x.style.borderColor = "var(--border)";
    const r = x.querySelector("[style*='border-radius:50%']");
    if (r) { r.style.borderColor = "var(--muted)"; r.innerHTML = ""; }
  });
  el.style.background = "rgba(245,158,11,.1)"; el.style.borderColor = "var(--orange)";
  const radio = el.querySelector("[style*='border-radius:50%']");
  if (radio) { radio.style.borderColor = "var(--orange)"; radio.innerHTML = `<div style="width:5px;height:5px;border-radius:50%;background:var(--orange)"></div>`; }
  document.getElementById("usbDevice").value = dev;
  document.getElementById("usbFsType").value = fstype;
}

// ─── Local verify ─────────────────────────────────────────────────────────────
async function localVerify() {
  const path = document.getElementById("localPath").value.trim();
  if (!path) return;
  spin("local-sp", true);
  try {
    const r = await fetch("/api/local/verify", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ path }) });
    const d = await r.json();
    const box = document.getElementById("local-result");
    box.style.display = "";
    box.innerHTML = `<div class="info ${d.ok?"green":"red"}">${d.ok ? "✓ Path accessible and writable" : "✗ " + esc(d.error)}<br>${d.df ? esc(d.df) : ""}</div>`;
    document.getElementById("mountPoint").value = path;
    updatePreviews();
  } catch(e) { toast(e.message, "err"); }
  spin("local-sp", false);
}

// ─── Containers ───────────────────────────────────────────────────────────────
function defaultCtCfg(c) {
  const foundations = ["immich-db","immich-redis","gluetun","postgres","redis","mariadb","mysql"];
  const isFoundation = foundations.some(f => c.name.includes(f));
  return { stopOnBackup: c.status==="running", restartAfter: c.status==="running", priority: isFoundation ? "foundation" : "normal" };
}

async function loadContainers() {
  document.getElementById("ct-loading").style.display = "flex";
  document.getElementById("ct-error").style.display   = "none";
  document.getElementById("ct-wrap").style.display    = "none";
  spin("ct-refresh-sp", true);
  try {
    const r = await fetch("/api/containers");
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    S.containers = d;
    d.forEach(c => { if (!S.containerCfg[c.id]) S.containerCfg[c.id] = defaultCtCfg(c); });
    renderContainers();
    const running = d.filter(c => c.status === "running").length;
    document.getElementById("run-lbl").textContent = `${running} containers running`;
    document.getElementById("ct-loading").style.display = "none";
    document.getElementById("ct-wrap").style.display    = "";
  } catch(e) {
    document.getElementById("ct-loading").style.display = "none";
    document.getElementById("ct-error").style.display   = "";
    document.getElementById("ct-error").textContent     = "⚠️ " + e.message;
  }
  spin("ct-refresh-sp", false);
}

function setCtFilter(f) {
  S.ctFilter = f;
  ["all","running","exited"].forEach(n => {
    const b = document.getElementById("filter-"+n);
    b.className = n === f ? "btn sm primary" : "btn sm ghost";
  });
  renderContainers();
}

const PRI_COLORS = { foundation:"var(--orange)", high:"var(--cyan)", normal:"var(--muted)", low:"var(--muted)" };

function renderContainers() {
  const body = document.getElementById("ct-body");
  body.innerHTML = "";
  let list = S.containers;
  if (S.ctFilter !== "all") list = list.filter(c => c.status === S.ctFilter);
  if (!list.length) {
    body.innerHTML = `<div style="padding:20px;text-align:center;color:var(--muted);font-size:13px">No containers match this filter</div>`;
    return;
  }
  list.forEach((c, i) => {
    const cc  = S.containerCfg[c.id] || defaultCtCfg(c);
    const run = c.status === "running";
    const row = document.createElement("div");
    row.className = "ct-row";
    row.style.background = i % 2 === 0 ? "" : "rgba(255,255,255,.012)";
    row.innerHTML = `
      <div><div class="ct-name">${esc(c.name)}</div><div class="ct-img">${esc(c.image)}</div></div>
      <div><span class="badge ${run?"green":"muted"}"><span class="dot"></span>${esc(c.status)}</span></div>
      <div><div class="toggle ${cc.stopOnBackup?"on":"off"}" data-action="toggle-ct" data-id="${esc(c.id)}" data-field="stopOnBackup"><div class="toggle-k"></div></div></div>
      <div><div class="toggle ${cc.restartAfter?"on":"off"}" data-action="toggle-ct" data-id="${esc(c.id)}" data-field="restartAfter"><div class="toggle-k"></div></div></div>
      <div>
        <select class="pri-select" data-id="${esc(c.id)}" style="color:${PRI_COLORS[cc.priority]||"var(--text)"};border-color:${PRI_COLORS[cc.priority]}44"
          onchange="setPriority(this.dataset.id,this)">
          <option value="foundation" ${cc.priority==="foundation"?"selected":""}>🟠 Foundation</option>
          <option value="high"       ${cc.priority==="high"      ?"selected":""}>🔵 High</option>
          <option value="normal"     ${cc.priority==="normal"    ?"selected":""}>⚪ Normal</option>
          <option value="low"        ${cc.priority==="low"       ?"selected":""}>⬛ Low</option>
        </select>
      </div>
      <div style="font-size:11px;color:var(--muted)">${esc(c.uptime)}</div>`;
    body.appendChild(row);
  });
}

function toggleCtField(el) {
  const id = el.dataset.id; const field = el.dataset.field;
  S.containerCfg[id][field] = !S.containerCfg[id][field];
  el.classList.toggle("on",  S.containerCfg[id][field]);
  el.classList.toggle("off", !S.containerCfg[id][field]);
}
function setPriority(id, sel) {
  S.containerCfg[id].priority = sel.value;
  sel.style.color       = PRI_COLORS[sel.value] || "var(--text)";
  sel.style.borderColor = (PRI_COLORS[sel.value]||"var(--border)") + "44";
}

function selectAllContainers(on) {
  S.containers.forEach(c => {
    if (!S.containerCfg[c.id]) S.containerCfg[c.id] = defaultCtCfg(c);
    S.containerCfg[c.id].stopOnBackup  = on;
    S.containerCfg[c.id].restartAfter  = on;
  });
  renderContainers();
  toast(on ? "All containers set to stop & restart" : "All containers cleared");
}

// ─── Schedule / Cron ──────────────────────────────────────────────────────────
const DAYS_SHORT = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
const dayGrid = document.getElementById("day-grid");
DAYS_SHORT.forEach((d, i) => {
  const btn = document.createElement("div");
  btn.className = "day-btn " + (S.cronDays.includes(i) ? "on" : "off");
  btn.textContent = d;
  btn.addEventListener("click", () => {
    const idx = S.cronDays.indexOf(i);
    if (idx >= 0) S.cronDays.splice(idx, 1); else S.cronDays.push(i);
    if (!S.cronDays.length) S.cronDays.push(i);
    S.cronDays.sort();
    btn.classList.toggle("on",  S.cronDays.includes(i));
    btn.classList.toggle("off", !S.cronDays.includes(i));
    buildCron();
  });
  dayGrid.appendChild(btn);
});

const hourSel = document.getElementById("cronHour");
for (let h = 0; h < 24; h++) {
  const o = document.createElement("option");
  o.value = h; o.textContent = String(h).padStart(2,"0") + ":00";
  if (h === 3) o.selected = true;
  hourSel.appendChild(o);
}

function setCronMode(m) {
  S.cronMode = m;
  document.getElementById("cron-builder").style.display = m === "builder" ? "" : "none";
  document.getElementById("cron-custom").style.display  = m === "custom"  ? "" : "none";
  document.getElementById("mode-builder").className = m === "builder" ? "btn primary sm" : "btn secondary sm";
  document.getElementById("mode-custom").className  = m === "custom"  ? "btn primary sm" : "btn secondary sm";
  buildCron();
}

function buildCron() {
  const freq = document.getElementById("cronFreq").value;
  const h    = document.getElementById("cronHour").value;
  const m    = document.getElementById("cronMin").value || "0";
  let expr, human;
  if (S.cronMode === "custom") {
    expr   = document.getElementById("cronCustom").value || "0 3 * * 1";
    human  = expr;
  } else {
    if (freq === "hourly")  { expr = `${m} * * * *`;           human = `Every hour at :${m.padStart(2,"0")}`; }
    else if (freq === "daily")   { expr = `${m} ${h} * * *`;   human = `Every day at ${h.toString().padStart(2,"0")}:${m.padStart(2,"0")}`; }
    else if (freq === "monthly") { expr = `${m} ${h} 1 * *`;   human = `1st of every month at ${h.toString().padStart(2,"0")}:${m.padStart(2,"0")}`; }
    else {
      const ds = S.cronDays.length ? S.cronDays.join(",") : "1";
      expr  = `${m} ${h} * * ${ds}`;
      human = `Every ${S.cronDays.map(d=>DAYS_SHORT[d]).join(", ")} at ${h.toString().padStart(2,"0")}:${m.padStart(2,"0")}`;
    }
    document.getElementById("field-hour").style.display  = freq === "hourly" ? "none" : "";
    document.getElementById("field-days").style.display  = freq === "weekly" ? "" : "none";
  }
  document.getElementById("cron-expr").textContent  = expr;
  document.getElementById("cron-human").textContent = human;
  const scriptPath = S.defaults.scriptPath;
  const logPath    = document.getElementById("logPath").value || S.defaults.logPath;
  document.getElementById("crontab-line").textContent = `${expr} ${scriptPath} >> ${logPath} 2>&1`;
}
buildCron();

function copyCron() {
  _copyText(document.getElementById("crontab-line").textContent);
}

function _nextCronRun(expr) {
  // Simple next-run calculator for basic cron expressions
  try {
    const parts = expr.trim().split(/\s+/);
    if (parts.length !== 5) return null;
    const [minP, hourP, domP, monP, dowP] = parts;
    const now = new Date(); now.setSeconds(0, 0);
    const d = new Date(now.getTime() + 60000); // start 1 min from now
    for (let i = 0; i < 1440 * 7; i++) {
      const ok = (
        (minP  === "*" || parseInt(minP)  === d.getMinutes()) &&
        (hourP === "*" || parseInt(hourP) === d.getHours()) &&
        (domP  === "*" || parseInt(domP)  === d.getDate()) &&
        (monP  === "*" || parseInt(monP)  === d.getMonth() + 1) &&
        (dowP  === "*" || dowP.split(",").map(Number).includes(d.getDay()))
      );
      if (ok) return d;
      d.setMinutes(d.getMinutes() + 1);
    }
    return null;
  } catch { return null; }
}

async function installCron() {
  spin("cron-inst-sp", true);
  try {
    const expr = document.getElementById("cron-expr").textContent;
    const r = await fetch("/api/cron", { method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        cronLine: expr,
        scriptPath: S.defaults.scriptPath,
        logPath: document.getElementById("logPath").value || S.defaults.logPath
      })});
    const d = await r.json();
    if (!d.ok) throw new Error(d.error);
    const el = document.getElementById("cron-status");
    el.style.display = "";
    el.innerHTML = `<div class="info green">✅ Cron entry installed — ${new Date().toLocaleString()}</div>`;
    const nextEl = document.getElementById("cron-next-run");
    const next = _nextCronRun(expr);
    if (next && nextEl) {
      nextEl.style.display = "";
      nextEl.innerHTML = `<div class="info cyan">🕐 Next scheduled run: <strong>${next.toLocaleString()}</strong></div>`;
    }
    toast("Cron installed");
  } catch(e) { toast(e.message, "err"); }
  spin("cron-inst-sp", false);
}

async function removeCron() {
  if (!confirm("Remove the scheduled cron entry? The script will no longer run automatically.")) return;
  await fetch("/api/cron/remove", { method:"POST" });
  const el = document.getElementById("cron-status");
  el.style.display = "";
  el.innerHTML = `<div class="info red">🗑 Cron entry removed.</div>`;
  const nextEl = document.getElementById("cron-next-run");
  if (nextEl) nextEl.style.display = "none";
  toast("Cron removed");
}

// ─── Config save / load ───────────────────────────────────────────────────────
function collectConfig() {
  const g = id => (document.getElementById(id)||{}).value || "";
  return {
    destType: S.destType, secondaryDests: S.secondaryDests, mountPoint: getMountPoint(), imageName: getImageName(),
    iscsiPortal: g("iscsiPortal"), iscsiPort: g("iscsiPort"), iscsiIQN: g("iscsiIQN"), iscsiDevice: g("iscsiDevice"),
    smbServer: g("smbServer"), smbShare: g("smbShare"), smbUser: g("smbUser"), smbDomain: g("smbDomain"), smbVersion: g("smbVersion"), smbExtraOpts: g("smbExtraOpts"),
    nfsServer: g("nfsServer"), nfsExport: g("nfsExport"), nfsMountOpts: g("nfsMountOpts"), nfsCustomOpts: g("nfsCustomOpts"),
    usbDevice: g("usbDevice"), usbFsType: g("usbFsType"),
    localPath: g("localPath"),
    ...S.toggles,
    ntfyTopic: g("ntfyTopic"), ntfyServer: g("ntfyServer"),
    shutdownMethod: g("shutdownMethod"), shutdownFallback: g("shutdownFallback"),
    gracePeriod: g("gracePeriod"), settleTime: g("settleTime"), healthTimeout: g("healthTimeout"),
    cronMode: S.cronMode, cronDays: S.cronDays, cronExpr: document.getElementById("cron-expr").textContent,
    cronFreq: g("cronFreq"), cronHour: g("cronHour"), cronMin: g("cronMin"), customCron: g("cronCustom"),
    maxLogLines: g("maxLogLines"), logPath: g("logPath"), lockFile: g("lockFile"), tipiDir: g("tipiDir"),
    tipiUser: g("tipiUser"), tipiPass: g("tipiPass"),
    imageHeadroom: g("imageHeadroom") || "5000",
    containerCfg: S.containerCfg,
  };
}

async function saveConfig() {
  try {
    const r = await fetch("/api/config", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(collectConfig()) });
    const d = await r.json();
    if (!d.ok) throw new Error(d.error);
    toast("Configuration saved");
  } catch(e) { toast(e.message, "err"); }
}

async function loadConfig() {
  try {
    const r = await fetch("/api/config");
    const c = await r.json();
    if (!c || !Object.keys(c).length) return;
    const sv = (id, v) => { const el = document.getElementById(id); if (el && v !== undefined) el.value = v; };
    sv("imageName", c.imageName); sv("mountPoint", c.mountPoint);
    sv("iscsiPortal", c.iscsiPortal); sv("iscsiPort", c.iscsiPort); sv("iscsiIQN", c.iscsiIQN); sv("iscsiDevice", c.iscsiDevice);
    sv("smbServer", c.smbServer); sv("smbShare", c.smbShare); sv("smbUser", c.smbUser); sv("smbDomain", c.smbDomain); sv("smbVersion", c.smbVersion); sv("smbExtraOpts", c.smbExtraOpts);
    sv("nfsServer", c.nfsServer); sv("nfsExport", c.nfsExport); sv("nfsMountOpts", c.nfsMountOpts); sv("nfsCustomOpts", c.nfsCustomOpts);
    sv("usbDevice", c.usbDevice); sv("usbFsType", c.usbFsType); sv("localPath", c.localPath);
    sv("ntfyTopic", c.ntfyTopic); sv("ntfyServer", c.ntfyServer);
    sv("shutdownMethod", c.shutdownMethod); sv("shutdownFallback", c.shutdownFallback);
    sv("gracePeriod", c.gracePeriod); sv("settleTime", c.settleTime); sv("healthTimeout", c.healthTimeout);
    sv("maxLogLines", c.maxLogLines); sv("logPath", c.logPath); sv("lockFile", c.lockFile); sv("tipiDir", c.tipiDir);
    sv("tipiUser", c.tipiUser); sv("tipiPass", c.tipiPass);
    sv("imageHeadroom", c.imageHeadroom);
    // toggles
    ["ntfyEnabled","notifySuccess","notifyFailure","notifyStart"].forEach(k => {
      if (c[k] !== undefined) {
        S.toggles[k] = c[k];
        const t = document.getElementById("toggle-" + k);
        if (t) { t.classList.toggle("on", c[k]); t.classList.toggle("off", !c[k]); }
      }
    });
    document.getElementById("ntfy-fields").style.opacity = S.toggles.ntfyEnabled ? "1" : "0.4";
    // dest type + secondary dests
    if (c.secondaryDests) S.secondaryDests = c.secondaryDests;
    if (c.destType) {
      const card = document.querySelector(`.dest-card[data-dest="${c.destType}"]`);
      if (card) card.click();
    }
    updateSecondaryLabels();
    if (c.cronDays) {
      S.cronDays = c.cronDays;
      dayGrid.querySelectorAll(".day-btn").forEach((btn, i) => {
        btn.classList.toggle("on",  S.cronDays.includes(i));
        btn.classList.toggle("off", !S.cronDays.includes(i));
      });
    }
    if (c.cronMode) setCronMode(c.cronMode);
    if (c.containerCfg) S.containerCfg = c.containerCfg;
    sv("cronFreq", c.cronFreq); sv("cronHour", c.cronHour); sv("cronMin", c.cronMin); sv("cronCustom", c.customCron);
    buildCron(); updatePreviews();
  } catch(e) { /* first run */ }
}

// ─── Script generation ────────────────────────────────────────────────────────
function generateScript() {
  if (!S.deps["image-backup"]) {
    toast("⚠ image-backup is not installed — use the Install button above first", "err");
    return;
  }
  const c   = collectConfig();
  const mp  = c.mountPoint || "/mnt/backups";
  const img = c.imageName  || "pi_backup.img";
  const mb  = c.imageHeadroom || "5000";
  const containers = S.containers;
  const ccfg       = S.containerCfg;
  const foundations = containers.filter(x => ccfg[x.id]?.priority === "foundation" && ccfg[x.id]?.restartAfter);
  const others      = containers.filter(x => ccfg[x.id]?.priority !== "foundation" && ccfg[x.id]?.restartAfter && x.name !== "runtipi");

  let mountSetup = "";
  if (c.destType === "smb")
    mountSetup = `# Mount SMB (credentials read from /etc/samba/credentials)\nif ! mountpoint -q "${mp}"; then\n  sudo mount -t cifs //${c.smbServer}/${c.smbShare} ${mp} -o "credentials=/etc/samba/credentials,domain=${c.smbDomain},vers=${c.smbVersion},uid=1000,gid=1000"\nfi`;
  else if (c.destType === "nfs")
    mountSetup = `# Mount NFS\nif ! mountpoint -q "${mp}"; then\n  sudo mount -t nfs ${c.nfsServer}:${c.nfsExport} ${mp} -o ${c.nfsMountOpts}\nfi`;
  else if (c.destType === "usb")
    mountSetup = `# Mount USB\nif ! mountpoint -q "${mp}"; then\n  sudo mount -t ${c.usbFsType} ${c.usbDevice} ${mp}\nfi`;
  else if (c.destType === "iscsi")
    mountSetup = `# iSCSI already logged in at boot via /etc/iscsi\nif ! mountpoint -q "${mp}"; then\n  sudo mount ${c.iscsiDevice} ${mp}\nfi`;

  // Build secondary destination sync steps
  const secondaries = (c.secondaryDests || []).filter(dt => dt !== c.destType);
  let secondarySync = "";
  if (secondaries.length > 0) {
    secondarySync = `\n# ── Step 4b: Sync image to secondary destinations ─────────────────────────────`;
    for (const dt of secondaries) {
      let smp = "", smountCmd = "", sunmountCmd = "";
      if (dt === "usb")   { smp = c.usbMountPoint   || "/mnt/usb_secondary";   smountCmd = `sudo mount -t ${c.usbFsType||"ext4"} ${c.usbDevice} "${smp}"`;   sunmountCmd = `sudo umount "${smp}"`; }
      if (dt === "smb")   { smp = c.smbMountPoint   || "/mnt/smb_secondary";   smountCmd = `sudo mount -t cifs //${c.smbServer}/${c.smbShare} "${smp}" -o "credentials=/etc/samba/credentials,domain=${c.smbDomain},vers=${c.smbVersion},uid=1000,gid=1000"`; sunmountCmd = `sudo umount "${smp}"`; }
      if (dt === "nfs")   { smp = c.nfsMountPoint   || "/mnt/nfs_secondary";   smountCmd = `sudo mount -t nfs ${c.nfsServer}:${c.nfsExport} "${smp}" -o ${c.nfsMountOpts}`;   sunmountCmd = `sudo umount "${smp}"`; }
      if (dt === "iscsi") { smp = c.iscsiMountPoint || "/mnt/iscsi_secondary"; smountCmd = `sudo mount ${c.iscsiDevice} "${smp}"`;   sunmountCmd = `sudo umount "${smp}"`; }
      secondarySync += `
echo "$(date): ── Secondary sync: ${dt.toUpperCase()} → ${smp} ──"
sudo mkdir -p "${smp}"
if ! mountpoint -q "${smp}"; then
  ${smountCmd} || { echo "$(date): WARNING - Could not mount secondary ${dt.toUpperCase()}, skipping."; }
fi
if mountpoint -q "${smp}"; then
  rsync -av --progress "$IMAGE_PATH" "$MARKER" "${smp}/" 2>&1 | sed "s/^/$(date): /"
  [ $? -eq 0 ] && echo "$(date): Secondary ${dt.toUpperCase()} sync complete." || echo "$(date): WARNING - rsync to ${dt.toUpperCase()} failed — primary backup is intact."
  ${sunmountCmd} || true
fi`;
    }
  }

  const ntfy = c.ntfyEnabled;
  const tipiCreds = !!(c.tipiUser && c.tipiPass);
  // Build the restart block as a reusable string (called on both success and failure)
  const restartBlock = `
  ${foundations.length ? `docker start ${foundations.map(x=>x.name).join(" ")} 2>&1 | sed "s/^/$(date): /"\n  sleep 20` : ""}
  cd "$TIPI_DIR" && sudo ./runtipi-cli start || echo "$(date): WARNING - runtipi-cli start returned non-zero (containers may still be coming up)"
  HEALTH_WAIT=0
  until [ "$(docker inspect -f '{{.State.Health.Status}}' runtipi 2>/dev/null)" == "healthy" ]; do
      [ "$HEALTH_WAIT" -ge "$TIPI_HEALTH_TIMEOUT" ] && echo "$(date): WARNING - Runtipi health timeout. Manual check required." && break
      sleep 2; HEALTH_WAIT=$(( HEALTH_WAIT + 2 ))
  done
  echo "$(date): Runtipi healthy after \${HEALTH_WAIT}s."
  # Ensure reverse proxy is running — it can be left in Created state if runtipi's
  # health check was slow during compose up (a known timing issue with runtipi-cli start)
  if [ "$(docker inspect -f '{{.State.Status}}' runtipi-reverse-proxy 2>/dev/null)" != "running" ]; then
    echo "$(date): Starting runtipi-reverse-proxy (was not running after runtipi-cli start)..."
    docker start runtipi-reverse-proxy 2>&1 | sed "s/^/$(date): /" || true
  else
    echo "$(date): ✓ runtipi-reverse-proxy already running."
  fi
  sleep 5
  ${tipiCreds ? 'runtipi_login || true' : ''}
  ${others.length ? others.map(x =>
    `smart_start ${x.name}`
  ).join("\n  ") : ""}
  while IFS= read -r _N; do [ -z "$_N" ] && continue; smart_start "$_N"; done <<< "$PRE_BACKUP_CONTAINERS"`;

  const script = `#!/bin/bash
# ==============================================================================
# Pi Backup Script — Generated by SpareCard
# ${new Date().toISOString()}
# ==============================================================================
BACKUP_ROOT="${mp}"
IMAGE_PATH="$BACKUP_ROOT/${img}"
IMAGE_HEADROOM_MB=${mb}
TIPI_DIR="${c.tipiDir||S.defaults.tipiDir}"
LOCK_FILE="${c.lockFile||"/tmp/weekly_image.lock"}"
CRON_LOG="${c.logPath||S.defaults.logPath}"
MAX_LOG_LINES=${c.maxLogLines||2000}
TIPI_HEALTH_TIMEOUT=${c.healthTimeout||120}
${tipiCreds ? `TIPI_USER="${c.tipiUser}"
TIPI_PASS="${c.tipiPass}"` : `TIPI_USER=""
TIPI_PASS=""`}
${ntfy ? `NTFY_URL="${c.ntfyServer||"https://ntfy.sh"}/${c.ntfyTopic||"my_backup"}"` : ""}

# ── Logging ───────────────────────────────────────────────────────────────────
[ -f "$CRON_LOG" ] && LINES=$(wc -l < "$CRON_LOG") && [ "$LINES" -gt "$MAX_LOG_LINES" ] && \\
  tail -n "$MAX_LOG_LINES" "$CRON_LOG" > "\${CRON_LOG}.tmp" && mv "\${CRON_LOG}.tmp" "$CRON_LOG"
exec > >(tee -a "$CRON_LOG") 2>&1

# ── Lock ──────────────────────────────────────────────────────────────────────
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "$(date): Already running. Exit."; exit 1; }

# ── State ─────────────────────────────────────────────────────────────────────
CONTAINERS_STOPPED=0   # set to 1 after containers are brought down

# ── Helpers ───────────────────────────────────────────────────────────────────
${ntfy
  ? `send_notification() {
    tail -n 35 "$CRON_LOG" | sed 's/\\x1b\\[[0-9;]*[a-zA-Z]//g' \\
      | curl -sf -H "Title: $1" -H "Priority: $2" -H "Tags: $3" --data-binary @- "$NTFY_URL" \\
      || echo "$(date): WARNING - ntfy failed."
}
send_simple_notification() {
    echo "$4" | curl -sf -H "Title: $1" -H "Priority: $2" -H "Tags: $3" --data-binary @- "$NTFY_URL" \\
      || echo "$(date): WARNING - ntfy failed."
}`
  : `send_notification() { : ; }
send_simple_notification() { : ; }`}
elapsed_time() { local S=$(( $(date +%s) - START_TIME )); printf "%dh %02dm %02ds" "$((S/3600))" "$(((S%3600)/60))" "$((S%60))"; }

# ── Runtipi API helpers ────────────────────────────────────────────────────────
TIPI_LOGGED_IN=0
_tipi_base_url() {
  # Resolve the runtipi container IP directly — bypasses Traefik which blocks /api/ paths
  local ip
  ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' runtipi 2>/dev/null | awk '{print $1}')
  [ -n "$ip" ] && echo "http://\${ip}:3000" || echo ""
}
runtipi_login() {
  [ -z "$TIPI_USER" ] || [ -z "$TIPI_PASS" ] && return 1
  local url r
  url=$(_tipi_base_url)
  [ -z "$url" ] && { echo "$(date): WARNING - cannot resolve Runtipi container IP for API login"; return 1; }
  r=$(curl -sf -c /tmp/_pbm_tipi_cookies \\
    -X POST "$url/api/auth/login" \\
    -H "Content-Type: application/json" \\
    -d "{\"username\":\"$TIPI_USER\",\"password\":\"$TIPI_PASS\"}" 2>&1)
  if [ $? -eq 0 ]; then
    TIPI_LOGGED_IN=1
    echo "$(date): Runtipi API login successful."
  else
    echo "$(date): WARNING - Runtipi API login failed: $r"
    return 1
  fi
}
runtipi_start_app_by_compose() {
  local compose_file="$1"
  [ "$TIPI_LOGGED_IN" -eq 0 ] && return 1
  local app_id
  app_id=$(echo "$compose_file" | sed -n 's|.*/data/apps/[^/]*/\\([^/]*\\)/.*|\\1|p')
  [ -z "$app_id" ] && return 1
  local url urn
  url=$(_tipi_base_url)
  [ -z "$url" ] && return 1
  urn=$(curl -sf -b /tmp/_pbm_tipi_cookies "$url/api/apps/installed" \\
    | APP_ID="$app_id" python3 -c "
import sys, json, os
app_id = os.environ['APP_ID']
try:
  apps = json.load(sys.stdin).get('installed', [])
  matches = [a['info']['urn'] for a in apps if a['app']['appName'] == app_id]
  print(matches[0] if matches else '')
except: pass" 2>/dev/null)
  if [ -z "$urn" ]; then
    echo "$(date): WARNING - Runtipi API: no installed app with appName='$app_id'"
    return 1
  fi
  echo "$(date): Starting '$app_id' via Runtipi API (URN: $urn)..."
  curl -sf -b /tmp/_pbm_tipi_cookies -X POST "$url/api/app-lifecycle/$urn/start" > /dev/null \\
    && echo "$(date): ✓ Started $app_id via Runtipi API" \\
    || { echo "$(date): WARNING - Runtipi API start failed for $app_id"; return 1; }
}

# smart_start: try docker start → compose up -d → Runtipi API (for /data/apps/ containers)
smart_start() {
  local container="$1" err_file
  [ -z "$container" ] && return 0
  # Skip containers that are already running (e.g. brought up by runtipi-cli start)
  [ "$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)" = "running" ] && return 0
  err_file=$(mktemp /tmp/_pbm_ds_err.XXXXXX)
  if docker start "$container" 2>"$err_file"; then
    echo "$(date): ✓ Started $container"
    rm -f "$err_file"
    return 0
  fi
  local compose_file
  compose_file=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$container" 2>/dev/null | cut -d, -f1)
  if [ -n "$compose_file" ] && [ "$compose_file" != "<no value>" ] && [ -f "$compose_file" ]; then
    local compose_proj compose_dir env_file compose_ok
    compose_proj=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)
    compose_dir=$(dirname "$compose_file")
    # runtipi convention: /data/apps/<store>/<app>/ → /app-data/<store>/<app>/app.env
    env_file="\${compose_dir/\\/data\\/apps\\//\\/app-data\\/}/app.env"
    echo "$(date): $container failed docker start — using compose up -d (project: $compose_proj)"
    echo "$(date):   Compose: $compose_file"
    if [ -f "$env_file" ]; then
      echo "$(date):   Env: $env_file"
      docker compose -f "$compose_file" --env-file "$env_file" up -d 2>&1 | sed "s/^/$(date):   /"
      compose_ok=\${PIPESTATUS[0]}
    else
      docker compose -f "$compose_file" up -d 2>&1 | sed "s/^/$(date):   /"
      compose_ok=\${PIPESTATUS[0]}
    fi
    if [ "\$compose_ok" -ne 0 ]; then
      if [[ "$compose_file" == /data/apps/* ]]; then
        runtipi_start_app_by_compose "$compose_file" \\
          || echo "$(date): WARNING - all start methods failed for $container"
      else
        echo "$(date): WARNING - compose up -d also failed for $container"
      fi
    fi
    rm -f "$err_file"
  else
    echo "$(date): WARNING - could not restart $container: $(head -2 "$err_file" 2>/dev/null)"
    rm -f "$err_file"
  fi
}

restart_containers() {
  echo "$(date): ── Restarting all services ──────────────────────────────────────────"
  ${restartBlock}
  echo "$(date): ── Services restart complete ─────────────────────────────────────────"
}

fail_exit() {
  echo "$(date): FATAL - $1"
  send_notification "Backup FAILED - $1" "high" "x,warning"
  if [ "$CONTAINERS_STOPPED" -eq 1 ]; then
    echo "$(date): Containers were stopped — attempting restart before exit..."
    restart_containers || true
  fi
  flock -u 9; exit 1
}

# ── Auto-resize image (runs BEFORE containers are stopped) ────────────────────
auto_resize_image() {
  local img="$1"
  local extra_mb="$2"
  [ -f "$img" ] || return 0   # no image yet — fresh run, skip

  echo "$(date): Checking image capacity..."
  local src_used_mb
  src_used_mb=$(df -BM --output=used / | tail -1 | tr -d 'M ')

  # Detach any stale loop device already pointing at this image
  sudo losetup -j "$img" 2>/dev/null | cut -d: -f1 | xargs -r sudo losetup -d 2>/dev/null

  # Attach image to read its total partition capacity
  local loop
  loop=$(sudo losetup -fP --show "$img" 2>/dev/null) || {
    echo "$(date): WARNING - could not attach image for size check, skipping auto-resize"
    return 0
  }
  local image_total_mb
  image_total_mb=$(sudo df -BM --output=size "\${loop}p2" 2>/dev/null | tail -1 | tr -d 'M ') || true
  sudo losetup -d "$loop" 2>/dev/null

  if [ -z "$image_total_mb" ]; then
    echo "$(date): WARNING - could not read image capacity, skipping auto-resize"
    return 0
  fi

  # Image must hold all source data plus the configured headroom
  local needed_mb=$(( src_used_mb + extra_mb ))
  echo "$(date): Source used: \${src_used_mb}MB | Image capacity: \${image_total_mb}MB | Needed: \${needed_mb}MB"

  if [ "$image_total_mb" -ge "$needed_mb" ]; then
    echo "$(date): ✓ Image has sufficient capacity (\${image_total_mb}MB >= \${needed_mb}MB)"
    return 0
  fi

  # Grow to cover the gap plus a 10% safety buffer
  local grow_mb=$(( needed_mb - image_total_mb + (extra_mb / 10) ))
  echo "$(date): ⚠ Image too small (\${image_total_mb}MB < \${needed_mb}MB) — growing by \${grow_mb}MB..."

  sudo truncate -s "+\${grow_mb}M" "$img" || {
    echo "$(date): ERROR - failed to expand image file (check destination disk space)"
    return 1
  }

  # Detach stale loop again before re-attaching for resize
  sudo losetup -j "$img" 2>/dev/null | cut -d: -f1 | xargs -r sudo losetup -d 2>/dev/null

  local loop2
  loop2=$(sudo losetup -fP --show "$img" 2>/dev/null) || {
    echo "$(date): ERROR - could not re-attach image for resize"
    return 1
  }

  echo "$(date): Resizing partition and filesystem..."
  sudo parted -s "$loop2" resizepart 2 100% 2>&1 | sed "s/^/$(date):   /"
  sudo partprobe "$loop2" 2>/dev/null; sleep 1
  sudo e2fsck -fy "\${loop2}p2" 2>&1 | tail -8 | sed "s/^/$(date):   /"
  sudo resize2fs "\${loop2}p2" 2>&1 | sed "s/^/$(date):   /"
  sudo losetup -d "$loop2" 2>/dev/null

  echo "$(date): ✓ Image resized — grew by \${grow_mb}MB. New capacity will reflect after next mount."
  return 0
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
echo "$(date): ============================================================"
echo "$(date): --- Weekly Image Backup: $(date) ---"
echo "$(date): Pi Backup Starting"
echo "$(date): ============================================================"
START_TIME=$(date +%s)
${mountSetup}
mountpoint -q "$BACKUP_ROOT" || fail_exit "$BACKUP_ROOT not mounted."
[ -x /usr/local/sbin/image-backup ] || fail_exit "image-backup not found."

SENTINEL="$BACKUP_ROOT/.image_initialised"

# Safety check: sentinel exists but image file is missing — stale sentinel (e.g. image renamed).
# Reset to fresh init rather than crashing mid-backup with containers stopped.
if [ -f "$SENTINEL" ] && [ ! -f "$IMAGE_PATH" ]; then
  echo "$(date): WARNING - Sentinel found but image file missing ($IMAGE_PATH)."
  echo "$(date): Removing stale sentinel — next run will do a fresh initialisation."
  rm -f "$SENTINEL"
fi

# Ownership guard: never touch an existing image this host didn't write.
# The marker is written after every successful backup; adopt a pre-existing
# image from the SpareCard Destination tab (or change the image name).
MARKER="$IMAGE_PATH.sparecard.json"
if [ -f "$IMAGE_PATH" ]; then
  if [ ! -f "$MARKER" ] || ! grep -qF "\\"hostname\\": \\"$(hostname)\\"" "$MARKER"; then
    OWNER=$(grep -o '"hostname": "[^"]*"' "$MARKER" 2>/dev/null | cut -d'"' -f4)
    fail_exit "$IMAGE_PATH already exists but is not marked as this host's backup (owner: \${OWNER:-unknown}). Refusing to overwrite — adopt it from the SpareCard Destination tab, or change the image name. No containers were stopped."
  fi
fi

# Auto-resize check — BEFORE stopping any containers
# If the image is too small it will be grown here; if resize fails we abort cleanly
if [ -f "$SENTINEL" ] && [ -f "$IMAGE_PATH" ]; then
  auto_resize_image "$IMAGE_PATH" "$IMAGE_HEADROOM_MB" || \\
    fail_exit "Image auto-resize failed — aborting. Containers are still running."
fi

${ntfy && c.notifyStart ? `send_simple_notification "Pi Backup Started" "default" "hourglass_flowing_sand" "Backup started at $(date)"` : ""}

# ── Step 1: Snapshot ──────────────────────────────────────────────────────────
PRE_BACKUP_CONTAINERS=$(docker ps --format '{{.Names}}' | grep -v '^runtipi$')
echo "$(date): Running: $(echo "$PRE_BACKUP_CONTAINERS" | tr '\\n' ' ')"

# ── Step 2: Stop ──────────────────────────────────────────────────────────────
cd "$TIPI_DIR" && sudo ./runtipi-cli stop || echo "$(date): WARNING - runtipi-cli stop failed."

# ── Step 3: Settle ────────────────────────────────────────────────────────────
docker ps -q | xargs -r docker stop 2>&1 | sed "s/^/$(date): /"
CONTAINERS_STOPPED=1
sync; sleep ${c.settleTime||3}; sync
sudo umount -lf /tmp/img-backup-mnt 2>/dev/null || true
sudo rm -rf /tmp/img-backup-mnt

# ── Step 4: Backup (sentinel-based first-run detection) ───────────────────────
echo "$(date): ============================================================"
echo "$(date): STARTING IMAGE CREATION"
echo "$(date): ============================================================"
if [ ! -f "$SENTINEL" ]; then
    echo "$(date): First run — initialising with -i flag..."
    sudo /usr/local/sbin/image-backup -i "$IMAGE_PATH,,\${IMAGE_HEADROOM_MB}"
    BACKUP_EXIT=$?
    [ "$BACKUP_EXIT" -eq 0 ] && sudo touch "$SENTINEL" && echo "$(date): Sentinel created."
else
    echo "$(date): Incremental backup..."
    sudo /usr/local/sbin/image-backup "$IMAGE_PATH"
    BACKUP_EXIT=$?
fi

# ── Step 5: Check result — restart containers regardless of outcome ────────────
if [ "$BACKUP_EXIT" -ne 0 ]; then
    DURATION=$(elapsed_time)
    echo "$(date): ERROR - image-backup exit $BACKUP_EXIT"
    ${ntfy && c.notifyFailure ? `send_notification "Backup FAILED ($DURATION) exit $BACKUP_EXIT" "high" "x,warning"` : ""}
    echo "$(date): Restarting containers after failed backup..."
    restart_containers || true
    flock -u 9; exit "$BACKUP_EXIT"
fi

# Record ownership so future runs (and other Pis) know this image is ours
printf '{"hostname": "%s", "lastBackup": %s}\\n' "$(hostname)" "$(date +%s)" | sudo tee "$MARKER" > /dev/null \\
  && echo "$(date): Ownership marker updated." \\
  || echo "$(date): WARNING - could not write ownership marker ($MARKER)."
${secondarySync}
# ── Step 6: Restart ───────────────────────────────────────────────────────────
echo "$(date): BACKUP SUCCESSFUL — restarting..."
restart_containers

# ── Done ──────────────────────────────────────────────────────────────────────
DURATION=$(elapsed_time)
echo "$(date): All done. Total elapsed: $DURATION"
${ntfy && c.notifySuccess ? `send_notification "Backup Success ($DURATION)" "default" "white_check_mark,floppy_disk"` : ""}
flock -u 9; exit 0
`;

  S.generatedScript = script;
  document.getElementById("script-card-title").textContent = "Generated Script";
  document.getElementById("script-out").textContent = script;
  document.getElementById("script-card").style.display = "";
  document.getElementById("btn-copy").style.display   = "";
  document.getElementById("btn-write").style.display  = "";
  document.getElementById("write-status").style.display = "none";
  toast("Script generated");
}

function copyScript() {
  _copyText(S.generatedScript);
  toast("Script copied to clipboard");
}

async function writeScript() {
  if (!S.generatedScript) return;
  spin("write-sp", true);
  try {
    const r = await fetch("/api/script", { method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ script: S.generatedScript, path: S.defaults.scriptPath }) });
    const d = await r.json();
    if (!d.ok) throw new Error(d.error);
    const el = document.getElementById("write-status");
    el.style.display = "";
    el.innerHTML = `<div class="info green">✅ Written to ${esc(d.path)} and made executable.</div>`;
    toast("Script saved to disk");
  } catch(e) { toast(e.message, "err"); }
  spin("write-sp", false);
}

async function viewScript() {
  try {
    const r = await fetch("/api/script?path=" + encodeURIComponent(S.defaults.scriptPath));
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "Script not found");
    document.getElementById("script-card-title").textContent = "Script on Disk";
    document.getElementById("script-out").textContent = d.script;
    document.getElementById("script-card").style.display = "";
    document.getElementById("btn-copy").style.display    = "";
    document.getElementById("btn-write").style.display   = "none";
    document.getElementById("write-status").style.display = "none";
    S.generatedScript = d.script;
    toast("Loaded script from " + d.path);
  } catch(e) {
    toast("⚠ " + e.message, "err");
  }
}

// ─── Manual backup run ────────────────────────────────────────────────────────
const PHASE_KEYWORDS = [
  "STARTING IMAGE CREATION",
  "BACKUP SUCCESSFUL",
  "Runtipi healthy",
  "All done"
];

function updatePhase(phase) {
  S.runPhase = phase;
  const colors = ["var(--orange)","var(--cyan)","var(--purple)","var(--green)"];
  const labels = ["Stopping…","Image…","Restarting…","Done ✓"];
  for (let i = 0; i < 4; i++) {
    const done = phase > i;
    const active = phase === i;
    $c("ph"+i).style.background  = (done||active) ? colors[i] : "var(--border)";
    $c("phl"+i).style.color = (done||active) ? colors[i] : "var(--muted)";
    $c("phl"+i).style.fontWeight = (done||active) ? "700" : "400";
  }
  const lbl = $c("phase-lbl");
  const dot = $c("phase-dot");
  const pst = $c("phase-status");
  if (phase >= 0 && phase < 4) {
    pst.style.display = "";
    lbl.textContent = labels[phase];
    lbl.style.color = colors[phase];
    dot.style.background = colors[phase];
    dot.style.boxShadow = `0 0 6px ${colors[phase]}`;
  } else { pst.style.display = "none"; }
}

function appendRunLog(msg, type) {
  const box = $c("run-log");
  const wrapper = document.createElement("div");
  wrapper.innerHTML = termLine(msg, type);
  box.appendChild(wrapper.firstChild);
  trimTermBox(box);
  box.scrollTop = box.scrollHeight;
}

let _runElapsedTimer = null;

async function startBackup() {
  document.getElementById("confirm-panel").style.display = "none";
  // Ownership pre-flight: the script refuses foreign images, so resolve it here
  // with an explicit adopt instead of a mid-run failure
  try {
    const own = await (await fetch("/api/image/ownership")).json();
    if (own.imageExists && !own.ours) {
      const who = own.markerExists ? `was last written by '${own.markerHost}'` : "has no SpareCard ownership marker";
      if (!confirm(`${own.path} already exists and ${who}.\n\nThe backup updates this file in place, overwriting its contents. Adopt it as this Pi's image and continue?`)) return;
      const ad = await (await fetch("/api/image/adopt", { method:"POST", headers:{"Content-Type":"application/json"}, body:"{}" })).json();
      if (!ad.ok) { toast(ad.error || "Adopt failed", "err"); return; }
    }
  } catch(e) {}
  S.backupRunning = true;
  S.runPhase = -1;
  document.getElementById("run-log").innerHTML = "";
  document.getElementById("run-log").dataset.expanded = "";
  document.getElementById("run-log").style.maxHeight = "340px";
  document.getElementById("run-log-wrap").style.display = "";
  document.getElementById("run-result-box").style.display = "none";
  document.getElementById("phase-bar").style.display = "";
  document.getElementById("phase-status").style.display = "";
  document.getElementById("run-btn").disabled = true;
  document.getElementById("live-dot").style.display = "inline";
  document.getElementById("clear-btn").style.display = "none";
  document.getElementById("run-result-badge").style.display = "none";
  updatePhase(0);

  // Elapsed timer
  const startTs = Date.now();
  const elapsedEl = document.getElementById("run-elapsed");
  if (elapsedEl) elapsedEl.textContent = "";
  clearInterval(_runElapsedTimer);
  _runElapsedTimer = setInterval(() => {
    const s = Math.floor((Date.now() - startTs) / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    if (elapsedEl) elapsedEl.textContent = h
      ? `${h}h ${String(m).padStart(2,"0")}m ${String(sec).padStart(2,"0")}s`
      : m ? `${m}m ${String(sec).padStart(2,"0")}s` : `${sec}s`;
  }, 1000);

  try {
    const r = await fetch("/api/backup/run", { method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ scriptPath: S.defaults.scriptPath }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);

    const es = new EventSource("/api/backup/stream");
    es.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === "log") {
        appendRunLog(msg.msg, msg.msg.startsWith("$") ? "cmd" : "info");
      } else if (msg.type === "phase") {
        updatePhase(msg.phase);
      } else if (msg.type === "done") {
        es.close();
        finishRun(msg.result);
      }
    };
    es.onerror = () => { es.close(); finishRun("failed"); };
  } catch(e) {
    appendRunLog(e.message, "err");
    finishRun("failed");
  }
}

function finishRun(result) {
  clearInterval(_runElapsedTimer);
  _runElapsedTimer = null;
  S.backupRunning = false;
  document.getElementById("run-btn").disabled = false;
  document.getElementById("live-dot").style.display = "none";
  document.getElementById("clear-btn").style.display = "";
  updatePhase(result === "success" ? 4 : S.runPhase);
  document.getElementById("phase-status").style.display = "none";

  const badge = document.getElementById("run-result-badge");
  badge.style.display = "";
  badge.className = `badge ${result === "success" ? "green" : "red"}`;
  badge.innerHTML = `<span class="dot"></span>${result === "success" ? "Last run: success" : "Last run: failed"}`;

  const box = document.getElementById("run-result-box");
  box.style.display = "";
  box.innerHTML = `<div class="info ${result==="success"?"green":"red"}">${result === "success"
    ? "✅ Backup completed successfully. All containers restored."
    : "❌ Backup failed. Containers may still be stopped — check log for details."}</div>`;
  loadLastBackup();
  if (result === "success") checkImageStatus();
}

function clearRunLog() {
  document.getElementById("run-log").innerHTML = "";
  document.getElementById("run-log-wrap").style.display = "none";
  document.getElementById("phase-bar").style.display = "none";
  document.getElementById("run-result-box").style.display = "none";
  document.getElementById("run-result-badge").style.display = "none";
  document.getElementById("clear-btn").style.display = "none";
  S.runPhase = -1;
}

// ─── Dependencies ─────────────────────────────────────────────────────────────
const DEST_DEPS = {
  iscsi:  [{bins:["iscsiadm"],              pkg:"open-iscsi", label:"open-iscsi"}],
  smb:    [{bins:["mount.cifs"],            pkg:"cifs-utils", label:"cifs-utils"},
           {bins:["smbclient"],             pkg:"smbclient",  label:"smbclient"}],
  nfs:    [{bins:["showmount","mount.nfs"], pkg:"nfs-common", label:"nfs-common"}],
  usb:    [],
  local:  [],
};

async function loadDeps() {
  try {
    const r = await fetch("/api/deps/check");
    S.deps = await r.json();
    // image-backup status cards in generate tab
    const installed = !!S.deps["image-backup"];
    const missing = document.getElementById("imgbak-missing-card");
    const ok      = document.getElementById("imgbak-ok-card");
    if (missing) missing.style.display = installed ? "none" : "";
    if (ok)      ok.style.display      = installed ? ""     : "none";
    // disable Run Backup button if image-backup missing
    const runBtn = document.getElementById("run-btn");
    if (runBtn) {
      runBtn.disabled = !installed;
      runBtn.title    = installed ? "" : "image-backup is not installed — see the Generate tab to install it";
    }
    // refresh banner for current dest
    checkDestDeps(S.destType);
  } catch {}
}

// ─── image-backup guided install ──────────────────────────────────────────────
function openImgbakModal(update) {
  const modal = document.getElementById("imgbak-modal");
  document.getElementById("imgbak-modal-title").textContent = update ? "Updating image-backup…" : "Installing image-backup…";
  document.getElementById("imgbak-log").innerHTML = "";
  document.getElementById("imgbak-result").style.display = "none";
  document.getElementById("imgbak-modal-close").disabled  = true;
  document.getElementById("imgbak-modal-close2").disabled = true;
  ["ib-step1","ib-step2","ib-step3","ib-step4"].forEach(id => {
    document.getElementById(id+"-track").style.background = "var(--border)";
    document.getElementById(id+"-lbl").style.color = "var(--muted)";
  });
  modal.style.display = "flex";

  fetch("/api/imgbak/install", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({update}) })
    .then(r => r.json())
    .then(d => {
      if (!d.ok) { appendImgbakLog(d.error || "Failed to start", "err"); finishImgbak("failed"); return; }
      const es = new EventSource("/api/imgbak/stream");
      es.onmessage = e => {
        const msg = JSON.parse(e.data);
        if (msg.type === "ping" || msg.type === "connected") return;
        if (msg.type === "log") {
          appendImgbakLog(msg.msg, msg.level);
          updateImgbakSteps(msg.msg);
        }
        if (msg.type === "done") {
          es.close();
          finishImgbak(msg.result);
        }
      };
      es.onerror = () => { es.close(); finishImgbak("failed"); };
    })
    .catch(e => { appendImgbakLog(e.message, "err"); finishImgbak("failed"); });
}

function appendImgbakLog(msg, level) {
  const box = $c("imgbak-log");
  const cls = level === "cmd" ? "t-cmd" : level === "ok" ? "t-ok" : level === "err" ? "t-err" : level === "warn" ? "t-warn" : "t-info";
  const prefix = level === "cmd" ? "$" : level === "ok" ? "✓" : level === "err" ? "✗" : level === "warn" ? "!" : " ";
  const el = document.createElement("div");
  el.className = "term-line";
  el.innerHTML = `<span class="term-prefix ${cls}">${prefix}</span><span class="${cls}">${esc(msg)}</span>`;
  box.appendChild(el);
  trimTermBox(box);
  box.scrollTop = box.scrollHeight;
}

function updateImgbakSteps(msg) {
  const steps = [
    ["ib-step1", ["Checking for git","git found","git installed"]],
    ["ib-step2", ["Cloning","Updating existing","Clone complete","updated"]],
    ["ib-step3", ["Installing image-"]],
    ["ib-step4", ["Verifying","image-backup installed"]],
  ];
  steps.forEach(([id, keywords]) => {
    if (keywords.some(k => msg.includes(k))) {
      $c(id+"-track").style.background = "var(--accent)";
      $c(id+"-lbl").style.color = "var(--accent)";
    }
  });
}

function finishImgbak(result) {
  const success = result === "success";
  ["ib-step1","ib-step2","ib-step3","ib-step4"].forEach(id => {
    $c(id+"-track").style.background = success ? "var(--green)" : "var(--red)";
    $c(id+"-lbl").style.color        = success ? "var(--green)" : "var(--red)";
  });
  const res = document.getElementById("imgbak-result");
  res.innerHTML = success
    ? `<div class="info green">✅ image-backup installed successfully! You can now generate and run backups.</div>`
    : `<div class="info red">❌ Installation failed. Check the log above for details.</div>`;
  res.style.display = "";
  document.getElementById("imgbak-modal-title").textContent = success ? "Installation complete" : "Installation failed";
  document.getElementById("imgbak-modal-close").disabled  = false;
  document.getElementById("imgbak-modal-close2").disabled = false;
  if (success) loadDeps(); // refresh status cards + re-enable Run Backup
}

function checkDestDeps(destType) {
  ["iscsi","smb","nfs","usb","local"].forEach(d => {
    const b = document.getElementById(`dep-banner-${d}`);
    if (b) b.style.display = "none";
  });
  if (!S.deps || !Object.keys(S.deps).length) return;
  const banner = document.getElementById(`dep-banner-${destType}`);
  if (!banner) return;
  const needed  = DEST_DEPS[destType] || [];
  const missing = needed.filter(dep => dep.bins.some(b => !S.deps[b]));
  if (!missing.length) return;
  const pkgs = [...new Set(missing.map(d => d.pkg))];
  const pkgHtml = pkgs.map(p =>
    `<code style="color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 6px;border-radius:3px">${p}</code>`
  ).join(" ");
  banner.style.display = "";
  banner.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
      <div>
        <strong style="color:var(--orange);font-size:13px">⚠ Missing ${pkgs.length > 1 ? "packages" : "package"}</strong>
        <div style="font-size:12px;color:var(--text);margin-top:4px;line-height:1.6">
          ${pkgHtml} ${pkgs.length > 1 ? "are" : "is"} required for this destination but not installed.
        </div>
      </div>
      <button class="btn sm" style="background:rgba(245,158,11,.15);color:var(--orange);border-color:rgba(245,158,11,.6);white-space:nowrap"
        data-action="open-install-modal" data-pkgs="${esc(JSON.stringify(pkgs))}">📦 Install now</button>
    </div>`;
}

function openInstallModal(pkgs) {
  document.getElementById("install-log").innerHTML = "";
  document.getElementById("install-result").style.display = "none";
  document.getElementById("install-title").textContent = `Installing: ${pkgs.join(", ")}`;
  document.getElementById("install-modal").style.display = "flex";
  installNext(pkgs, 0);
}

async function installNext(pkgs, idx) {
  if (idx >= pkgs.length) {
    await loadDeps();
    const res = document.getElementById("install-result");
    res.style.display = "";
    res.innerHTML = '<div class="info green">✅ All packages installed successfully.</div>';
    return;
  }
  appendLog("install-log", `Installing ${pkgs[idx]}…`, "cmd");
  try {
    const r = await fetch("/api/deps/install", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({package: pkgs[idx]})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    const es = new EventSource("/api/deps/stream");
    es.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === "log" && msg.msg) appendLog("install-log", msg.msg, "info");
      else if (msg.type === "done") {
        es.close();
        if (msg.result === "success") {
          appendLog("install-log", `✓ ${pkgs[idx]} installed`, "ok");
          installNext(pkgs, idx + 1);
        } else {
          appendLog("install-log", `✗ Failed to install ${pkgs[idx]} (exit ${msg.code})`, "err");
          const res = document.getElementById("install-result");
          res.style.display = "";
          res.innerHTML = '<div class="info red">❌ Installation failed. Check the log above.</div>';
        }
      }
    };
    es.onerror = () => { es.close(); appendLog("install-log", "Connection lost", "err"); };
  } catch(e) {
    appendLog("install-log", e.message, "err");
  }
}

// ─── Verify ───────────────────────────────────────────────────────────────────
async function startVerify() {
  document.getElementById("verify-log").innerHTML = "";
  document.getElementById("verify-log-wrap").style.display = "";
  document.getElementById("verify-result-box").style.display = "none";
  document.getElementById("verify-result-badge").style.display = "none";
  document.getElementById("verify-btn").disabled = true;
  document.getElementById("verify-live-dot").style.display = "inline";
  document.getElementById("verify-clear-btn").style.display = "none";

  const vip = document.getElementById("verifyImagePath");
  const imagePath = (vip && vip.value.trim()) || `${getMountPoint()}/${getImageName()}`;
  try {
    const r = await fetch("/api/verify/run", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ imagePath })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);

    const es = new EventSource("/api/verify/stream");
    es.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === "log") {
        const lvl = msg.level || "info";
        appendLog("verify-log", msg.msg, lvl);
      } else if (msg.type === "done") {
        es.close();
        finishVerify(msg.result);
      }
    };
    es.onerror = () => { es.close(); finishVerify("failed"); };
  } catch(e) {
    appendLog("verify-log", e.message, "err");
    finishVerify("failed");
  }
}

function finishVerify(result) {
  document.getElementById("verify-btn").disabled = false;
  document.getElementById("verify-live-dot").style.display = "none";
  document.getElementById("verify-clear-btn").style.display = "";

  const badge = document.getElementById("verify-result-badge");
  badge.style.display = "";
  const cls   = result === "success" ? "green" : result === "warning" ? "orange" : "red";
  const label = result === "success" ? "Clean" : result === "warning" ? "Warnings — see log" : "Errors found";
  badge.className = `badge ${cls}`;
  badge.innerHTML = `<span class="dot"></span>${label}`;

  const msgs = {
    success: "✅ Both partitions verified clean. Image is good to restore.",
    warning: "⚠️ fsck found minor issues (likely journal state from live backup). Image should still restore correctly — boot will replay the journal.",
    failed:  "❌ Verification failed or errors found. Check the log above for details."
  };
  const box = document.getElementById("verify-result-box");
  box.style.display = "";
  box.innerHTML = `<div class="info ${result==="success"?"green":result==="warning"?"orange":"red"}">${msgs[result]||msgs.failed}</div>`;
}

function clearVerifyLog() {
  document.getElementById("verify-log").innerHTML = "";
  document.getElementById("verify-log-wrap").style.display = "none";
  document.getElementById("verify-result-box").style.display = "none";
  document.getElementById("verify-result-badge").style.display = "none";
  document.getElementById("verify-clear-btn").style.display = "none";
}

// ─── Compact image ─────────────────────────────────────────────────────────────
let _compactSSE = null;
let _compactBannerDismissed = false;

async function checkImageStatus() {
  const btn = document.getElementById("compact-check-btn");
  if (btn) btn.textContent = "↻ Checking…";
  try {
    const r = await fetch("/api/image-status");
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    renderImageStats(d);
  } catch(e) {
    toast("Could not fetch image status: " + e, "err");
  } finally {
    if (btn) btn.textContent = "↻ Refresh Stats";
  }
}

function renderImageStats(d) {
  const statsEl = document.getElementById("compact-stats");
  if (!d.exists) { statsEl.style.display = "none"; return; }
  statsEl.style.display = "";
  document.getElementById("cstat-logical").textContent = d.logical_mb.toLocaleString() + " MB";
  document.getElementById("cstat-sparse").textContent  = d.sparse_mb.toLocaleString()  + " MB";
  document.getElementById("cstat-source").textContent  = d.source_used_mb.toLocaleString() + " MB";
  const wastedEl  = document.getElementById("cstat-wasted");
  const badgeEl   = document.getElementById("compact-wasted-badge");
  const bannerEl  = document.getElementById("compact-banner");
  const bannerMsg = document.getElementById("compact-banner-msg");
  if (d.compact_recommended) {
    wastedEl.innerHTML = `<span style="color:var(--orange)">⚠ ~${d.wasted_mb.toLocaleString()} MB could be reclaimed by compacting</span>`;
    badgeEl.style.display = "";
    badgeEl.textContent   = `⚠ ~${d.wasted_mb.toLocaleString()} MB recoverable`;
    if (!_compactBannerDismissed) {
      bannerEl.style.display = "";
      bannerMsg.textContent = `image is ${d.logical_mb.toLocaleString()} MB logical but source only uses ${d.source_used_mb.toLocaleString()} MB — ~${d.wasted_mb.toLocaleString()} MB recoverable`;
    }
  } else {
    badgeEl.style.display  = "none";
    bannerEl.style.display = "none";
    wastedEl.innerHTML = d.exists
      ? `<span style="color:var(--green)">✓ Image is well-sized — no compaction needed</span>` : "";
  }
}

function dismissCompactBanner() {
  _compactBannerDismissed = true;
  document.getElementById("compact-banner").style.display = "none";
}

const _CL_IDS = ["cl-sentinel","cl-lock","cl-compact-tmp","cl-image"];
function clToggleAll(checked) {
  _CL_IDS.forEach(id => { document.getElementById(id).checked = checked; });
}
function clSyncAll() {
  const all = document.getElementById("cl-all");
  if (all) all.checked = _CL_IDS.every(id => document.getElementById(id).checked);
}
async function runCleanup() {
  const targets = [];
  if (document.getElementById("cl-sentinel").checked)    targets.push("sentinel");
  if (document.getElementById("cl-lock").checked)        targets.push("lock");
  if (document.getElementById("cl-compact-tmp").checked) targets.push("compact_tmp");
  if (document.getElementById("cl-image").checked) {
    if (!confirm("Permanently delete the backup image file? This cannot be undone.")) return;
    targets.push("image");
  }
  if (!targets.length) { toast("Nothing selected", "warn"); return; }
  const statusEl = document.getElementById("cleanup-status");
  statusEl.textContent = "Working…";
  try {
    const r = await fetch("/api/cleanup", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ targets })
    });
    const j = await r.json();
    if (!r.ok) { toast(j.error || "Cleanup failed", "err"); statusEl.textContent = ""; return; }
    const summary = Object.entries(j.results).map(([k,v]) => `${k}: ${v}`).join(" · ");
    statusEl.textContent = "✓ " + summary;
    // uncheck all
    ["cl-all","cl-sentinel","cl-lock","cl-compact-tmp","cl-image"].forEach(id => {
      document.getElementById(id).checked = false;
    });
    toast("Cleanup complete", "ok");
  } catch(e) { toast(e.message, "err"); statusEl.textContent = ""; }
}

function clearCompactLog() {
  document.getElementById("compact-log").innerHTML = "";
  document.getElementById("compact-log-wrap").style.display = "none";
  document.getElementById("compact-clear-btn").style.display = "none";
  document.getElementById("compact-result-box").style.display = "none";
  document.getElementById("compact-result-badge").style.display = "none";
}

async function startCompact() {
  if (_compactSSE) { _compactSSE.close(); _compactSSE = null; }
  const vip = document.getElementById("verifyImagePath");
  const imagePath = (vip && vip.value.trim()) ||
    (getMountPoint().replace(/\/$/, "") + "/" + getImageName());

  const logEl    = document.getElementById("compact-log");
  const wrapEl   = document.getElementById("compact-log-wrap");
  const btn      = document.getElementById("compact-btn");
  const spinner  = document.getElementById("compact-spinner");
  const dotEl    = document.getElementById("compact-live-dot");
  const resBox   = document.getElementById("compact-result-box");
  const resBadge = document.getElementById("compact-result-badge");

  logEl.innerHTML = "";
  wrapEl.style.display = "";
  resBox.style.display = resBadge.style.display = "none";
  document.getElementById("compact-clear-btn").style.display = "none";
  btn.disabled = true;
  spinner.style.display = dotEl.style.display = "";

  try {
    const r = await fetch("/api/compact/run", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ imagePath })
    });
    if (!r.ok) {
      const e = await r.json();
      toast(e.error || "Failed to start compact", "err");
      btn.disabled = false; spinner.style.display = dotEl.style.display = "none";
      return;
    }
  } catch(e) {
    toast("Network error: " + e, "err");
    btn.disabled = false; spinner.style.display = dotEl.style.display = "none";
    return;
  }

  _compactSSE = new EventSource("/api/compact/stream");
  _compactSSE.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "log") {
      appendLog("compact-log", msg.msg, msg.level || "info");
    } else if (msg.type === "done") {
      _compactSSE.close(); _compactSSE = null;
      btn.disabled = false; spinner.style.display = dotEl.style.display = "none";
      document.getElementById("compact-clear-btn").style.display = "";
      const ok = msg.result === "success";
      resBox.style.display = "";
      resBox.innerHTML = ok
        ? `<div class="info green">✓ Compact complete${msg.saved_mb > 0 ? ` — reclaimed ~${msg.saved_mb.toLocaleString()} MB` : ''}</div>`
        : `<div class="info red">✗ Compact failed — check output above</div>`;
      resBadge.style.display = "";
      resBadge.className = "badge " + (ok ? "green" : "red");
      resBadge.textContent = ok ? "Compacted" : "Failed";
      if (ok) { _compactBannerDismissed = true; checkImageStatus(); }
    }
  };
  _compactSSE.onerror = () => {
    _compactSSE.close(); _compactSSE = null;
    btn.disabled = false; spinner.style.display = dotEl.style.display = "none";
  };
}

// ─── Last backup status ───────────────────────────────────────────────────────
function _timeAgo(ts) {
  if (!ts) return null;
  const secs = Math.floor(Date.now() / 1000) - ts;
  if (secs < 60)    return "just now";
  if (secs < 3600)  return `${Math.floor(secs/60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs/3600)}h ago`;
  return `${Math.floor(secs/86400)}d ago`;
}

async function loadLastBackup() {
  try {
    const r = await fetch("/api/backup/last");
    const d = await r.json();
    const badge = document.getElementById("last-backup-badge");
    const txt   = document.getElementById("last-backup-txt");
    if (d.running) {
      badge.className = "badge blue";
      txt.textContent = "Running…";
      return;
    }
    if (!d.result) {
      badge.className = "badge muted";
      txt.textContent = "No backup yet";
      return;
    }
    const ok   = d.result === "success";
    const ago  = _timeAgo(d.finished_ts);
    const parts = [ok ? "✓ success" : "✗ failed"];
    if (d.elapsed) parts.push(d.elapsed);
    if (ago)       parts.push(ago);
    badge.className = `badge ${ok ? "green" : "red"}`;
    txt.textContent = parts.join(" · ");
    if (d.finished) badge.title = `Finished: ${d.finished}`;
  } catch {}
}

function showLastBackupModal() {
  const modal = document.getElementById("last-backup-modal");
  document.getElementById("lbm-content").innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  modal.style.display = "flex";
  fetch("/api/backup/last").then(r => r.json()).then(d => {
    const ok = d.result === "success";
    const cls = d.result === "success" ? "green" : d.result === "failed" ? "red" : "muted";
    let html = `<div class="g2" style="margin-bottom:18px">`;
    html += `<div><div class="lbl">Result</div><div style="margin-top:6px"><span class="badge ${cls}"><span class="dot"></span>${esc(d.result || "Unknown")}</span></div></div>`;
    if (d.elapsed) html += `<div><div class="lbl">Duration</div><div style="margin-top:6px;color:var(--bright);font-size:13px;font-weight:600">${esc(d.elapsed)}</div></div>`;
    html += `</div>`;
    if (d.started)  html += `<div class="field"><div class="lbl">Started</div><div style="color:var(--text);font-size:12px;margin-top:4px">${esc(d.started)}</div></div>`;
    if (d.finished) html += `<div class="field"><div class="lbl">Finished</div><div style="color:var(--text);font-size:12px;margin-top:4px">${esc(d.finished)}</div></div>`;
    if (d.log_lines && d.log_lines.length) {
      html += `<div class="lbl" style="margin-bottom:8px;margin-top:4px">Log</div><div class="term-box" style="max-height:320px;overflow-y:auto">`;
      for (const line of d.log_lines) {
        const msg = line.replace(/^[^\:]+:\s*/, "");
        const type = /ERROR|FATAL/.test(line) ? "err"
          : /WARNING/.test(line) ? "warn"
          : /All done|SUCCESSFUL|healthy/.test(line) ? "ok"
          : /====|Step [0-9]/.test(line) ? "cmd"
          : "info";
        html += termLine(msg, type);
      }
      html += `</div>`;
    }
    if (!d.result && !d.running) {
      html = `<div class="info blue">No completed backup found in the log file.</div>`;
    }
    document.getElementById("lbm-content").innerHTML = html;
  }).catch(() => {
    document.getElementById("lbm-content").innerHTML = '<div class="info red">Failed to load backup details.</div>';
  });
}

// ─── System info ──────────────────────────────────────────────────────────────
async function loadSystem() {
  try {
    const r = await fetch("/api/system");
    const d = await r.json();
    const dot = document.getElementById("docker-dot");
    const lbl = document.getElementById("docker-lbl");
    if (d.dockerAvailable) {
      dot.className = "sdot green"; lbl.textContent = "Docker connected";
    } else {
      dot.className = "sdot red"; lbl.textContent = "Docker unavailable";
    }
    if (d.hostname) document.getElementById("hdr-sub").textContent = `${d.hostname} — Raspberry Pi image backup`;
  } catch {}
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
document.querySelector('.tab-btn[data-tab="dashboard"]').addEventListener("click", loadDashboard);

function dbBadge(id, txtId, label, cls) {
  const b = document.getElementById(id), t = document.getElementById(txtId);
  if (!b || !t) return;
  b.className = "badge " + cls;
  const dot = b.querySelector(".dot");
  if (dot) dot.style.background = "";
  t.textContent = label;
}

function fmtTs(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, {weekday:"short",day:"numeric",month:"short"})
       + " · " + d.toLocaleTimeString(undefined, {hour:"2-digit",minute:"2-digit"});
}

function nextCronRun(expr) {
  try {
    const parts = expr.trim().split(/\s+/);
    if (parts.length < 5) return "—";
    const [min, hour, dom, mon, dow] = parts;
    // Only handle simple weekly/daily cases (no ranges/steps for now)
    const now = new Date();
    const candidate = new Date(now);
    candidate.setSeconds(0); candidate.setMilliseconds(0);
    candidate.setMinutes(parseInt(min) || 0);
    candidate.setHours(parseInt(hour) || 0);
    if (dow !== "*") {
      const targetDay = parseInt(dow);
      let daysAhead = targetDay - candidate.getDay();
      if (daysAhead <= 0) daysAhead += 7;
      candidate.setDate(candidate.getDate() + daysAhead);
    } else {
      if (candidate <= now) candidate.setDate(candidate.getDate() + 1);
    }
    if (candidate <= now) candidate.setDate(candidate.getDate() + 7);
    return candidate.toLocaleDateString(undefined, {weekday:"short",day:"numeric",month:"short"})
         + " · " + candidate.toLocaleTimeString(undefined, {hour:"2-digit",minute:"2-digit"});
  } catch { return "—"; }
}

let _dbTimer = null;   // 1s elapsed-time ticker (display only)
let _dbPoll  = null;   // ~3s data refresh, active ONLY while a backup runs
function parseElapsedSecs(s) {
  let secs = 0;
  const h = s.match(/(\d+)h/); if (h) secs += parseInt(h[1]) * 3600;
  const m = s.match(/(\d+)m/); if (m) secs += parseInt(m[1]) * 60;
  const sc = s.match(/(\d+)s/); if (sc) secs += parseInt(sc[1]);
  return secs;
}
function fmtElapsed(s) {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return h ? `${h}h ${m}m ${sec}s` : m ? `${m}m ${sec}s` : `${sec}s`;
}
async function loadDashboard() {
  try {
    const r = await fetch("/api/dashboard");
    const d = await r.json();

    // Auto-refresh while a backup is running; an idle page makes zero requests
    if (d.running && !_dbPoll) {
      _dbPoll = setInterval(loadDashboard, 3000);
    } else if (!d.running && _dbPoll) {
      clearInterval(_dbPoll); _dbPoll = null;
    }

    // ── Last backup ───────────────────────────────────────────────────────────
    const last = d.last || {};
    const res  = last.result;
    if (_dbTimer) { clearInterval(_dbTimer); _dbTimer = null; }
    if (d.running) {
      dbBadge("db-backup-badge","db-backup-badge-txt","Running…","orange");
      document.getElementById("db-started").textContent = fmtTs(last.started_ts) || last.started || "—";
      document.getElementById("db-finished-lbl").textContent = "ETA";
      if (last.started_ts && last.prev_elapsed) {
        const etaTs = last.started_ts + parseElapsedSecs(last.prev_elapsed);
        document.getElementById("db-finished").textContent = fmtTs(etaTs) + " (est.)";
      } else {
        document.getElementById("db-finished").textContent = "—";
      }
      document.getElementById("db-elapsed-lbl").textContent = "Running for";
      if (last.started_ts) {
        const tick = () => {
          const s = Math.max(0, Math.floor(Date.now()/1000) - last.started_ts);
          document.getElementById("db-elapsed").textContent = fmtElapsed(s);
        };
        tick();
        _dbTimer = setInterval(tick, 1000);
      } else {
        document.getElementById("db-elapsed").textContent = "—";
      }
      document.getElementById("db-mode").textContent = "—";
    } else {
      dbBadge("db-backup-badge","db-backup-badge-txt",
        res === "success" ? "Success" : res === "failed" ? "Failed" : "No data",
        res === "success" ? "green"   : res === "failed" ? "red"    : "muted");
      document.getElementById("db-finished-lbl").textContent = "Finished";
      document.getElementById("db-elapsed-lbl").textContent  = "Duration";
      document.getElementById("db-started").textContent  = fmtTs(last.started_ts)  || last.started  || "—";
      document.getElementById("db-finished").textContent = fmtTs(last.finished_ts) || last.finished || "—";
      document.getElementById("db-elapsed").textContent  = last.elapsed  || "—";
      document.getElementById("db-mode").textContent     = last.inferred ? "Inferred from sentinel" : (res ? "From log" : "—");
    }

    const logWrap = document.getElementById("db-log-wrap");
    const logEl   = document.getElementById("db-log");
    if (last.log_lines && last.log_lines.length) {
      logEl.innerHTML = last.log_lines.map(l => termLine(l.replace(/\n$/,""), "info")).join("");
      logWrap.style.display = "";
      logEl.scrollTop = logEl.scrollHeight;
    } else {
      logWrap.style.display = "none";
    }

    // ── Mount ─────────────────────────────────────────────────────────────────
    const mnt = d.mount || {};
    if (mnt.mounted) {
      dbBadge("db-mount-badge","db-mount-badge-txt","Mounted","green");
    } else {
      dbBadge("db-mount-badge","db-mount-badge-txt","Not mounted","red");
    }
    document.getElementById("db-mount-src").textContent = mnt.source || "—";
    document.getElementById("db-mount-fs").textContent  = mnt.fstype || "—";

    // ── Image ─────────────────────────────────────────────────────────────────
    const img = d.image || {};
    if (img.exists) {
      dbBadge("db-image-badge","db-image-badge-txt","Present","green");
      document.getElementById("db-img-logical").textContent = img.logical_mb != null ? img.logical_mb.toLocaleString() + " MB" : "—";
      document.getElementById("db-img-sparse").textContent  = img.sparse_mb  != null ? img.sparse_mb.toLocaleString()  + " MB" : "—";
    } else {
      dbBadge("db-image-badge","db-image-badge-txt","Not found","muted");
      document.getElementById("db-img-logical").textContent = "—";
      document.getElementById("db-img-sparse").textContent  = "—";
    }
    document.getElementById("db-sentinel").textContent = d.sentinel ? "Present (incremental)" : "Absent (fresh init)";
    document.getElementById("db-compact-warn").style.display = img.compact_recommended ? "" : "none";

    // ── Schedule ──────────────────────────────────────────────────────────────
    const cron = d.cron || {};
    if (cron.installed) {
      dbBadge("db-cron-badge","db-cron-badge-txt","Installed","green");
    } else {
      dbBadge("db-cron-badge","db-cron-badge-txt","Not set","muted");
    }
    document.getElementById("db-cron-expr").textContent = cron.expr || "—";
    document.getElementById("db-cron-next").textContent = cron.expr ? nextCronRun(cron.expr) : "—";

    // ── State pills ───────────────────────────────────────────────────────────
    const pr = document.getElementById("db-pill-running");
    pr.className = d.running ? "badge orange" : "badge muted";
    pr.textContent = d.running ? "Backup running" : "Backup idle";

    const pl = document.getElementById("db-pill-lock");
    pl.className = d.lock ? "badge orange" : "badge muted";
    pl.textContent = d.lock ? "Lock file present" : "No lock";

    const ps = document.getElementById("db-pill-sentinel");
    ps.className = d.sentinel ? "badge green" : "badge muted";
    ps.textContent = d.sentinel ? "Sentinel present" : "No sentinel";

    // ── Timestamp ─────────────────────────────────────────────────────────────
    document.getElementById("db-refresh-ts").textContent =
      "Last refreshed " + new Date().toLocaleTimeString(undefined, {hour:"2-digit",minute:"2-digit",second:"2-digit"});

  } catch(e) {
    if (_dbPoll) { clearInterval(_dbPoll); _dbPoll = null; }  // no toast spam while polling
    toast("Dashboard load failed: " + e.message, "err");
  }
}

// ─── Restore tab ──────────────────────────────────────────────────────────────
let restoreSelectedDevice = null;
let restoreImageVerified  = false;
let restoreImageInfo      = null;   // {path, sizeBytes, sizeGb} from /api/restore/verify
let restoreDevices        = [];     // last /api/restore/devices scan
let restoreBootDevice     = "";     // e.g. /dev/mmcblk0
let restoreFitOk          = true;   // image size <= target size

// Auto-fill image path + check mount when restore tab is first shown
document.querySelector('.tab-btn[data-tab="restore"]').addEventListener("click", () => {
  const rip = document.getElementById("restoreImagePath");
  if (rip && !rip.value) {
    // Prefer verify path if user typed one there, else compose from settings
    const vip = document.getElementById("verifyImagePath");
    const mp  = getMountPoint() || "/mnt/backups";
    const img = getImageName()  || "pi_backup.img";
    rip.value = (vip && vip.value.trim()) || `${mp}/${img}`;
  }
  checkRestoreSourceMount();
  // Apply restore banner dismiss state
  if (localStorage.getItem("pbm_restore_banner_dismissed") === "1") {
    const b = document.getElementById("restore-danger-banner");
    if (b) b.style.display = "none";
  }
});

function dismissRestoreBanner() {
  localStorage.setItem("pbm_restore_banner_dismissed", "1");
  const b = document.getElementById("restore-danger-banner");
  if (b) b.style.display = "none";
}

// ─── Restore source mount helpers ────────────────────────────────────────────
async function checkRestoreSourceMount() {
  const mp   = getMountPoint() || "/mnt/backups";
  const pill = document.getElementById("restore-src-pill");
  const info = document.getElementById("restore-src-info");
  const cfg  = document.getElementById("restore-src-cfg");
  const mBtn = document.getElementById("restore-src-mount-btn");
  const uBtn = document.getElementById("restore-src-unmount-btn");
  pill.className = "badge muted";
  pill.innerHTML = '<span class="dot"></span>Checking…';
  try {
    const r = await fetch(`/api/mount/status?path=${encodeURIComponent(mp)}`);
    const d = await r.json();
    if (d.mounted) {
      pill.className = "badge green";
      pill.innerHTML = '<span class="dot"></span>Mounted';
      info.textContent = `${mp} — ${d.source || ""} ${d.df ? "· " + d.df.trim() : ""}`.trim();
      cfg.style.display = "none";
      mBtn.style.display = "none";
      uBtn.style.display = "";
    } else {
      pill.className = "badge orange";
      pill.innerHTML = '<span class="dot"></span>Not Mounted';
      info.textContent = `${mp} is not currently mounted — mount it below to access your backup image.`;
      showRestoreSrcConfig(mp);
      mBtn.style.display = "";
      uBtn.style.display = "none";
    }
  } catch(e) {
    pill.className = "badge red";
    pill.innerHTML = '<span class="dot"></span>Error';
    info.textContent = e.message;
  }
}

function showRestoreSrcConfig(mp) {
  const cfg    = document.getElementById("restore-src-cfg");
  const detail = document.getElementById("restore-src-cfg-detail");
  const c      = collectConfig();
  let summary  = "";
  if (c.destType === "smb")   summary = `Type: SMB/CIFS  •  //${c.smbServer}/${c.smbShare}  →  ${mp}`;
  else if (c.destType === "nfs")   summary = `Type: NFS  •  ${c.nfsServer}:${c.nfsExport}  →  ${mp}`;
  else if (c.destType === "usb")   summary = `Type: USB/Block  •  ${c.usbDevice}  →  ${mp}`;
  else if (c.destType === "iscsi") summary = `Type: iSCSI  •  ${c.iscsiDevice}  →  ${mp}`;
  else if (c.destType === "local") summary = `Type: Local path  •  ${c.localPath}`;
  detail.textContent = summary || "No destination configured — go to the Destination tab first.";
  cfg.style.display = summary ? "" : "none";
}

async function restoreSourceMount() {
  const log  = document.getElementById("restore-src-log");
  const c    = collectConfig();
  const mp   = getMountPoint() || "/mnt/backups";
  log.style.display = "";
  log.innerHTML = "";
  spin("restore-src-mnt-sp", true);
  document.getElementById("restore-src-mount-btn").disabled = true;

  const appendLog = (msg, cls) => {
    const el = document.createElement("div");
    el.className = "term-line";
    el.innerHTML = `<span class="term-prefix ${cls}"></span><span class="${cls}">${esc(msg)}</span>`;
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
  };

  appendLog(`Mounting ${c.destType.toUpperCase()} at ${mp}…`, "t-cmd");
  try {
    const body = buildMountBody(c.destType, mp);
    const r    = await fetch("/api/mount/do", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
    const d    = await r.json();
    if (d.ok) {
      appendLog(`Mounted successfully. ${d.df || ""}`, "t-ok");
      setTimeout(checkRestoreSourceMount, 500);
    } else {
      appendLog(`Mount failed: ${d.error}`, "t-err");
    }
  } catch(e) {
    appendLog(`Error: ${e.message}`, "t-err");
  }
  spin("restore-src-mnt-sp", false);
  document.getElementById("restore-src-mount-btn").disabled = false;
}

async function restoreSourceUnmount() {
  const mp = getMountPoint() || "/mnt/backups";
  const log = document.getElementById("restore-src-log");
  log.style.display = "";
  log.innerHTML = `<div class="term-line"><span class="t-cmd">Unmounting ${esc(mp)}…</span></div>`;
  try {
    const r = await fetch("/api/mount/do", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({action:"unmount", mountPoint:mp}) });
    const d = await r.json();
    log.innerHTML += `<div class="term-line"><span class="${d.ok ? "t-ok" : "t-err"}">${d.ok ? "Unmounted OK" : esc(d.error)}</span></div>`;
    setTimeout(checkRestoreSourceMount, 500);
  } catch(e) {
    log.innerHTML += `<div class="term-line"><span class="t-err">${esc(e.message)}</span></div>`;
  }
}

async function verifyRestoreImage() {
  const path = document.getElementById("restoreImagePath").value.trim();
  const status = document.getElementById("restore-img-status");
  spin("restore-verify-sp", true);
  restoreImageVerified = false;
  restoreImageInfo = null;
  updateRestoreConfirm();
  try {
    const r = await fetch("/api/restore/verify", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({imagePath: path}) });
    const d = await r.json();
    if (d.ok) {
      status.innerHTML = `<div class="info green">✅ Image found: <strong>${esc(d.path)}</strong> — ${esc(d.sizeGb)} GB</div>`;
      restoreImageVerified = true;
      restoreImageInfo = d;
    } else {
      status.innerHTML = `<div class="info red">❌ ${esc(d.error)}</div>`;
    }
    status.style.display = "";
  } catch(e) {
    status.innerHTML = `<div class="info red">Request failed: ${esc(e.message)}</div>`;
    status.style.display = "";
  }
  spin("restore-verify-sp", false);
  updateRestoreConfirm();
}

async function scanRestoreDevices() {
  spin("restore-scan-sp", true);
  restoreSelectedDevice = null;
  document.getElementById("restoreTargetDevice").value = "";
  updateRestoreConfirm();
  try {
    const r = await fetch("/api/restore/devices");
    const d = await r.json();
    renderRestoreDevices(d.devices, d.bootDevice);
  } catch(e) {
    document.getElementById("restore-dev-list").innerHTML = `<div class="info red">Scan failed: ${esc(e.message)}</div>`;
  }
  spin("restore-scan-sp", false);
}

function renderRestoreDevices(devices, bootDevice) {
  const list  = document.getElementById("restore-dev-list");
  const empty = document.getElementById("restore-dev-empty");
  restoreDevices    = devices;
  restoreBootDevice = bootDevice;

  // Selectable: USB/removable devices only. The boot disk and fixed internal
  // disks are still rendered, but greyed out and unclickable, so it's obvious
  // why they can't be picked.
  const usable = devices.filter(dev => !dev.isBootDevice && (dev.hotplug || dev.tran === "usb"));
  const locked = devices.filter(dev => !usable.includes(dev));

  if (!usable.length) {
    empty.textContent = devices.length
      ? "No USB drives or SD card readers detected. Plug in your device and scan again."
      : "No devices found. Plug in your USB drive or SD card reader, then scan again.";
    empty.style.display = "";
  } else {
    empty.style.display = "none";
  }

  const usableRows = usable.map(dev => {
    const icon = "💾";
    return `<div class="target-item" id="rdev-${esc(dev.name.replace('/dev/',''))}" data-action="select-restore-dev" data-name="${esc(dev.name)}" data-size="${esc(dev.size)}" data-model="${esc(dev.model||"")}">
      <div class="radio-outer"><div class="radio-inner"></div></div>
      <span style="font-size:18px">${icon}</span>
      <div style="flex:1">
        <div style="font-size:13px;color:var(--bright);font-weight:600">${esc(dev.name)}</div>
        <div style="font-size:11px;color:var(--muted)">${esc(dev.size)} · ${esc(dev.model||"USB Device")} · USB / Removable</div>
      </div>
      <span class="badge blue">Removable</span>
    </div>`;
  });
  const lockedRows = locked.map(dev => {
    const boot  = dev.isBootDevice;
    const title = boot ? "This is the disk the Pi is running from — it can never be a restore target"
                       : "Fixed internal disk — only removable USB devices can be restore targets";
    return `<div class="target-item" aria-disabled="true" title="${esc(title)}" style="opacity:.45;cursor:not-allowed">
      <div class="radio-outer" style="visibility:hidden"><div class="radio-inner"></div></div>
      <span style="font-size:18px">${boot ? "🛡️" : "🔒"}</span>
      <div style="flex:1">
        <div style="font-size:13px;color:var(--muted);font-weight:600">${esc(dev.name)}</div>
        <div style="font-size:11px;color:var(--muted)">${esc(dev.size)} · ${esc(dev.model||"Disk")}</div>
      </div>
      <span class="badge ${boot ? "red" : "muted"}">${boot ? "Boot disk — protected" : "Not removable"}</span>
    </div>`;
  });
  list.innerHTML = usableRows.concat(lockedRows).join("");
}

function selectRestoreDevice(name, size, model) {
  const dev = restoreDevices.find(d => d.name === name);
  if (dev && dev.isBootDevice) { toast("That is the boot disk — it cannot be a restore target", "err"); return; }
  restoreSelectedDevice = name;
  document.getElementById("restoreTargetDevice").value = name;
  document.querySelectorAll("#restore-dev-list .target-item").forEach(el => el.classList.remove("active"));
  const el = document.getElementById("rdev-" + name.replace("/dev/",""));
  if (el) el.classList.add("active");
  updateRestoreConfirm();
}

function updateRestoreConfirm() {
  const card = document.getElementById("restore-confirm-card");
  const chk1 = document.getElementById("restore-chk1");
  const chk2 = document.getElementById("restore-chk2");
  if (restoreImageVerified && restoreSelectedDevice) {
    const imgPath = document.getElementById("restoreImagePath").value.trim();
    document.getElementById("restore-cmd-preview").textContent =
      `sudo image-restore ${imgPath} ${restoreSelectedDevice}\n# — or if image-restore unavailable —\nsudo dd if=${imgPath} of=${restoreSelectedDevice} bs=4M status=progress conv=fsync`;
    document.getElementById("restore-chk1-dev").textContent = restoreSelectedDevice;
    renderRestoreSummary(imgPath);
    chk1.checked = false;
    chk2.checked = false;
    card.style.display = "";
  } else {
    card.style.display = "none";
  }
  updateRestoreStartBtn();
}

function renderRestoreSummary(imgPath) {
  const box = document.getElementById("restore-summary");
  const gb  = b => (b / 1073741824).toFixed(2) + " GB";
  const dev = restoreDevices.find(d => d.name === restoreSelectedDevice);
  const imgBytes = restoreImageInfo ? (restoreImageInfo.sizeBytes || 0) : 0;
  const devBytes = dev ? (dev.sizeBytes || 0) : 0;
  restoreFitOk = !(imgBytes && devBytes && imgBytes > devBytes);

  let fitLine;
  if (!imgBytes || !devBytes) {
    fitLine = `<span class="t-warn">⚠ Could not compare image and device sizes — double-check manually before continuing</span>`;
  } else if (restoreFitOk) {
    fitLine = `<span class="t-ok">✓ Image fits on target — ${esc(gb(devBytes - imgBytes))} headroom remains</span>`;
  } else {
    fitLine = `<span class="t-err">✗ Image (${esc(gb(imgBytes))}) is LARGER than the target (${esc(gb(devBytes))}) — restore is blocked</span>`;
  }
  box.innerHTML =
    `<div><span style="color:var(--muted)">Image source&nbsp;:</span> ${esc(imgPath)}${imgBytes ? ` — <strong>${esc(gb(imgBytes))}</strong>` : ""}</div>
     <div><span style="color:var(--muted)">Target device:</span> ${esc(restoreSelectedDevice)}${dev ? ` — <strong>${esc(dev.size)}</strong> · ${esc(dev.model || "USB Device")}` : ""}</div>
     <div>${fitLine}</div>`;
}

function updateRestoreStartBtn() {
  const chk1 = document.getElementById("restore-chk1");
  const chk2 = document.getElementById("restore-chk2");
  const btn  = document.getElementById("restore-start-btn");
  if (btn) btn.disabled = !(restoreFitOk && chk1?.checked && chk2?.checked);
}
document.addEventListener("change", e => {
  if (e.target.id === "restore-chk1" || e.target.id === "restore-chk2") updateRestoreStartBtn();
});

async function startRestore() {
  const imagePath    = document.getElementById("restoreImagePath").value.trim();
  const targetDevice = document.getElementById("restoreTargetDevice").value.trim();
  if (!imagePath || !targetDevice) { toast("Image path and target device required", "err"); return; }
  const tgtDev = restoreDevices.find(d => d.name === targetDevice);
  if ((tgtDev && tgtDev.isBootDevice) || (restoreBootDevice && targetDevice === restoreBootDevice)) {
    toast(`Refusing: ${targetDevice} is the boot disk`, "err"); return;
  }
  if (!restoreFitOk) { toast("Image is larger than the target device — restore blocked", "err"); return; }

  // Show output card, reset log
  const outCard = document.getElementById("restore-output-card");
  outCard.style.display = "";
  document.getElementById("restore-log").innerHTML = "";
  document.getElementById("restore-result-box").style.display = "none";
  document.getElementById("restore-result-badge").style.display = "none";
  ["rph0","rph1","rph2","rph3"].forEach(id => {
    document.getElementById(id).style.background = "var(--border)";
    document.getElementById(id.replace("rph","rphl")).style.color = "var(--muted)";
  });
  outCard.scrollIntoView({behavior:"smooth", block:"start"});

  document.getElementById("restore-start-btn").disabled = true;

  try {
    const r = await fetch("/api/restore/run", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({imagePath, targetDevice, confirmDevice: targetDevice}) });
    const d = await r.json();
    if (!d.ok) { appendRestoreLog(d.error || "Failed to start", "err"); finishRestore("failed"); return; }

    const es = new EventSource("/api/restore/stream");
    es.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === "ping" || msg.type === "connected") return;
      if (msg.type === "log") {
        appendRestoreLog(msg.msg, msg.level);
        updateRestorePhases(msg.msg);
      }
      if (msg.type === "done") { es.close(); finishRestore(msg.result); }
    };
    es.onerror = () => { es.close(); finishRestore("failed"); };
  } catch(e) {
    appendRestoreLog(e.message, "err"); finishRestore("failed");
  }
}

function appendRestoreLog(msg, level) {
  const box = $c("restore-log");
  const cls = level === "cmd" ? "t-cmd" : level === "ok" ? "t-ok" : level === "err" ? "t-err" : level === "warn" ? "t-warn" : "t-info";
  const pre = level === "cmd" ? "$" : level === "ok" ? "✓" : level === "err" ? "✗" : level === "warn" ? "⚠" : " ";
  const el  = document.createElement("div");
  el.className = "term-line";
  el.innerHTML = `<span class="term-prefix ${cls}">${pre}</span><span class="${cls}">${esc(msg)}</span>`;
  box.appendChild(el);
  trimTermBox(box);
  box.scrollTop = box.scrollHeight;
}

function updateRestorePhases(msg) {
  const phases = [
    ["rph0", ["Verifying image","Image:"]],
    ["rph1", ["Safety check","boot device","clear"]],
    ["rph2", ["Writing image","image-restore","dd if=","DO NOT unplug"]],
    ["rph3", ["successfully","ready — safely"]],
  ];
  phases.forEach(([id, kws]) => {
    if (kws.some(k => msg.includes(k))) {
      $c(id).style.background = "var(--accent)";
      $c(id.replace("rph","rphl")).style.color = "var(--accent)";
    }
  });
}

function finishRestore(result) {
  const success = result === "success";
  const color   = success ? "var(--green)" : "var(--red)";
  ["rph0","rph1","rph2","rph3"].forEach(id => {
    $c(id).style.background = color;
    $c(id.replace("rph","rphl")).style.color = color;
  });
  const box = document.getElementById("restore-result-box");
  box.innerHTML = success
    ? `<div class="info green">✅ Restore complete. The target device is ready to boot as a Pi clone.</div>`
    : `<div class="info red">❌ Restore failed. Check the log above. Your source image file is untouched.</div>`;
  box.style.display = "";
  const badge = document.getElementById("restore-result-badge");
  badge.innerHTML = success ? `<span class="badge green"><span class="dot"></span>Success</span>` : `<span class="badge red"><span class="dot"></span>Failed</span>`;
  badge.style.display = "";
  document.getElementById("restore-start-btn").disabled = false;
}

// ─── Change Password ──────────────────────────────────────────────────────────
function showChangePwModal() {
  document.getElementById('cp-current').value = '';
  document.getElementById('cp-new').value = '';
  document.getElementById('cp-confirm').value = '';
  document.getElementById('cp-msg').style.display = 'none';
  document.getElementById('changepw-modal').style.display = 'flex';
}

async function doChangePassword() {
  const cur = document.getElementById('cp-current').value;
  const nw  = document.getElementById('cp-new').value;
  const cf  = document.getElementById('cp-confirm').value;
  const btn = document.getElementById('cp-btn');
  document.getElementById('cp-msg').style.display = 'none';
  if (!cur || !nw || !cf) { showCpMsg('All fields are required.', 'red'); return; }
  if (nw !== cf)           { showCpMsg('New passwords do not match.', 'red'); return; }
  if (nw.length < 8)       { showCpMsg('Password must be at least 8 characters.', 'red'); return; }
  btn.disabled = true;
  try {
    const r = await fetch('/api/auth/change', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({currentPassword: cur, newPassword: nw})
    });
    const d = await r.json();
    if (d.ok) {
      showCpMsg('Password updated! Your browser will ask you to log in again.', 'green');
      setTimeout(() => { document.getElementById('changepw-modal').style.display = 'none'; }, 2500);
    } else {
      showCpMsg(d.error || 'Update failed.', 'red');
    }
  } catch(e) {
    showCpMsg('Request failed.', 'red');
  }
  btn.disabled = false;
}

function showCpMsg(text, type) {
  const el = document.getElementById('cp-msg');
  el.textContent = text; el.className = 'info ' + type; el.style.display = 'block';
}

// ─── Verify path user-edit tracking ──────────────────────────────────────────
(function() {
  const vip = document.getElementById("verifyImagePath");
  if (vip) {
    vip.addEventListener("input", () => { vip.dataset.userEdited = vip.value ? "1" : ""; });
  }
})();

// ─── Init ─────────────────────────────────────────────────────────────────────
async function loadDefaults() {
  try {
    const r = await fetch("/api/config/defaults");
    const d = await r.json();
    Object.assign(S.defaults, d);
    // Populate placeholders with actual resolved paths
    const lp = document.getElementById("logPath");
    const td = document.getElementById("tipiDir");
    if (lp && !lp.value) lp.placeholder = d.logPath;
    if (td && !td.value) td.placeholder = d.tipiDir;
  } catch(e) { /* non-critical */ }
}
loadDefaults();
loadSystem();
loadLastBackup();
loadDeps();
loadConfig().then(() => { loadContainers(); checkMountStatus(S.destType); });
checkImageStatus();
loadDashboard();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # Bind to loopback by default. HTTP Basic Auth + the dev server are not
    # meant to face a whole LAN; reach it over SSH/Tailscale, or set
    # PBM_HOST=0.0.0.0 to deliberately expose it.
    host = os.environ.get("PBM_HOST", "127.0.0.1")
    exposed = host not in ("127.0.0.1", "localhost", "::1")

    print(f"""
  ╔══════════════════════════════════════════╗
  ║             SpareCard  v1.0              ║
  ╚══════════════════════════════════════════╝

  Open in browser:
    http://localhost:{PORT}
    {"http://<your-pi-ip>:" + str(PORT) if exposed else "(loopback only — set PBM_HOST=0.0.0.0 to expose on the LAN)"}

  Stop with Ctrl+C
""")
    if exposed:
        app.logger.warning("Binding to %s — the UI is reachable from the network. "
                           "Ensure a strong admin password is set.", host)

    # Install Flask if missing
    try:
        import flask
    except ImportError:
        import subprocess
        subprocess.run(["pip3","install","flask","--break-system-packages","-q"], check=True)

    app.run(host=host, port=PORT, debug=False, threaded=True)
