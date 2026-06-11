# SpareCard (formerly Pi Backup Manager) — `server.py` Hardening & Improvement Handoff

Handoff for Claude Code. Single-file Flask app (`server.py`, ~5,800 lines). The
**security recommendations 1–4 are already applied** in this file. This document
covers the **10 remaining improvements**, ranked top (do first) to bottom.

## Progress tracker

| # | Item | Status | Date |
|---|------|--------|------|
| 1 | Escape log/badge output in the browser | ✅ Done | 2026-06-11 |
| 2 | Prevent catastrophic restore in the UI | ✅ Done | 2026-06-11 |
| 3 | `Job` runner refactor (multi-tab SSE) | ✅ Done | 2026-06-11 |
| 4 | Persist destructive-op logs to disk | ✅ Done | 2026-06-11 |
| 5 | Body cap + safe JSON + config schema | ✅ Done | 2026-06-11 |
| 6 | Dashboard cache + `stat` over `du`/`df` | ✅ Done | 2026-06-11 |
| 7 | Auto-refresh while running + cap terminal DOM | ✅ Done | 2026-06-11 |
| 8 | Code tidy-ups | ✅ Done | 2026-06-11 |
| 9 | Responsive layout + accessibility | ✅ Done | 2026-06-11 |
| 10 | Inline-handler / DOM-churn cleanup | ✅ Done | 2026-06-11 |

Update this table as items land; add completion notes inside each item's section.

**Hard constraint: keep everything in the one `server.py`.** The deployment model
is "scp one file to a Pi and run it." None of the items below require splitting
the file; do not introduce extra modules, templates, or static assets.

---

## 1. Codebase orientation (read this first)

The file has two halves, split by a marker line:

```
grep -n 'HTML = r"""<!DOCTYPE html>' server.py     # everything ABOVE = Python backend
grep -n 'SETUP_HTML = r"""' server.py              # the small pre-auth setup page
```

- **Backend (Python)** is everything before `HTML = r"""`. It also contains the
  `SETUP_HTML` string near the top.
- **Frontend** is one big `HTML = r"""…"""` string (the main app, ~3,700 lines of
  HTML/CSS/JS) plus the `index()` route and `__main__` at the very end.
- `sh(` / `sudo(` no longer exist in the backend; the frontend JS uses `fetch(`,
  `.push(`, `getElementById`, etc. So backend-only text edits are safe to scope
  to "before the `HTML = r\"\"\"` marker."

Config & runtime knobs (top of file):
- `CONFIG_FILE` ← env `PBM_CONFIG` (default `~/.pi-backup-manager.json`)
- `AUTH_FILE`   ← env `PBM_AUTH`   (default `~/.pi-backup-manager-auth.json`)
- `PORT`        ← env `PBM_PORT`   (default 7823)
- `JOB_LOG_DIR` ← env `PBM_LOG_DIR` (default `~/.pbm`) — per-run job log files
- Bind host     ← env `PBM_HOST`   (default `127.0.0.1`; set `0.0.0.0` to expose)

### Established patterns to REUSE (do not reinvent)

These were added during the security pass; build on them rather than introducing
parallel mechanisms:

- `run(argv, timeout=30, merge=False)` — runs a command with **no shell**. Always
  pass an argv **list**. `merge=True` folds stderr into stdout (replaces `2>&1`).
  Missing binary returns rc 127. **Never** reintroduce `shell=True` or f-strings
  into a command string.
- `sudo_run(argv, …)` — same, prepends `sudo`.
- `_df_line(path)` — last line of `df -h <path>`.
- `_disk_base(dev)` — normalises a device/partition to its base disk name (no
  `/dev/`): `sda1→sda`, `mmcblk0p2→mmcblk0`, `nvme0n1p3→nvme0n1`.
- `_valid_disk(s)` — true only for a **whole disk** path (rejects partitions).
- `_csrf_ok()` — CSRF gate in `before_request`; mutations need header `X-PBM-CSRF: 1`.
- `_auth_cache` (+ `_auth_cache_key`, `_prune_auth_cache`) — short-TTL cache so
  PBKDF2 is not run on every request. Clear it whenever credentials change.
- Frontend: a `window.fetch` wrapper (top of the main `<script>`) already attaches
  the CSRF header to same-origin requests, so new `fetch()` calls need nothing extra.
- `esc(s)` (JS, ~line 3283) — escapes `& < > " '`. Use it for any HTML
  interpolation, including attribute values. For values passed to inline
  `onclick` handlers, don't build JS string literals — put the value in a
  `data-*` attribute (escaped with `esc`) and read `this.dataset.*` (see
  `renderNfsExports` / `renderRestoreDevices` for the pattern).

### Validation harness (run after EVERY change)

```bash
python3 - <<'EOF'
import py_compile, importlib.util, tempfile, os, base64
py_compile.compile("server.py", doraise=True)             # 1) syntax
tmp = tempfile.mkdtemp()
os.environ["PBM_AUTH"]   = os.path.join(tmp, "auth.json")  # isolate from real $HOME
os.environ["PBM_CONFIG"] = os.path.join(tmp, "cfg.json")
spec = importlib.util.spec_from_file_location("server", "server.py")
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)  # 2) import (catches NameError)
c = srv.app.test_client()
c.post("/api/auth/setup", json={"username":"admin","password":"hunter2hunter2"})
A = {"Authorization":"Basic "+base64.b64encode(b"admin:hunter2hunter2").decode()}
C = {**A, "X-PBM-CSRF":"1"}
assert c.get("/api/system", headers=A).status_code == 200
assert c.post("/api/config", json={}, headers=A).status_code == 403     # CSRF blocks no-header POST
assert c.post("/api/config", json={}, headers=C).status_code == 200     # header passes
print("harness OK")
EOF
# Also assert no shell ever creeps back into the backend:
awk '1;/^HTML = r"""<!DOCTYPE html>/{exit}' server.py | grep -nE '\b(sh|sudo)\(|shell=True' && echo "REGRESSION" || echo "no shell in backend OK"
```

> Note: this sandbox has no block devices / `sudo`, so the actual
> `losetup`/`mount`/`dd`/`restore` paths can only be smoke-tested for argument
> construction, not real execution. Final verification must happen on a real Pi/VM.

---

## 2. The 10 recommendations, in priority order

Effort key: **S** ≈ <1h, **M** ≈ a few hours, **L** ≈ half-day+.
Each item lists: why it's ranked here, where to work, the approach, and how to
prove it's done.

---

### #1 — Escape log/badge output in the browser  ·  Effort: S  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - The three log writers (`appendImgbakLog` ~4782, restore-mount `appendLog`
>   closure ~5463, `appendRestoreLog` ~5656) now use `esc(msg)`.
> - `esc()` (~3283) extended to also escape `"` and `'`, making it safe for
>   HTML-attribute contexts too.
> - Audit of all ~50 `innerHTML` sites found and fixed additional unescaped
>   server data: mount banner (mp/source/df, ~3541), iSCSI session banner
>   (iqn/portal/device, ~3568), last-backup modal (result/elapsed/started/
>   finished, ~5168), restore unmount log (~5490–5498), restore image verify
>   status (~5512–5519), device-scan error (~5536), restore device table
>   (name/size/model, ~5563).
> - Two attribute-context injections fixed by moving values to `data-*`
>   attributes read via `this.dataset.*` instead of inline `onclick="...('${v}')"`
>   JS strings: NFS export paths (~3755), restore device name/size/model (~5559).
> - Confirmed safe: `termLine`/`appendLog` (escape internally), `toast`
>   (`textContent`), iSCSI target list (`addEventListener`), container rows.
> - Verified: harness OK, no-shell check OK, extracted JS passes `node --check`.

**Original spec (Risk was: HIGH, open):**

**Why first:** the backend is locked down, so the browser is now the last
injection surface. Log lines contain attacker-influenceable strings (SMB share
names, disk labels, `fsck`/`dd` output) and are written via `innerHTML`.

**Where:** an `esc()` helper that escapes `& < >` already exists (~line 3283), but
three log writers bypass it with a partial inline escape:

```
grep -n 'replace(/</g,"&lt;")' server.py      # ~lines 4782, 5463, 5656
```

**Approach:** replace each `${msg.replace(/</g,"&lt;")}` with `${esc(msg)}`. Audit
other `innerHTML` template strings that interpolate server data (badges, result
boxes, device tables) and route those through `esc()` too; prefer `textContent`
where no markup is needed.

**Done when:** a backup/restore log line containing `<img src=x onerror=alert(1)>`
or `&` renders as literal text, not markup. Harness still passes.

---

### #2 — Prevent the catastrophic restore in the UI  ·  Effort: M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - `renderRestoreDevices` now renders the boot disk and fixed internal disks as
>   greyed-out, unclickable rows (🛡️ "Boot disk — protected" / 🔒 "Not removable")
>   instead of hiding them; USB/removable filter for selectable rows unchanged.
> - `/api/restore/devices` now runs `lsblk -b` and returns `sizeBytes` per device
>   (human `size` recomputed via new `_human_size()` helper, ~line 348); `hotplug`
>   parsing accepts both string `"1"` and JSON `true` lsblk variants.
> - Confirm card gained a **RESTORE SUMMARY** block (`renderRestoreSummary`):
>   image path + size, target device + size + model, and a fit check — green
>   "image fits, N GB headroom", or red "image LARGER than target — blocked".
>   `updateRestoreStartBtn` requires `restoreFitOk` in addition to both checkboxes.
> - Client-side guards in `selectRestoreDevice` and `startRestore` refuse the
>   boot device and an oversized image (defence in depth; backend is backstop).
> - Backend backstop added in `api_restore_run`: refuses when image size >
>   target size (`lsblk -b -d -n -o SIZE`); skipped gracefully if size unknown.
> - Verified: harness OK (incl. `_human_size` units + `sizeBytes` in devices
>   payload), no-shell check OK, extracted main JS passes `node --check`.
>   Real-device behaviour (lsblk output, locked rows, fit check) still needs a
>   look on an actual Pi.

**Original spec (Risk was: HIGH, open):**

**Why second:** wiping the wrong/boot disk is irreversible. The server already
refuses it (rec 4), but the best fix is to never let a tired human build that
request.

**Where:** restore device picker is populated from `/api/restore/devices`
(returns `isBootDevice` per device); `startRestore()` (JS, ~line 5609) and the
restore confirmation UI.

**Approach:**
1. In the device dropdown, disable/grey any device flagged `isBootDevice` with a
   "boot disk — protected" label.
2. Before the destructive step, show a confirmation summary: resolved command,
   image source size, target size, target free space (most of this is already
   computed server-side / available from `/api/restore/devices` + image status).

**Done when:** the boot disk cannot be selected in the UI, and starting a restore
shows a size/target summary before writing. Backend guard remains as backstop.

---

### #3 — `Job` runner refactor (fixes multi-tab SSE + 3 more)  ·  Effort: L  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - `Job` class added at ~line 296 (replaces the old backup globals). One
>   instance per feature: `backup_job`, `verify_job`, `compact_job`,
>   `install_job`, `imgbak_job`, `restore_job`.
> - Per-client subscriber queues (fan-out) fix the multi-tab bug; all six
>   `generate()` loops, `_*_queue`/`_*_status` globals, and the bare-`except`
>   queue-drain loops are gone. Every stream route is now `return X.stream()`.
> - Status mutation happens under `Job.lock` via atomic `start()`/`finish()`
>   (fixes the unlocked global reassignments and the check-then-start race).
> - `_backup_log_history` was **wired in, not deleted**: `Job.history` (cap 500,
>   cleared on `start()`) is replayed to clients that connect mid-job, for ALL
>   six jobs — a tab that joins late now gets the full log so far. A client
>   connecting after `done` gets a full replay and a clean close.
> - `Job._guard` wraps every worker: an uncaught exception emits
>   `Exception: …` and finishes `failed` (with `error=` field, matching old
>   backup behaviour); a worker that returns without calling `finish()` is
>   auto-failed. Thread bodies keep only their `finally` cleanup (loop detach).
> - Worker signature is now `target(job, *args)`; extra done-payload fields go
>   through `job.finish(result, code=…, saved_mb=…)`; phase events via
>   `job.event({...})`. `api_backup_last`/`api_dashboard` read `backup_job.running`.
> - Backup log events now carry `level:"info"` like the other jobs (frontend
>   ignores it there — dispatches on `type` only; all six handlers verified).
> - For #4: the single tee point is `Job._publish` (or `emit`) — one place now.
> - Verified: harness OK, no-shell OK, `node --check` OK, plus new tests:
>   two concurrent SSE clients over HTTP both receive the complete log /
>   phases / one `done` (incl. a mid-job joiner via replay), double-start
>   returns 409, exception & no-finish guards produce `failed`, subscriber
>   queues don't leak. Real Pi smoke test still recommended.

**Original spec (open):**

**Why third:** one refactor fixes four problems and removes ~250 lines of
duplication. **Current bug:** all SSE features share a single module-level
`queue.Queue`, so two open tabs steal each other's log lines and a `done` event
can close the wrong stream.

**Where (six near-identical jobs):**
```
grep -nE '@app.route\("/api/[a-z]+/stream"\)' server.py
# backup(1026) verify(1260) compact(1450) deps/install(1704) imgbak(1816) restore(1993)
grep -nE '^_[a-z]+_status |^_[a-z]+_queue ' server.py   # 6 status dicts + 6 queues
```

**Approach:** introduce ONE class and instantiate it per feature:

```python
class Job:
    def __init__(self, name):
        self.name = name
        self.status = {"running": False, "result": None}
        self.lock = threading.Lock()
        self._subs = []          # one queue PER connected client (fan-out)
    def start(self, target, *args):
        with self.lock:
            if self.status["running"]: return False
            self.status = {"running": True, "result": None}
        threading.Thread(target=self._run, args=(target, args), daemon=True).start()
        return True
    def emit(self, msg, level="info"):
        for q in list(self._subs): q.put({"type":"log","msg":msg,"level":level})
    def finish(self, result):
        with self.lock:
            self.status = {"running": False, "result": result}
        for q in list(self._subs): q.put({"type":"done","result":result})
    def stream(self):            # the single replacement for all six generate()
        q = queue.Queue(); self._subs.append(q)
        def gen():
            try:
                while True:
                    ev = q.get()
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev["type"] == "done": break
            finally:
                self._subs.remove(q)
        return Response(gen(), mimetype="text/event-stream")
```

Then `backup = Job("backup")`, `restore = Job("restore")`, …; each thread calls
`job.emit(...)` / `job.finish(...)`; each route becomes `return X.stream()` and
`if not X.start(...)`. **Per-client queues fix the multi-tab bug.** Also: status
mutation now happens under `self.lock` (fixes the unlocked global reassignments),
and the unused `_backup_log_history` replay buffer should either be wired into
`Job` (replay on connect) or deleted.

**Done when:** two browser tabs streaming the same job each receive the full log;
status updates correctly; harness passes; the six old `generate()`/`_*_queue`/
`_*_status` blocks are gone.

---

### #4 — Persist destructive-op logs to disk  ·  Effort: S–M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - Teed inside `Job` as planned: `start()` calls `_open_log()`, `_publish()`
>   calls `_log_to_disk(ev)` (so SSE clients and the disk file can never
>   disagree), `finish()` closes the file. Applies to ALL six jobs.
> - Files: `JOB_LOG_DIR/<job>-<YYYYmmdd-HHMMSS>.log`, dir created `0700` on
>   first use; `JOB_LOG_DIR` ← env `PBM_LOG_DIR`, default `~/.pbm`.
> - Rotation: newest `Job.LOG_KEEP` (10) files kept per job name, pruned at
>   each `start()`.
> - Format: `YYYY-mm-dd HH:MM:SS [levl] msg` per line, flushed per line (an
>   interrupted restore still leaves a trail); `done` line carries result +
>   extra fields as JSON; other events (e.g. backup `phase`) dumped as JSON.
> - Disk logging is best-effort by design: `_open_log`/`_log_to_disk` swallow
>   errors and disable the file — an unwritable dir or full disk never blocks
>   the job itself (tested).
> - Verified: harness OK, no-shell OK; tests cover tee content (log/phase/done
>   lines), per-run file via HTTP backup run, rotation to 10 files, and
>   unwritable-dir resilience.

**Original spec (open):**

**Why here:** only backup writes a log today; restore/verify/compact stream to the
browser and vanish on tab close. Restore especially needs a forensic trail.
Bundles into #3 (one tee point in `Job`).

**Where:** inside the `Job` runner (or each thread if #3 not yet done).

**Approach:** tee every `emit()` to `~/.pbm/<job>-<YYYYmmdd-HHMMSS>.log`. Create the
dir on first use; cap/rotate (keep last N files).

**Done when:** after a restore, a timestamped log file exists with the full output.

---

### #5 — Request hardening: body cap + safe JSON + config schema  ·  Effort: S  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - `app.config["MAX_CONTENT_LENGTH"] = 2 MB` + a JSON `@app.errorhandler(413)`.
> - New `_body()` helper (top of file, under `app =`): uses
>   `get_json(force=True, silent=True)` — still tolerates a missing
>   Content-Type like the old `force=True` did, but malformed/missing JSON now
>   aborts with a clean JSON 400 instead of an HTML traceback page. It also
>   requires the body to be a JSON *object* (every caller does `.get(...)`).
> - All 24 `request.get_json(force=True)` call sites replaced with `_body()`.
>   Exception: `/api/cleanup` keeps its deliberate `silent=True … or {}`
>   (missing body ⇒ no targets ⇒ no-op).
> - `/api/config` POST validates keys against `_CONFIG_ALLOWED_KEYS` (everything
>   `collectConfig()` sends + legacy `scriptPath`/`cronHuman` so old files
>   survive a load→save round-trip), rejects unknowns with a 400 naming them,
>   and stamps `"version": 1` on every save.
> - Verified: harness OK, no-shell OK; tests cover malformed-JSON 400 (auth'd
>   JSON body), missing-body 400, missing Content-Type still accepted, 2 MB+
>   body → JSON 413, unknown-key rejection, full collectConfig payload saves
>   with `version: 1`, and GET→POST config round-trip.

**Original spec (open):**

**Why here:** small, closes the "write arbitrary blob to disk" and stack-leak gaps.

**Where:**
```
grep -nc 'MAX_CONTENT_LENGTH' server.py   # currently 0 — add it
grep -nc 'get_json(force=True)' server.py # 24 call sites
```
`/api/config` POST handler; app construction (`app = Flask(__name__)`).

**Approach:**
1. `app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024` (2 MB).
2. Replace `request.get_json(force=True)` with `request.get_json(silent=True)` +
   an explicit `if data is None: return jsonify({"error":"invalid JSON"}), 400`
   (a tiny helper `_body()` avoids repeating this 24×).
3. In `/api/config`, validate keys against an allowlist before persisting; store a
   `"version": 1` field for forward-compat.

**Done when:** an oversized body returns 413; malformed JSON returns a clean 400
(no traceback); unknown config keys are rejected.

---

### #6 — Dashboard efficiency: cache + `stat` over `du`/`df`  ·  Effort: M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - `_image_stats(path)` helper added (next to `_human_size`): ONE `stat()`
>   call gives logical size (`st_size`) **and** sparse/allocated size
>   (`st_blocks * 512` — byte-identical to what `du` reports, verified in
>   test). `du` is now gone from the backend entirely (`grep block-size` → 0):
>   used by `api_image_status`, `_compute_dashboard`, and the compact thread's
>   before/after math (that was the `_image_stats` half of #8).
> - `df -BM` in `api_image_status` replaced by `shutil.disk_usage("/")`.
> - `/api/dashboard` is now a thin TTL-cache wrapper (`_dashboard_cache`,
>   `_DASHBOARD_TTL = 3.0` s) around the extracted `_compute_dashboard()`;
>   cached hits fork zero subprocesses and return the identical payload.
> - NOT done here (still #8): replacing the `test_request_context()` self-call
>   to `api_backup_last()` inside `_compute_dashboard`.
> - Numbers caveat: dashboard `sparse_mb` was previously `du --block-size=1M`
>   (ceiling); now floor-of-bytes — at most 1 MB lower, everything else
>   byte-identical.
> - Verified: harness OK, no-shell OK; tests: `_image_stats` == `du` on a
>   sparse file + missing-file shape, `/api/image-status` end-to-end against a
>   real sparse image, cached dashboard hit performs zero `run()` calls and
>   equals the uncached payload, TTL expiry recomputes.

**Original spec (open):**

**Why here:** biggest perceived speedup on weak Pis. `/api/dashboard` forks ~10
subprocesses per call (`tail`, `du`, `df`, `findmnt`, `flock`, `crontab`, plus
`api_backup_last`'s own `tail`).

**Where:** `api_dashboard`, `api_backup_last`, `api_image_status` (search those
names); `grep -n 'block-size=1' server.py` for the `du` calls.

**Approach:**
1. Add a 3–5s TTL cache for the dashboard payload (timestamp + memoised dict; no
   external deps).
2. Use `Path(...).stat().st_size` for logical sizes; only call `du` for the
   **sparse** size where genuinely needed.
3. (Pairs with #8) extract `_image_stats(path) -> dict` so the `du`/sparse math
   lives in one place.

**Done when:** repeated dashboard loads within the TTL don't re-fork; numbers
unchanged vs. before.

---

### #7 — Auto-refresh while running + cap terminal DOM  ·  Effort: S–M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - New `_dbPoll` timer (separate from the `_dbTimer` elapsed ticker):
>   `loadDashboard()` starts a 3 s `setInterval(loadDashboard)` only when the
>   payload says `running`, and clears it the moment it goes idle — an idle
>   page makes zero polling requests. A fetch error also clears it (no toast
>   spam if the server goes away mid-poll); pairs with the server-side 3 s
>   dashboard TTL cache from #6.
> - `trimTermBox(box)` + `TERM_MAX_LINES = 1000` added next to `termLine`/
>   `appendLog`; called from generic `appendLog` (covers verify, compact,
>   deps-install logs) and the dedicated `appendRunLog`, `appendImgbakLog`,
>   `appendRestoreLog`. The tiny `innerHTML +=` mount/unmount snippets are
>   bounded and were left alone.
> - Verified: harness OK, `node --check` OK; Node DOM-stub test: 5,000
>   appended lines leave exactly 1,000 nodes; poll-logic test: idle starts
>   nothing, running starts exactly one interval, idle again clears it.

**Original spec (open):**

**Why here:** QoL + memory. Today refresh is manual; the existing `setInterval` is
only the elapsed-time counter, not a data refresh.

**Where (JS):** `loadDashboard()` (~5267), `_dbTimer` (~5255/5293); the log writers
(`appendRestoreLog` and siblings near 4782/5463/5656).

**Approach:**
1. Poll `/api/dashboard` every ~3s **only while** `status.running`; `clearInterval`
   the moment it goes idle (so an idle page makes zero requests).
2. After appending a log line, trim: `while (box.children.length > 1000)
   box.removeChild(box.firstChild)`.

**Done when:** idle dashboard issues no polling requests; a running job updates
itself; a 5,000-line log keeps only ~1,000 nodes.

---

### #8 — Code tidy-ups  ·  Effort: S  ·  low risk  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - Runtipi route: `import json as _json, urllib.request, urllib.error`
>   removed — `urllib.error`/`urllib.request` hoisted to the module imports,
>   `_json` replaced by the module-level `json`.
> - `api_backup_last` split: new `_compute_last_backup(cfg)` returns a plain
>   dict; the route is a thin `jsonify` wrapper and `_compute_dashboard` calls
>   it directly — the `flask.current_app.test_request_context()` self-re-entry
>   (and the dashboard's local `import flask`) are gone.
> - `_image_stats()` factoring: was already done in #6.
> - Bare `except:` queue-drain loops: already deleted by #3 (verified zero
>   `get_nowait`/bare-except drains remain in the backend).
> - NOT touched: the `try: import flask / except ImportError: pip install`
>   block in `__main__` — it's outside any route body and is deliberate
>   (if dead-ish) bootstrap behaviour; changing startup wasn't worth the risk.
> - Verified: harness OK, no-shell OK, no function-local imports left in the
>   backend; `/api/backup/last` shape unchanged on both the sentinel-fallback
>   and parsed-log paths, and `dashboard.last` is byte-identical to the route
>   payload (same code path now).

**Original spec (open):**

**Why here:** correctness-adjacent cleanups that make everything else safer to edit.

**Where / what:**
- Hoist function-local imports to module top: `import flask` inside `api_dashboard`;
  `import json as _json, urllib.request, urllib.error` inside the runtipi test route.
  (`grep -n 'import flask' server.py`, `grep -n 'import json as _json' server.py`)
- Replace `api_dashboard`'s `flask.current_app.test_request_context()` self-re-entry
  (it calls `api_backup_last()` through a fake request) with a plain extracted
  `_compute_last_backup(cfg)` that both the route and the dashboard call.
- Factor the duplicated `du`/sparse math into `_image_stats()` (shared with #6).
  ✅ Already done as part of #6.
- Replace bare `except:` in queue-drain loops with `except queue.Empty:` (these may
  disappear entirely if #3 lands first).

**Done when:** no imports inside route bodies; no `test_request_context` in
`api_dashboard`; harness passes.

---

### #9 — Responsive layout + accessibility  ·  Effort: M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - A solid `@media(max-width:640px)` block already existed (earlier mobile
>   commit). Added to it: `.g-stack{…1fr!important}` (stacks the four inline
>   `grid-template-columns` rows — iSCSI portal row, NFS server row, compact
>   stats; the imgbak modal step bar became `class="phase-bar"` and inherits
>   the existing 2×2 rule), `.target-item{flex-wrap:wrap}`, `.term-box
>   {overflow-x:auto}`. New `@media(max-width:420px)` block for ~380 px
>   phones: 2-col dest grid, 40 px day buttons, 1-col container rows.
> - Icon-only buttons (4× modal `✕`, 1× `⛶` log expand) got `aria-label` +
>   `title`. Buttons with visible text labels were left alone.
> - Shape-not-just-colour: pure-CSS change at the `.badge .dot` rule — every
>   status dot now renders a glyph via `::before` (`green ✓ / red ✗ /
>   orange ⚠ / blue ℹ / muted ·`), matching the log glyphs. No JS changes;
>   applies to all dashboards pills, mount pills, container rows, result
>   badges automatically. Badges without a `.dot` are unaffected.
> - Verified: harness OK, JS `node --check` OK, marker assertions for all CSS
>   additions + aria-labels. Visual check at 380 px still worth doing on a
>   real phone.

**Original spec (open):**

**Why here:** broadens who/where it's usable; no functional risk.

**Where (CSS/HTML in the `HTML` string):** `grep -nc '@media' server.py` → currently
1. The dashboard grid, device tables, and the fixed-width setup card.

**Approach:**
1. Add `@media (max-width:640px)` rules to stack multi-column layouts and let the
   device tables scroll/wrap on a ~380px phone screen.
2. Give emoji-only icon buttons `aria-label` + `title` (🔄 refresh, 💾, etc.).
3. Convey status by **shape and colour**, not colour alone — extend the ✓/✗/⚠
   glyphs already used in logs to the status badges (helps colourblind/SR users).

**Done when:** the UI is usable at 380px wide; icon buttons announce a label;
success/failure is distinguishable without colour.

---

### #10 — Inline-handler / DOM-churn cleanup  ·  Effort: M  ·  ✅ DONE 2026-06-11

> **Completion notes:**
> - Added `$ = id => document.getElementById(id)` plus a memoising `$c(id)`
>   (`_elCache`) documented as *static nodes only*. The stream path now does
>   ZERO repeated lookups per log line: `appendLog`/`appendRunLog`/
>   `appendImgbakLog`/`appendRestoreLog` box lookups and ALL phase updaters
>   (`updatePhase`, `updateImgbakSteps`/`finishImgbak`, `updateRestorePhases`/
>   `finishRestore`) go through `$c`.
> - One delegated `document` click listener (`[data-action]` + `closest`)
>   replaces every inline `onclick` that lived inside re-rendered template
>   strings: restore device rows (`select-restore-dev`), NFS export rows
>   (`select-nfs-export`), USB partition rows (`select-usb-part` — this also
>   removed the last JS-string-building handler, `'/dev/${p.name}'`),
>   container stop/restart toggles (`toggle-ct`), deps banner install button
>   (`open-install-modal`, pkgs as escaped JSON in `data-pkgs`). The container
>   priority `<select>` now reads `this.dataset.id` instead of interpolating
>   `'${c.id}'`. `grep onclick= | grep '\${'` → 0 dynamic inline handlers.
>   `selectUsbPart`'s sibling reset selector updated `[onclick]`→`[data-action]`.
> - Static, render-once `onclick=` attributes on fixed buttons were left as-is
>   on purpose — they're set once in HTML, cause no churn, and rewriting ~80
>   of them is pure risk for zero behaviour gain.
> - Verified: harness OK, `node --check` OK, no-shell OK; Node stub tests:
>   `$c` hits `getElementById` once per id, `updateRestorePhases` does 0 new
>   lookups on repeated lines, and the dispatcher routes restore-dev /
>   install-modal (JSON round-trip) / toggle-ct clicks correctly and ignores
>   clicks outside `[data-action]`.

**Original spec (open):**

**Why last:** purely maintainability/micro-perf; cosmetic.

**Where (JS):** 86 inline `onclick=` attributes; 358 `getElementById` calls;
`updateRestorePhases` re-looks-up four nodes per log line.

**Approach:** add `const $ = id => document.getElementById(id);`, convert hot
inline handlers to delegated listeners
(`document.addEventListener('click', e => { const el = e.target.closest('[data-action]'); … })`),
and cache frequently-used nodes once instead of per-line lookups.

**Done when:** behaviour identical; fewer global handlers; no per-line repeated
lookups in the stream path.

---

## 3. Suggested batching (interlocking work)

1. **Quick hardening pass:** #1 ✅ + #5 (small, closes remaining safety gaps).
2. **Job-runner pass:** #3 + #4 + #7 (they interlock around the SSE/job lifecycle).
3. **Safety-and-speed pass:** #2 + #6 (+ the `_image_stats` half of #8).
4. **Polish:** remaining #8, then #9, then #10.

Run the §1 validation harness after each item, and do real
`mount`/`losetup`/`restore` testing on an actual Pi or VM before shipping, since
the sandbox can't exercise those paths.

## 4. What is already DONE (do not redo)

Security recs 1–4 are applied in this `server.py`:
1. **Command injection removed** — argv-based `run()`/`sudo_run()`, no `shell=True`,
   no f-strings into commands; `crontab -` via stdin; `shutil.which`; glob in Python.
2. **CSRF + loopback** — `_csrf_ok()` + `X-PBM-CSRF` header (frontend `fetch`
   wrapper attaches it); default bind `127.0.0.1`, `PBM_HOST` to expose.
3. **Auth hardening** — `_auth_cache` (PBKDF2 not per-request), bounded
   rate-limiter (`_prune_failures`, cap 1024 IPs), open-setup warning, cache
   cleared on password change.
4. **Restore safety** — `_disk_base()` unified normalisation, `_valid_disk()`
   rejects partitions, `confirmDevice` must equal target, image-exists + boot-disk
   refusal up front and re-checked in the thread.
