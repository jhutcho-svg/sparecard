# SpareCard

Keep a bootable spare of your Raspberry Pi — a web-based image backup manager for any Pi, with first-class Runtipi/Docker awareness. *(Formerly "Pi Backup Manager".)*

![Destination](screenshots/destination.png)

---

## What is this?

SpareCard is a self-hosted web UI that automates full image backups of your Raspberry Pi's boot device — SD card, USB SSD, NVMe, or any other block device — using [RonR's image-backup tools](https://github.com/seamusdemora/RonR-RPi-image-utils). If the Pi runs Runtipi it's the backup GUI Runtipi doesn't have built-in — containers are stopped and restarted around the backup in the right order. On a Pi without Docker or Runtipi, the container steps are skipped automatically and it's simply a clean image-backup GUI.

You configure your backup destination, schedule, and notification settings through the browser. The app generates and installs a shell script that runs on cron — stopping your containers, backing up the image incrementally, restarting everything, and notifying you when done.

> Tested on Raspberry Pi OS (64-bit). May work on other Debian-based ARM systems.

---

## Features

- Live dashboard: last backup result, mount status, image size, cron schedule, running state + ETA
- Full Pi image backup via RonR image-backup (incremental after first run)
- Multi-destination support: iSCSI, USB, SMB, NFS
- Secondary destinations via rsync after primary backup
- Runtipi-aware: stops and restarts Docker containers in the correct order — skipped automatically on hosts without Docker/Runtipi
- Runtipi API fallback: restarts app containers that need network recreation
- Guided image-backup install from GitHub (no manual steps)
- Restore tab with USB/SD safety checks
- Ownership guard: a `<image>.sparecard.json` marker records which Pi wrote the image — backups refuse to overwrite a pre-existing or foreign image until you adopt it (one click) or change the image name
- Visual cron scheduler
- ntfy.sh push notifications (start, success, failure)
- fstab mount-on-boot toggles
- Reset & Cleanup panel: remove sentinel, lock file, compact temp, and image in one click
- Basic auth with first-run setup wizard
- Mobile-responsive layout
- 100% self-contained single Python file

---

## Requirements

- Raspberry Pi running Raspberry Pi OS (64-bit recommended)
- Python 3.9+
- Flask (`sudo apt install python3-flask`)
- **Passwordless** sudo for the running user (the Raspberry Pi OS default for the first user). The app runs as a systemd service with no terminal, so sudo can never prompt — without a `NOPASSWD: ALL` rule, every privileged action (iSCSI, mounting, the backup itself) fails. If your user needs a password for sudo, grant it with:
  ```
  echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/010_$USER-nopasswd
  sudo chmod 440 /etc/sudoers.d/010_$USER-nopasswd
  ```
  The installer checks this and warns if it's missing.
- [RonR image-backup tools](https://github.com/seamusdemora/RonR-RPi-image-utils) — installable via the GUI
- **Optional:** `zerofree` (`sudo apt install zerofree`) — for fast Compact Image; falls back to slower dd method without it
- **Optional:** Runtipi, SMB/NFS/iSCSI target, [ntfy.sh](https://ntfy.sh) account

---

## Installation

```bash
git clone https://github.com/jhutcho-svg/sparecard.git
cd sparecard
bash install.sh
```

The installer will:
- Copy `server.py` and set up the working directory
- Install Flask if not already present
- Install RonR image-backup tools from GitHub if not found
- Check Docker group membership
- Write, enable, and start the systemd service

Once complete, open your browser at `http://<pi-ip>:7823`.

### Custom port

```bash
PBM_PORT=8080 bash install.sh
```

---

## First Run

1. Open `http://<pi-ip>:7823` — you'll be prompted to set a username and password
2. Go to the **Destination** tab and configure where backups are stored
3. Go to the **Config** tab and set your image filename and optional ntfy topic
4. Go to the **Generate** tab, generate the script, and click **Install Script**
5. Go to the **Schedule** tab to set your cron schedule
6. The **Dashboard** tab gives you a live overview at any time — last backup result, mount status, image size, schedule, and running state with ETA

---

## Usage

### Backup destinations

| Type | Notes |
|---|---|
| Local path | USB drive, NFS mount already in fstab |
| iSCSI | Auto-detects sessions; manages login/logout |
| SMB | Mounts share, runs backup, unmounts |
| NFS | Mounts share, runs backup, unmounts |

### How incremental backups work

`image-backup` requires the `-i` flag on the **first run only** to initialise the image file. After that, runs are incremental (much faster).

SpareCard tracks this automatically via a sentinel file (`$BACKUP_ROOT/.image_initialised`):
- Sentinel **absent** → first run, full image created
- Sentinel **present** → incremental update

The sentinel is only created on a successful backup, so a failed first run retries correctly.

> **Note:** If you rename the image file after the first run, delete the sentinel file to force re-initialisation.

### Runtipi container restart

When Runtipi is configured, the generated script:
1. Stops all running Docker containers before backup
2. After backup, starts containers using a three-tier fallback:
   - `docker start`
   - `docker compose up -d`
   - Runtipi REST API (for app containers that need network recreation, e.g. Immich, qbitgluetun)

Enter your Runtipi username and password in the **Config** tab to enable the API fallback. The API URL is auto-detected from the running container — use the **Test Runtipi API** button to verify credentials before generating the script.

The script detects its environment at runtime: on a host without Docker the container stop/start steps are skipped entirely, and without a `runtipi-cli` in the Runtipi directory the Runtipi-specific steps (CLI stop/start, health wait, reverse-proxy check, API login) are skipped — no spurious `docker: command not found` noise in the log.

---

## Configuration

All settings are saved in `~/.pi-backup-manager.json`. The main options are set through the UI tabs — no manual file editing needed.

Key config options:

| Setting | Where | Description |
|---|---|---|
| Image filename | Config tab | e.g. `pi_backup.img` |
| Backup root | Config tab | Mount point for backup destination |
| ntfy topic | Config tab | Push notification topic |
| Runtipi directory | Config tab | Path to runtipi install (default `~/runtipi`) |
| Runtipi credentials | Config tab | Username/password for API-based container restart (URL auto-detected) |
| Cron schedule | Schedule tab | Visual picker or manual cron expression |

---

## Screenshots

| Dashboard | Destination |
|---|---|
| ![Dashboard](screenshots/dashboard.png) | ![Destination](screenshots/destination.png) |

| Schedule | Generate |
|---|---|
| ![Schedule](screenshots/schedule.png) | ![Generate](screenshots/generate.png) |

| Containers | Restore |
|---|---|
| ![Containers](screenshots/containers.png) | ![Restore](screenshots/restore.png) |

---

## Changelog

All notable changes are documented here. This is the single source of truth for release history.

---

### 2026-06-12

#### Added
- **Image ownership guard** — a sidecar `<image>.sparecard.json` marker records which host wrote the image. The generated backup script refuses to touch an existing image without this host's marker (it aborts *before* stopping any containers, with an ntfy failure notification) and updates the marker after every successful run; secondary rsync destinations receive the marker alongside the image. The Destination tab warns when a mounted destination already holds a foreign or unmarked image (size, mtime, owner) with a one-click **Adopt** button, and the manual Run Backup flow confirms + adopts up front. Reset & Cleanup deletes markers together with images. Prevents a pre-existing `pi_backup.img` from another Pi (or an older setup) being silently overwritten by a name collision.
- **Installer passwordless-sudo check** — the service runs with no terminal, so sudo can never prompt; the app has always required `NOPASSWD` sudo for everything beyond the package-manager sudoers entry, but nothing checked or documented it. `install.sh` now drops cached credentials (`sudo -K`) and tests `sudo -n true` at the end of each run; on failure it explains the error users would otherwise hit ("a terminal is required to read the password") and offers to write the standard `010_<user>-nopasswd` rule (visudo-validated, removed if invalid). The README Requirements section now states the requirement explicitly.

#### Fixed
- **iSCSI block device auto-detect** — `iscsiadm -m session -P 3` prints `Target: <iqn> (non-flash)` on modern open-iscsi, so the IQN→device map was keyed with the suffix attached and lookups by bare IQN never matched. Login auto-detect and the sessions list device column always came back empty; both now work.
- **Stalled commands returned an HTML 500** — `subprocess.TimeoutExpired` was uncaught in `run()`, so a hung command crashed the request handler and the browser got Flask's HTML error page (surfacing as "unexpected token '<' … is not valid JSON"). Timeouts now return rc 124 with a clear message.

#### Changed
- **Docker/Runtipi now truly optional** — the generated backup script detects its environment at runtime (`HAS_DOCKER`/`HAS_TIPI`): hosts without Docker skip the container snapshot/stop/restart steps entirely, and hosts without `runtipi-cli` skip the Runtipi CLI/health-wait/reverse-proxy/API steps. Backup logs on a plain Pi are now clean instead of full of `docker: command not found` and `cd: /home/<user>/runtipi: No such file or directory` noise. The installer's "Runtipi not found" message is informational now, and the README no longer positions Runtipi as a prerequisite.
- **Rebrand internals (easy half)** — systemd unit, install dir, and sudoers file renamed to `sparecard` (`sparecard.service`, `~/sparecard`, `/etc/sudoers.d/sparecard`). Re-running `install.sh` on an existing install migrates automatically: the old `pi-backup-manager` unit is stopped and removed along with its sudoers entry. Config/auth paths, `PBM_*` env vars, the `~/.pbm` log dir, and the `X-PBM-CSRF` header deliberately keep their old names — renaming them would need permanent compatibility shims for no user-visible gain.

---

### 2026-06-11

#### Changed
- **Renamed to SpareCard** (formerly Pi Backup Manager) — all visible branding: page titles, headers, auth realm, README, installer text, service description, cron marker.
- 2 MB request body cap (JSON 413); `_body()` helper gives clean JSON 400s at all `get_json` sites; `/api/config` enforces a key allowlist with a version stamp.
- Image stats via `st_blocks` replace `du` forks; `shutil.disk_usage` replaces `df`; `/api/dashboard` served from a 3 s TTL cache.
- Delegated `[data-action]` click handling replaces inline `onclick` in re-rendered rows; memoised element lookups remove per-log-line `getElementById` churn.

#### Added
- **Restore fit check** — the boot disk is shown locked ("Boot disk — protected"); a size summary with fit check runs before writing, and both client and server refuse images larger than the target device.
- **Per-run job logs** — every backup/verify/compact/restore run is teed to `~/.pbm/<job>-<timestamp>.log` (`PBM_LOG_DIR`, last 10 kept).
- **Responsive layout** down to ~380 px wide; aria-labels on icon-only buttons; status badges use shape glyphs, not colour alone.

#### Fixed
- **Multi-tab live logs** — a shared `Job` class with per-client queues replaces six duplicated SSE stacks; a second browser tab now replays history and streams correctly instead of stealing the stream.
- Dashboard auto-refreshes (3 s) only while a backup is running; terminal log boxes are capped at 1000 DOM nodes.

---

### 2026-06-10

#### Security

- **Command injection eliminated** — `sh()`/`sudo()` string-shell runners removed entirely. All ~70 call sites now use `run(argv, …)` / `sudo_run(argv, …)`, which pass argument lists to `subprocess` with no shell. User-supplied values (passwords, mount options, device paths, IQNs, etc.) can no longer be interpreted as shell syntax. A `merge=True` flag replaces `2>&1`; `command -v` checks replaced with `shutil.which`; the install image glob is expanded in Python; the `repr()`-as-shell-quoting hack in cron/remove replaced with the `crontab -` stdin approach.
- **CSRF + loopback binding** — a `before_request` check (`_csrf_ok`) rejects any mutating `/api` request that lacks the `X-PBM-CSRF: 1` header, and rejects a foreign `Origin` even when the header is present. Safe GETs and the pre-auth setup routes are exempt. The frontend gained a small fetch wrapper that attaches the header automatically. The server now binds `127.0.0.1` by default; set `PBM_HOST=0.0.0.0` to expose on the LAN.
- **Auth hardening** — a verified-credential cache means PBKDF2 runs ~once per client per 5 minutes instead of on every request; the cache is cleared immediately on password change so old credentials cannot linger. The rate-limiter dict is now pruned on each auth attempt and hard-capped at 1024 IPs to bound memory use. Entering open-setup mode (no auth file) logs a one-time warning.
- **Restore safety** — boot-device and restore-target both normalise through a shared `_disk_base()` helper, closing the old digit-stripping bypass on `mmcblk`/`nvme` naming (`mmcblk0p2` → `mmcblk0`, not the broken `mmcblk0p`). `/api/restore/run` now requires a whole disk (partitions rejected), requires `confirmDevice` to echo the target back, verifies the image file exists before opening the thread, and refuses the boot disk up-front — with the worker thread re-checking again right before writing.

#### Changed
- `_disk_base()` shared helper introduced to normalise `sda1→sda`, `mmcblk0p2→mmcblk0`, `nvme0n1p3→nvme0n1` consistently across mount status and restore paths
- `/proc/device-tree/model` read via `Path.read_text()` instead of a shell `cat | tr` pipeline

---

### 2026-05-01

#### Fixed
- **`install.sh` same-file copy error** — running `bash install.sh` from inside the install directory caused `cp: same file` to abort the install. Now uses an inode check (`-ef`) instead of string comparison, correctly skipping the copy when source and destination are already the same file.
- **`install.sh` hardcoded to `apt-get`** — Flask, zerofree, and git installs all called `apt-get` directly, breaking on any non-Debian system. Replaced with a `pkg_install` helper that dispatches to the detected package manager.
- **zerofree install error on Arch/CachyOS** — `zerofree` is not in the official Arch repos (AUR-only), causing `pacman` to error out. The installer now skips the zerofree install on Arch/CachyOS and Alpine/Void (where it is also unavailable) and warns that Compact Image will use the slower fallback method.

#### Added
- **Multi-distro installer support** — `install.sh` now detects and supports `apt` (Debian/Ubuntu/Pi OS), `pacman` (Arch/CachyOS/Manjaro), `dnf` (Fedora/RHEL 9+), `yum` (RHEL 8/CentOS 7), `zypper` (openSUSE), `apk` (Alpine), and `xbps-install` (Void Linux). Correct package names are used per distro; pip is used as a fallback for Flask if the system package manager fails.

---

### 2026-04-12

#### Fixed
- **Image auto-resize logic rewritten** — previously compared image free space against a threshold, which could still overflow if new data exceeded remaining headroom (e.g. large Immich tarballs). Now correctly compares total image capacity against `source used + headroom`. The `src_used_mb` variable was captured but unused in the resize decision before this fix.
- **Runtipi API URL blocked by Traefik** — the configured external URL was intercepted by Traefik's `api@internal` router (`PathPrefix('/api')`), causing all API calls to return 404. The generated script now resolves the container IP via `docker inspect` at runtime and calls the API directly on port 3000, bypassing Traefik entirely.
- **`smart_start` stderr temp file permission error** — `/tmp/_pbm_ds_err` was created root-owned on the first cron run, causing `Permission denied` on all subsequent calls and silencing all container restart error messages. Fixed with `mktemp` per-call temp files.
- **`smart_start` called on already-running containers** — after `runtipi-cli start` brings containers up, the script no longer falls through to `compose up -d` for containers already running, eliminating noisy log spam.
- **Stale loop devices in auto-resize** — `auto_resize_image` now detaches any existing loop device pointing at the image file before each `losetup` attach, preventing device accumulation after crashes.

#### Changed
- Default `IMAGE_HEADROOM_MB` raised from 2000 → **5000 MB** to better accommodate large app backup data (Immich, etc.)
- Runtipi URL field removed from Config tab — API URL is auto-detected from the container at runtime

#### Added
- **Test Runtipi API button** in Config tab — resolves container IP and verifies credentials live before script generation

---

### 2026-04-05

#### Added
- **Dashboard tab** — live overview of last backup result, mount status, image size, cron schedule, and running state
- **Dashboard ETA + live timer** — when a backup is running, shows started time, estimated finish (based on previous run duration), and a live "Running for" counter
- **Reset & Cleanup panel** — remove sentinel, lock file, compact temp mount, and image file in one click; uses `sudo rm -f` for root-owned files; select-all checkbox; image target uses `*.img` glob (backend and label)
- **Mobile responsive layout** — `@media(max-width:640px)` breakpoint across all tabs; scrollable tab bar with hidden scrollbar

#### Fixed
- Dashboard mount/cron/image fields always showing wrong values — `sh()` stdout/stderr were swapped (`_, out, rc`) in three dashboard calls; fixed to `out, _, rc`
- Dashboard showing "no data" during a cron-triggered backup — `running` field now also checks whether the lock file is held (`flock -n`), not only the in-memory web UI flag
- Dashboard showing "running" indefinitely after backup completes — `flock` does not delete the lock file; replaced existence check with `flock -n <file> true` to test if a process actually holds the lock
- Reset & Cleanup image delete silently succeeding on wrong filename — backend now globs `*.img` and reports how many files were deleted

---

### 2026-03-20

#### Added
- **Security hardening** — input validation helpers added for all shell-executed parameters: `_valid_mount_path`, `_valid_hostname`, `_valid_share`, `_valid_device`, `_valid_iqn` (RFC 3720), `_valid_port`, `_valid_fstype`, `_valid_script_path`
- Script read/write restricted to home directory via `Path.resolve()` + `is_relative_to()`

---

### 2026-03-19

#### Added
- **Runtipi API restart fallback** — third tier in `smart_start`: if `docker start` and `compose up -d` both fail (e.g. Immich/qbitgluetun whose compose files reference external Docker networks by ID that are recreated on Runtipi restart), the script authenticates with the Runtipi REST API and starts the app via `POST /api/app-lifecycle/{urn}/start`. Login performed once per restart cycle, session cookie reused.
- **"No backup yet" fix after service restart** — `_apply_sentinel_fallback()` in `api_backup_last`: if the log yields no result, checks for `.image_initialised` sentinel and uses image file mtime as the last backup timestamp.
- **`runtipi-reverse-proxy` left in Created state** — explicit check added to the generated script's restart block: after Runtipi passes health check, `runtipi-reverse-proxy` state is verified and started if not running (known timing issue with `runtipi-cli start`).

#### Fixed
- **iSCSI block device detection** — replaced `ls -1t /dev/sd*` + string append with `iscsiadm -m session -P 3` to reliably map IQN → block device; login endpoint retries up to 5s for device to appear in sysfs
- **iSCSI fields blank when session already connected** — `/api/iscsi/sessions` now returns `device` field; destination panel auto-populates IQN and block device and unlocks steps 2 & 3 if an active session exists

---

## Credits

- [RonR / seamusdemora](https://github.com/seamusdemora/RonR-RPi-image-utils) — image-backup and image-restore tools
- [Runtipi](https://runtipi.io) — the Docker platform this tool is designed around
- [ntfy.sh](https://ntfy.sh) — push notifications

---

## License

MIT — see [LICENSE](LICENSE)
