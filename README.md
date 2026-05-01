# Pi Backup Manager

A web-based Raspberry Pi image backup manager for Runtipi + Raspbian setups.

![Destination](screenshots/destination.png)

---

## What is this?

Pi Backup Manager is a self-hosted web UI that automates full SD card / boot disk image backups of your Raspberry Pi using [RonR's image-backup tools](https://github.com/seamusdemora/RonR-RPi-image-utils). It's the backup GUI that Runtipi doesn't have built-in.

You configure your backup destination, schedule, and notification settings through the browser. The app generates and installs a shell script that runs on cron — stopping your containers, backing up the image incrementally, restarting everything, and notifying you when done.

> Tested on Raspberry Pi OS (64-bit). May work on other Debian-based ARM systems.

---

## Features

- Live dashboard: last backup result, mount status, image size, cron schedule, running state + ETA
- Full Pi image backup via RonR image-backup (incremental after first run)
- Multi-destination support: iSCSI, USB, SMB, NFS
- Secondary destinations via rsync after primary backup
- Runtipi-aware: stops and restarts Docker containers in the correct order
- Runtipi API fallback: restarts app containers that need network recreation
- Guided image-backup install from GitHub (no manual steps)
- Restore tab with USB/SD safety checks
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
- `sudo` access for the running user
- [RonR image-backup tools](https://github.com/seamusdemora/RonR-RPi-image-utils) — installable via the GUI
- **Optional:** `zerofree` (`sudo apt install zerofree`) — for fast Compact Image; falls back to slower dd method without it
- **Optional:** Runtipi, SMB/NFS/iSCSI target, [ntfy.sh](https://ntfy.sh) account

---

## Installation

```bash
git clone https://github.com/jhutcho-svg/pi-backup-manager.git
cd pi-backup-manager
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

Pi Backup Manager tracks this automatically via a sentinel file (`$BACKUP_ROOT/.image_initialised`):
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

---

## Configuration

All settings are saved in `~/pi-backup-manager/config.json`. The main options are set through the UI tabs — no manual file editing needed.

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
