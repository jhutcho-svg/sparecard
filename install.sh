#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SpareCard — installer
# Usage:  bash install.sh
# Run as a normal user (not root). sudo access is required for systemd setup.
# ─────────────────────────────────────────────────────────────────────────────
set -e

INSTALL_DIR="$HOME/sparecard"
SERVICE_NAME="sparecard"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
OLD_SERVICE_NAME="pi-backup-manager"   # pre-rebrand name, cleaned up below
PORT="${PBM_PORT:-7823}"
IMGBAK_REPO="$HOME/RonR-RPi-image-utils"
IMGBAK_BIN="/usr/local/sbin/image-backup"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}   $*"; }
step()  { echo -e "${CYAN}[step]${NC}   $*"; }
die()   { echo -e "${RED}[error]${NC}  $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] && die "Do not run as root. Run as your normal user with sudo access."
command -v python3 >/dev/null || die "python3 not found. Install it with: sudo apt install python3"
command -v sudo    >/dev/null || die "sudo not found."

PYTHON="$(command -v python3)"
PIP="$(command -v pip3 2>/dev/null || command -v pip 2>/dev/null || true)"

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    FLASK_PKG="python3-flask"
    ZEROFREE_PKG="zerofree"
    pkg_install() { sudo apt-get install -y -q "$@"; }
elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
    FLASK_PKG="python-flask"
    ZEROFREE_PKG=""   # AUR-only on Arch/CachyOS, not in official repos
    pkg_install() { sudo pacman -S --noconfirm --needed "$@"; }
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    FLASK_PKG="python3-flask"
    ZEROFREE_PKG="zerofree"
    pkg_install() { sudo dnf install -y "$@"; }
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    FLASK_PKG="python3-flask"
    ZEROFREE_PKG="zerofree"
    pkg_install() { sudo yum install -y "$@"; }
elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
    FLASK_PKG="python3-Flask"
    ZEROFREE_PKG="zerofree"
    pkg_install() { sudo zypper install -y "$@"; }
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
    FLASK_PKG="py3-flask"
    ZEROFREE_PKG=""   # not in Alpine repos
    pkg_install() { sudo apk add "$@"; }
elif command -v xbps-install >/dev/null 2>&1; then
    PKG_MGR="xbps"
    FLASK_PKG="python3-Flask"
    ZEROFREE_PKG=""   # not in Void repos
    pkg_install() { sudo xbps-install -y "$@"; }
else
    PKG_MGR="unknown"
    FLASK_PKG="flask"
    ZEROFREE_PKG="zerofree"
    pkg_install() { warn "No supported package manager found. Install manually: $*"; return 1; }
fi
info "Package manager: $PKG_MGR"

info "Installing SpareCard for user: $USER"
info "Install directory: $INSTALL_DIR"
info "Service port:      $PORT"
echo

# ── Create install directory ──────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

# ── Copy server.py ────────────────────────────────────────────────────────────
step "Copying server.py…"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/server.py" ]]; then
    if [[ "$SCRIPT_DIR/server.py" -ef "$INSTALL_DIR/server.py" ]]; then
        info "server.py already in place at $INSTALL_DIR"
    else
        cp "$SCRIPT_DIR/server.py" "$INSTALL_DIR/server.py"
        info "Copied server.py from $SCRIPT_DIR"
    fi
elif [[ -f "$PWD/server.py" ]]; then
    if [[ "$PWD/server.py" -ef "$INSTALL_DIR/server.py" ]]; then
        info "server.py already in place at $INSTALL_DIR"
    else
        cp "$PWD/server.py" "$INSTALL_DIR/server.py"
        info "Copied server.py from $PWD"
    fi
else
    die "server.py not found alongside install.sh or in current directory."
fi

# ── Syntax-check server.py ────────────────────────────────────────────────────
step "Syntax-checking server.py…"
"$PYTHON" -c "import py_compile; py_compile.compile('${INSTALL_DIR}/server.py', doraise=True)" \
    || die "server.py has a syntax error — aborting."
info "Syntax OK."

# ── Install Flask ─────────────────────────────────────────────────────────────
step "Checking for Flask…"
if ! "$PYTHON" -c "import flask" 2>/dev/null; then
    info "Installing Flask via $PKG_MGR…"
    pkg_install "$FLASK_PKG" \
        || {
            warn "$PKG_MGR install failed — falling back to pip…"
            if [[ -z "$PIP" ]]; then
                die "pip not found and package manager install failed. Install Flask manually."
            fi
            "$PIP" install flask --break-system-packages -q \
                || "$PIP" install flask -q \
                || die "Flask install failed. Install manually: flask via $PKG_MGR or pip."
        }
    info "Flask installed."
else
    info "Flask already present."
fi

# ── Install zerofree ─────────────────────────────────────────────────────────
step "Checking for zerofree…"
if command -v zerofree >/dev/null 2>&1; then
    info "zerofree already installed."
elif [[ -z "$ZEROFREE_PKG" ]]; then
    warn "zerofree is not available for $PKG_MGR — Compact Image will use slower fallback method."
else
    info "Installing zerofree (used by Compact Image feature)…"
    pkg_install "$ZEROFREE_PKG" \
        || warn "zerofree install failed — Compact Image will use slower fallback method."
fi

# ── Install image-backup (RonR RPi-image-utils) ───────────────────────────────
step "Checking for image-backup…"
if [[ -x "$IMGBAK_BIN" ]]; then
    info "image-backup already installed at $IMGBAK_BIN."
else
    info "image-backup not found — installing from GitHub…"

    # Ensure git is available
    if ! command -v git >/dev/null 2>&1; then
        info "Installing git…"
        pkg_install git || die "Failed to install git."
    fi

    # Clone the repo
    if [[ -d "$IMGBAK_REPO" ]]; then
        info "Updating existing clone at $IMGBAK_REPO…"
        git -C "$IMGBAK_REPO" pull --ff-only \
            || { warn "git pull failed — removing and re-cloning…"; rm -rf "$IMGBAK_REPO"; }
    fi

    if [[ ! -d "$IMGBAK_REPO" ]]; then
        info "Cloning RonR-RPi-image-utils…"
        git clone https://github.com/seamusdemora/RonR-RPi-image-utils.git "$IMGBAK_REPO" \
            || die "Clone failed — check internet connectivity."
    fi

    # Install binaries to /usr/local/sbin
    info "Installing image-* utilities to /usr/local/sbin…"
    sudo install --mode=755 "$IMGBAK_REPO"/image-* /usr/local/sbin \
        || die "Failed to install image-backup binaries."

    # Verify
    if [[ -x "$IMGBAK_BIN" ]]; then
        info "image-backup installed successfully at $IMGBAK_BIN."
    else
        die "image-backup install verification failed — $IMGBAK_BIN not found."
    fi
fi

# ── Check for Runtipi ─────────────────────────────────────────────────────────
step "Checking for Runtipi…"
if [[ -f "$HOME/runtipi/runtipi-cli" ]]; then
    info "Runtipi found at $HOME/runtipi."
else
    warn "Runtipi not found at $HOME/runtipi."
    warn "If you use Runtipi, install it first: https://runtipi.io/docs/getting-started/installation"
    warn "Then update the Runtipi Directory in the backup manager settings."
fi

# ── Docker group ──────────────────────────────────────────────────────────────
step "Checking Docker group membership…"
if getent group docker &>/dev/null; then
    if id -nG "$USER" | grep -qw docker; then
        info "$USER is already in the docker group."
    else
        sudo usermod -aG docker "$USER"
        info "Added $USER to the docker group."
        warn "Docker group change takes effect on next login (the service will work immediately)."
    fi
else
    warn "Docker group not found — Docker may not be installed yet."
    warn "After installing Docker, run: sudo usermod -aG docker \$USER"
    warn "Then restart the service:     sudo systemctl restart $SERVICE_NAME"
fi

# ── Clean up pre-rebrand (Pi Backup Manager) service & sudoers ────────────────
if [[ -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service" || -f "/etc/sudoers.d/${OLD_SERVICE_NAME}" ]]; then
    step "Removing old ${OLD_SERVICE_NAME} service/sudoers (renamed to ${SERVICE_NAME})…"
    if [[ -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service" ]]; then
        sudo systemctl disable --now "$OLD_SERVICE_NAME" 2>/dev/null || true
        sudo rm -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service"
        sudo systemctl daemon-reload
        info "Old service removed."
    fi
    if [[ -f "/etc/sudoers.d/${OLD_SERVICE_NAME}" ]]; then
        sudo rm -f "/etc/sudoers.d/${OLD_SERVICE_NAME}"
        info "Old sudoers entry removed."
    fi
    if [[ -d "$HOME/$OLD_SERVICE_NAME" && ! "$HOME/$OLD_SERVICE_NAME" -ef "$INSTALL_DIR" ]]; then
        warn "Old install dir $HOME/$OLD_SERVICE_NAME left in place — remove it once you're happy with the new install."
    fi
fi

# ── Write sudoers entry (allows web UI to install optional dependencies) ──────
step "Writing sudoers entry for dependency installer…"
SUDOERS_FILE="/etc/sudoers.d/sparecard"
case "$PKG_MGR" in
    apt)    PKG_BIN_PATH="$(command -v apt-get)"; SUDO_ARGS="install -y *" ;;
    pacman) PKG_BIN_PATH="$(command -v pacman)";  SUDO_ARGS="-S --noconfirm --needed *" ;;
    dnf)    PKG_BIN_PATH="$(command -v dnf)";     SUDO_ARGS="install -y *" ;;
    yum)    PKG_BIN_PATH="$(command -v yum)";     SUDO_ARGS="install -y *" ;;
    zypper) PKG_BIN_PATH="$(command -v zypper)";  SUDO_ARGS="install -y *" ;;
    apk)    PKG_BIN_PATH="$(command -v apk)";     SUDO_ARGS="add *" ;;
    xbps)   PKG_BIN_PATH="$(command -v xbps-install)"; SUDO_ARGS="-y *" ;;
    *)      PKG_BIN_PATH="" ;;
esac

if [[ -n "$PKG_BIN_PATH" ]]; then
    sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
# SpareCard — allows web UI to install optional dependencies (iSCSI, NFS, SMB)
$USER ALL=(ALL) NOPASSWD: $PKG_BIN_PATH $SUDO_ARGS
EOF
    sudo chmod 440 "$SUDOERS_FILE"
    if sudo visudo -cf "$SUDOERS_FILE" 2>/dev/null; then
        info "Sudoers entry written ($PKG_BIN_PATH $SUDO_ARGS)"
    else
        warn "Sudoers validation failed — removing. Use the terminal to install dependencies manually."
        sudo rm -f "$SUDOERS_FILE"
    fi
else
    warn "Could not write sudoers entry — install dependencies manually if the UI install button fails."
fi

# ── Write systemd unit ────────────────────────────────────────────────────────
step "Writing systemd service…"
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=SpareCard Web UI
After=network.target
After=docker.socket
Wants=docker.socket

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/server.py
Restart=on-failure
RestartSec=5
Environment=PBM_PORT=$PORT
Environment=PBM_HOST=0.0.0.0
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
info "Service file written to $SERVICE_FILE"

# ── Enable and start ───────────────────────────────────────────────────────────
step "Enabling and starting service…"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

# ── Check passwordless sudo (required by the web UI at runtime) ───────────────
# The service runs with no terminal, so sudo can never prompt for a password.
# Drop the credentials cached by this script's own sudo calls first, otherwise
# the check passes here but fails for the service once the cache expires.
step "Checking passwordless sudo…"
sudo -K
if sudo -n true 2>/dev/null; then
    info "Passwordless sudo OK."
else
    NOPASSWD_FILE="/etc/sudoers.d/010_${USER}-nopasswd"
    warn "──────────────────────────────────────────────────────────────────────"
    warn "User '$USER' does NOT have passwordless sudo."
    warn "The web UI runs as a service with no terminal, so every privileged"
    warn "action (iSCSI, mounting, fstab, the backup itself) will fail with:"
    warn "    sudo: a terminal is required to read the password"
    warn ""
    warn "Fix it by granting passwordless sudo (the Raspberry Pi OS default):"
    warn "    echo \"$USER ALL=(ALL) NOPASSWD: ALL\" | sudo tee $NOPASSWD_FILE"
    warn "    sudo chmod 440 $NOPASSWD_FILE"
    warn "    sudo visudo -cf $NOPASSWD_FILE   # must print: parsed OK"
    warn "──────────────────────────────────────────────────────────────────────"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
sleep 3
STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)
echo
if [[ "$STATUS" == "active" ]]; then
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo -e "${GREEN}  ✓ SpareCard is running!${NC}"
    echo
    echo "  Open in your browser:"
    echo "    http://localhost:$PORT"
    [[ -n "$LOCAL_IP" ]] && echo "    http://$LOCAL_IP:$PORT"
    echo
    echo "  Manage the service:"
    echo "    sudo systemctl status  $SERVICE_NAME"
    echo "    sudo systemctl stop    $SERVICE_NAME"
    echo "    sudo journalctl -u $SERVICE_NAME -f"
    echo
    echo "  Next steps:"
    echo "    1. Open the UI and set up auth (first-run setup page)"
    echo "    2. Configure your backup destination (Destination tab)"
    echo "    3. Generate and install your backup script (Schedule tab)"
    echo
else
    warn "Service status is '$STATUS'. Check logs:"
    warn "  sudo journalctl -u $SERVICE_NAME -n 30"
fi
