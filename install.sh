#!/bin/bash
set -euo pipefail

DRY_RUN=false
PYTHON_BIN=""
PACKAGE_MANAGER=""
REPO_URL="${REPO_URL:-https://github.com/Gennon/SystemSentinel.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/system-sentinel}"

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_section() {
    echo ""
    echo "════════════════════════════════════════════════"
    echo "$1"
    echo "════════════════════════════════════════════════"
}

# Detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Check Python version (3.11+)
check_python() {
    if command -v python3 &> /dev/null; then
        ver=$(python3 --version 2>&1 | awk '{print $2}')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON_BIN="python3"
            log_info "Python $ver detected"
            return 0
        fi
        log_warn "Python $ver found but 3.11+ is required"
    fi
    return 1
}

# Check git
check_git() {
    if command -v git &> /dev/null; then
        git_version=$(git --version | awk '{print $3}')
        log_info "git $git_version detected"
        return 0
    else
        return 1
    fi
}

# Install Python
install_python() {
    pm="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would install Python 3.11+ via $pm"
        return 0
    fi

    log_warn "Python 3.11+ not found. Installing..."
    case "$pm" in
        apt)
            sudo apt-get update
            sudo apt-get install -y python3.11 python3.11-venv python3-pip
            ;;
        dnf)
            sudo dnf install -y python3.11 python3-pip
            ;;
        pacman)
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm python
            ;;
    esac
    log_info "Python installed successfully"
}

# Install git
install_git() {
    pm="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would install git via $pm"
        return 0
    fi

    log_warn "git not found. Installing..."
    case "$pm" in
        apt)
            sudo apt-get update
            sudo apt-get install -y git
            ;;
        dnf)
            sudo dnf install -y git
            ;;
        pacman)
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm git
            ;;
    esac
    log_info "git installed successfully"
}

# Clone repository
clone_repo() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would clone $REPO_URL to $INSTALL_DIR"
        return 0
    fi

    log_info "Cloning repository to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    log_info "Repository cloned"
}

# Create and activate virtualenv
setup_venv() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would create venv at $INSTALL_DIR/.venv"
        return 0
    fi

    log_info "Creating Python virtualenv..."
    if ! "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv" 2>/dev/null; then
        log_warn "venv creation failed, installing python venv package..."
        ver=$("$PYTHON_BIN" --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
        case "$PACKAGE_MANAGER" in
            apt)    sudo apt-get install -y "python${ver}-venv" ;;
            dnf)    sudo dnf install -y "python${ver}-venv" ;;
            pacman) sudo pacman -S --noconfirm python ;;
        esac
        "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
    fi
    log_info "Virtualenv created"
}

# Install package
install_package() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would install system-sentinel with discord support"
        return 0
    fi

    log_info "Installing system-sentinel..."
    # Activate venv and install
    cd "$INSTALL_DIR"
    # shellcheck source=/dev/null
    source .venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install -e ".[discord]"
    log_info "Package installed successfully"
}

# Run setup wizard
run_setup_wizard() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY RUN] Would run sentinel setup wizard"
        return 0
    fi

    log_info "Launching setup wizard..."
    cd "$INSTALL_DIR"
    # shellcheck source=/dev/null
    source .venv/bin/activate
    sentinel setup
}

# Main
main() {
    echo "╔════════════════════════════════════════════════╗"
    echo "║         SystemSentinel — Full Installer        ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}[DRY RUN MODE]${NC} No changes will be made."
        echo ""
    fi

    log_section "Step 1: Checking prerequisites"
    PACKAGE_MANAGER=$(detect_package_manager)
    if [[ "$PACKAGE_MANAGER" == "unknown" ]]; then
        log_error "Unsupported package manager. Supported: apt-get, dnf, pacman"
        exit 1
    fi
    log_info "Detected package manager: $PACKAGE_MANAGER"

    if ! check_python; then
        install_python "$PACKAGE_MANAGER"
    fi

    if ! check_git; then
        install_git "$PACKAGE_MANAGER"
    fi

    log_section "Step 2: Cloning repository"
    if [[ ! -d "$INSTALL_DIR" ]]; then
        clone_repo
    else
        log_info "Directory $INSTALL_DIR already exists, skipping clone"
    fi

    log_section "Step 3: Setting up Python environment"
    setup_venv

    log_section "Step 4: Installing SystemSentinel"
    install_package

    log_section "Step 5: Running setup wizard"
    log_warn "The setup wizard will guide you through the initial configuration."
    log_warn "You may be prompted for your sudo password."
    read -p "Continue with setup wizard? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_setup_wizard
        echo ""
        log_info "Installation complete! SystemSentinel is ready."
        log_info "Start the daemon with: cd $INSTALL_DIR && source .venv/bin/activate && sentinel run"
    else
        echo ""
        log_info "Installation complete! To run setup later:"
        echo "  cd $INSTALL_DIR"
        echo "  source .venv/bin/activate"
        echo "  sentinel setup"
    fi
}

main
