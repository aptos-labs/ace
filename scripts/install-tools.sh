#!/usr/bin/env bash
# Install external tools required to build and run ACE scenarios.
# Safe to re-run — skips tools that are already at the pinned version.
set -euo pipefail

APTOS_CLI_VERSION="9.0.0"

# ---------------------------------------------------------------------------
# Aptos CLI
# ---------------------------------------------------------------------------
install_aptos() {
    local os arch zip target

    if command -v aptos &>/dev/null && aptos --version 2>/dev/null | grep -qF "$APTOS_CLI_VERSION"; then
        echo "aptos CLI $APTOS_CLI_VERSION already installed, skipping."
        return
    fi

    case "$(uname -s)" in
        Linux)  os="Ubuntu-22.04" ;;
        Darwin) os="macOS" ;;
        *)      echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64)  arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)       echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac

    zip="aptos-cli-${APTOS_CLI_VERSION}-${os}-${arch}.zip"
    target="https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${APTOS_CLI_VERSION}/${zip}"

    echo "Installing aptos CLI $APTOS_CLI_VERSION from $target ..."
    curl -fsSL -o "/tmp/${zip}" "$target"
    unzip -qo "/tmp/${zip}" -d /usr/local/bin/
    chmod +x /usr/local/bin/aptos
    rm "/tmp/${zip}"
    echo "aptos CLI installed: $(aptos --version)"
}


# ---------------------------------------------------------------------------
# logrotate
# ---------------------------------------------------------------------------
install_logrotate() {
    if command -v logrotate &>/dev/null; then
        echo "logrotate already installed, skipping."
        return
    fi

    case "$(uname -s)" in
        Darwin)
            if ! command -v brew &>/dev/null; then
                echo "Homebrew not found — install it from https://brew.sh then re-run." >&2
                exit 1
            fi
            brew install logrotate
            ;;
        Linux)
            if command -v apt-get &>/dev/null; then
                sudo apt-get install -y logrotate
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y logrotate
            elif command -v yum &>/dev/null; then
                sudo yum install -y logrotate
            else
                echo "No supported package manager found (apt/dnf/yum)." >&2
                exit 1
            fi
            ;;
        *)
            echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac

    echo "logrotate installed: $(logrotate --version | head -1)"
}

install_aptos
install_logrotate
