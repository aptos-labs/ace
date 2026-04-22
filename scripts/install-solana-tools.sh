#!/usr/bin/env bash
# Install Solana CLI and Anchor CLI required to build and test the Solana example.
# Safe to re-run — skips tools that are already at the pinned version.
set -euo pipefail

SOLANA_CLI_VERSION="3.1.10"
ANCHOR_CLI_VERSION="0.32.1"

# ---------------------------------------------------------------------------
# Solana CLI  (installs solana, solana-test-validator, cargo-build-sbf)
# ---------------------------------------------------------------------------
install_solana() {
    if command -v solana &>/dev/null && solana --version 2>/dev/null | grep -qF "$SOLANA_CLI_VERSION"; then
        echo "solana CLI $SOLANA_CLI_VERSION already installed, skipping."
        return
    fi

    local arch tarball target
    case "$(uname -m)" in
        x86_64)        arch="x86_64-unknown-linux-gnu" ;;
        arm64|aarch64) arch="aarch64-unknown-linux-gnu" ;;
        *)             echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac

    tarball="solana-release-${arch}.tar.bz2"
    target="https://github.com/anza-xyz/agave/releases/download/v${SOLANA_CLI_VERSION}/${tarball}"

    echo "Installing Solana CLI $SOLANA_CLI_VERSION from $target ..."
    curl -fsSL -o "/tmp/${tarball}" "$target"
    tar -xjf "/tmp/${tarball}" -C /opt/
    rm -f "/tmp/${tarball}"

    # Symlink key binaries to /usr/local/bin so they are on PATH.
    # The full release directory is kept in /opt/solana-release so that
    # cargo-build-sbf can locate platform-tools-sdk/ next to itself.
    for bin in solana solana-keygen solana-test-validator cargo-build-sbf; do
        ln -sf "/opt/solana-release/bin/${bin}" /usr/local/bin/
    done

    echo "Solana CLI installed: $(solana --version)"
}

# ---------------------------------------------------------------------------
# Anchor CLI  (pre-built binary from GitHub releases)
# ---------------------------------------------------------------------------
install_anchor() {
    if command -v anchor &>/dev/null && anchor --version 2>/dev/null | grep -qF "$ANCHOR_CLI_VERSION"; then
        echo "anchor CLI $ANCHOR_CLI_VERSION already installed, skipping."
        return
    fi

    local arch binary target
    case "$(uname -m)" in
        x86_64)        arch="x86_64-unknown-linux-gnu" ;;
        arm64|aarch64) arch="aarch64-unknown-linux-gnu" ;;
        *)             echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac

    binary="anchor-${ANCHOR_CLI_VERSION}-${arch}"
    target="https://github.com/coral-xyz/anchor/releases/download/v${ANCHOR_CLI_VERSION}/${binary}"

    echo "Installing Anchor CLI $ANCHOR_CLI_VERSION from $target ..."
    curl -fsSL -o /usr/local/bin/anchor "$target"
    chmod +x /usr/local/bin/anchor
    echo "Anchor CLI installed: $(anchor --version)"
}

install_solana
install_anchor
