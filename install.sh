#!/usr/bin/env bash
# ngehe installer — detects OS, installs nmap if missing, builds ngehe
# from source, and drops it into /usr/local/bin (or $PREFIX).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/chud-lori/ngehe/main/install.sh | sudo bash
#   PREFIX=$HOME/.local ./install.sh        # non-root install
#   ./install.sh --uninstall                # remove ngehe (keeps Go toolchain)

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
ACTION="install"
[[ "${1:-}" == "--uninstall" ]] && ACTION="uninstall"

log()  { printf '\033[1;34m[ngehe]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ngehe]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ngehe]\033[0m %s\n' "$*" >&2; exit 1; }

ensure_root_for_prefix() {
  if [[ "$PREFIX" == "/usr/local" || "$PREFIX" == "/usr" ]]; then
    if [[ $EUID -ne 0 ]]; then
      die "PREFIX=$PREFIX needs root. Run with sudo, or set PREFIX=\$HOME/.local"
    fi
  fi
}

detect_pm() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "brew"; return
  fi
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v dnf     >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v yum     >/dev/null 2>&1; then echo "yum"; return; fi
  if command -v pacman  >/dev/null 2>&1; then echo "pacman"; return; fi
  if command -v apk     >/dev/null 2>&1; then echo "apk"; return; fi
  echo "unknown"
}

install_pkg() {
  local pm="$1"; shift
  local pkgs=("$@")
  case "$pm" in
    brew)   brew install "${pkgs[@]}" ;;
    apt)    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" ;;
    dnf)    dnf install -y "${pkgs[@]}" ;;
    yum)    yum install -y "${pkgs[@]}" ;;
    pacman) pacman -Sy --noconfirm "${pkgs[@]}" ;;
    apk)    apk add --no-cache "${pkgs[@]}" ;;
    *)      warn "Unknown package manager — please install manually: ${pkgs[*]}"; return 1 ;;
  esac
}

ensure_dep() {
  local cmd="$1"; local pkg="$2"; local pm="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    log "$cmd already installed ($(command -v "$cmd"))"
    return
  fi
  log "installing $cmd via $pm…"
  if [[ "$pm" == "brew" ]]; then
    if [[ $EUID -eq 0 ]]; then
      warn "skipping $cmd: brew refuses root. Install manually: brew install $pkg"
      return
    fi
  fi
  install_pkg "$pm" "$pkg" || warn "$cmd install failed — ngehe features needing it will not work"
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    log "go found ($(go version | awk '{print $3}'))"
    return
  fi
  warn "Go toolchain not found. ngehe is built from source."
  warn "Install Go from https://go.dev/dl/ (or your package manager) and re-run this script."
  die "Go is required for installation."
}

build_and_install() {
  local dst="$PREFIX/bin/ngehe"
  log "building ngehe…"
  ( cd "$(dirname "$0")" && go build -o "$dst" . )
  chmod 0755 "$dst"
  log "installed: $dst"
}

uninstall() {
  local dst="$PREFIX/bin/ngehe"
  if [[ -f "$dst" ]]; then
    rm -f "$dst"
    log "removed $dst"
  else
    log "$dst not present — nothing to remove"
  fi
}

main() {
  if [[ "$ACTION" == "uninstall" ]]; then
    ensure_root_for_prefix
    uninstall
    return
  fi

  ensure_root_for_prefix
  ensure_go

  local pm
  pm="$(detect_pm)"
  log "package manager: $pm"

  # nmap is the only required external CLI for `ngehe box`.
  ensure_dep nmap nmap "$pm"

  # hashcat is recommended for cracking the krb5asrep / krb5tgs hashes
  # ngehe produces, but optional. Not auto-installed (large download,
  # GPU-driver-dependent on some platforms). Just point the user at it.
  if ! command -v hashcat >/dev/null 2>&1; then
    log "(optional) hashcat not found — install separately to crack JWT / AS-REP / Kerberoast hashes"
  fi
  if ! command -v sqlmap >/dev/null 2>&1; then
    log "(optional) sqlmap not found — install separately for deeper SQLi exploitation after ngehe flags a finding"
  fi

  mkdir -p "$PREFIX/bin"
  build_and_install

  log "done. Try:"
  log "  ngehe --help"
  log "  ngehe doctor"
  log "  ngehe box --target 10.10.11.5 --markdown box.md"
}

main "$@"
