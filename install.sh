#!/usr/bin/env bash
# ngehe installer — detects OS, installs nmap if missing, builds ngehe
# from source, and drops it into /usr/local/bin (or $PREFIX).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/chud-lori/ngehe/main/install.sh | sudo bash
#   PREFIX=$HOME/.local ./install.sh           # non-root install
#   ./install.sh --with-extras                 # also install nuclei + amass + subfinder + httpx
#   ./install.sh --uninstall                   # remove ngehe binary (keeps extras, Go toolchain)
#   ./install.sh --uninstall --with-extras     # also remove nuclei + amass + subfinder + httpx

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
ACTION="install"
WITH_EXTRAS=0
for arg in "$@"; do
  case "$arg" in
    --uninstall)   ACTION="uninstall" ;;
    --with-extras) WITH_EXTRAS=1 ;;
  esac
done

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

install_extras() {
  local pm="$1"
  log "installing extras (nuclei, amass, subfinder, httpx)…"

  # Prefer the distro package where it exists (Kali ships all four). Fall
  # back to `go install` for tools the package manager doesn't carry.
  case "$pm" in
    apt)
      apt-get update -qq
      for pkg in nuclei amass subfinder httpx-toolkit; do
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null; then
          log "installed $pkg via apt"
        else
          warn "$pkg not in apt — will try go install"
          go_install_extra "$pkg"
        fi
      done
      ;;
    brew)
      if [[ $EUID -eq 0 ]]; then
        warn "brew refuses root — install extras manually: brew install nuclei amass subfinder httpx"
      else
        brew install nuclei amass subfinder httpx || warn "one or more extras failed via brew"
      fi
      ;;
    *)
      log "package manager does not carry the extras — using 'go install'"
      go_install_extra nuclei
      go_install_extra amass
      go_install_extra subfinder
      go_install_extra httpx
      ;;
  esac
}

go_install_extra() {
  local name="$1"
  local module=""
  case "$name" in
    nuclei)         module="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
    amass)          module="github.com/owasp-amass/amass/v4/...@master" ;;
    subfinder)      module="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
    httpx|httpx-toolkit) module="github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
    *) warn "unknown extra: $name"; return ;;
  esac
  log "go install $module"
  if ! GO111MODULE=on go install "$module"; then
    warn "go install failed for $name"
  fi
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

uninstall_extras() {
  local pm="$1"
  log "removing extras (nuclei, amass, subfinder, httpx)…"

  case "$pm" in
    apt)
      # apt remove won't error if pkg is missing thanks to set +e here.
      set +e
      for pkg in nuclei amass subfinder httpx-toolkit; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
          DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge "$pkg" && log "apt removed $pkg"
        fi
      done
      set -e
      ;;
    brew)
      if [[ $EUID -eq 0 ]]; then
        warn "brew refuses root — remove extras manually: brew uninstall nuclei amass subfinder httpx"
      else
        for pkg in nuclei amass subfinder httpx; do
          if brew list --formula 2>/dev/null | grep -qx "$pkg"; then
            brew uninstall "$pkg" 2>/dev/null && log "brew removed $pkg"
          fi
        done
      fi
      ;;
    *)
      log "no package-manager record — relying on go-install paths"
      ;;
  esac

  # `go install` drops binaries in $GOBIN || $GOPATH/bin || ~/go/bin.
  # Remove from each plausible location for the invoking user — and from
  # the SUDO_USER home if we were elevated by sudo, so we clean up the
  # original user's go-install dir.
  local home_dirs=("$HOME")
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    local sudo_home
    sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [[ -n "$sudo_home" && "$sudo_home" != "$HOME" ]] && home_dirs+=("$sudo_home")
  fi

  for h in "${home_dirs[@]}"; do
    for bin in nuclei amass subfinder httpx; do
      for path in "$h/go/bin/$bin" "$h/.local/bin/$bin"; do
        if [[ -f "$path" ]]; then
          rm -f "$path" && log "removed $path"
        fi
      done
    done
  done

  # Hint at residual config / template dirs nuclei + subfinder leave behind.
  local note_paths=()
  for h in "${home_dirs[@]}"; do
    for d in "$h/nuclei-templates" "$h/.config/nuclei" "$h/.config/subfinder" "$h/.config/amass" "$h/.config/httpx"; do
      [[ -e "$d" ]] && note_paths+=("$d")
    done
  done
  if [[ "${#note_paths[@]}" -gt 0 ]]; then
    log "config / template dirs left in place (delete if you want them gone):"
    for p in "${note_paths[@]}"; do
      log "  $p"
    done
  fi
}

main() {
  if [[ "$ACTION" == "uninstall" ]]; then
    ensure_root_for_prefix
    uninstall
    if [[ "$WITH_EXTRAS" -eq 1 ]]; then
      local pm
      pm="$(detect_pm)"
      uninstall_extras "$pm"
    else
      log "(extras kept — re-run with --uninstall --with-extras to also remove nuclei, amass, subfinder, httpx)"
    fi
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

  if [[ "$WITH_EXTRAS" -eq 1 ]]; then
    install_extras "$pm"
  else
    log "(skipping extras — re-run with --with-extras for nuclei + amass + subfinder + httpx)"
  fi

  mkdir -p "$PREFIX/bin"
  build_and_install

  log "done. Try:"
  log "  ngehe --help"
  log "  ngehe doctor"
  log "  ngehe box --target 10.10.11.5 --markdown box.md"
  if [[ "$WITH_EXTRAS" -eq 1 ]]; then
    log "  ngehe surface --domain target.htb     # subdomain + live-host map"
    log "  ngehe scan ... --nuclei                # add nuclei template scan"
  fi
}

main "$@"
