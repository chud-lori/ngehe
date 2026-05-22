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

post_install_sanity() {
  # Nuclei needs its template database before it can do anything useful.
  # Fetching it now (foreground, with progress) is much friendlier than
  # the silent ~1GB download nuclei kicks off on first scan.
  if command -v nuclei >/dev/null 2>&1; then
    if [[ -d "$HOME/nuclei-templates" ]] && find "$HOME/nuclei-templates" -name '*.yaml' -print -quit 2>/dev/null | grep -q .; then
      log "nuclei templates already present in \$HOME/nuclei-templates"
    else
      log "fetching nuclei templates (~1GB, one-time)…"
      if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        # Run as the invoking user so templates land in their HOME, not root's.
        sudo -u "$SUDO_USER" nuclei -update-templates -silent 2>&1 | sed 's/^/  /' || warn "nuclei -update-templates failed (run manually later)"
      else
        nuclei -update-templates -silent 2>&1 | sed 's/^/  /' || warn "nuclei -update-templates failed (run manually later)"
      fi
    fi
  fi
}

install_extras() {
  local pm="$1"
  log "installing extras (nuclei, amass, subfinder, httpx)…"

  # Prefer the distro package where it exists (Kali ships all four).
  # On macOS use brew. Everywhere else, pull pre-built release binaries
  # from the upstream GitHub releases — much faster than `go install`
  # and immune to transitive-dep + checksum problems.
  case "$pm" in
    apt)
      apt-get update -qq
      local apt_missing=()
      for pair in "nuclei nuclei" "amass amass" "subfinder subfinder" "httpx httpx-toolkit"; do
        local bin="${pair%% *}" pkg="${pair##* }"
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null; then
          log "installed $bin via apt ($pkg)"
        else
          warn "$pkg not in apt — will fall back to release binary"
          apt_missing+=("$bin")
        fi
      done
      if [[ "${#apt_missing[@]}" -gt 0 ]]; then
        ensure_release_deps
        for bin in "${apt_missing[@]}"; do
          install_release_binary "$bin"
        done
      fi
      ;;
    brew)
      if [[ $EUID -eq 0 ]]; then
        warn "brew refuses root — install extras manually: brew install nuclei amass subfinder httpx"
      else
        brew install nuclei amass subfinder httpx || warn "one or more extras failed via brew"
      fi
      ;;
    *)
      log "package manager does not carry the extras — using release binaries"
      ensure_release_deps
      install_release_binary nuclei
      install_release_binary amass
      install_release_binary subfinder
      install_release_binary httpx
      ;;
  esac
}

# ensure_release_deps installs curl + unzip if missing (needed to fetch
# and unpack the release tarballs). Quiet no-op when both are present.
ensure_release_deps() {
  local pm
  pm="$(detect_pm)"
  for c in curl unzip; do
    if ! command -v "$c" >/dev/null 2>&1; then
      log "installing $c (required to fetch release binaries)…"
      install_pkg "$pm" "$c" || warn "$c install failed — release-binary path will not work"
    fi
  done
}

# github_latest_tag returns the version (without the leading "v") of the
# repo's latest release, using the redirect from /releases/latest. Avoids
# the API rate limit hit you'd take from /releases/latest JSON.
github_latest_tag() {
  local repo="$1"
  curl -sLI -o /dev/null -w "%{url_effective}\n" "https://github.com/$repo/releases/latest" \
    | sed -E 's|.*/tag/v?||' | tr -d '[:space:]'
}

# install_release_binary fetches the pre-built tarball for the given tool
# from its upstream GitHub release and drops the resulting binary in
# $PREFIX/bin. Handles the three URL conventions used by the four tools.
install_release_binary() {
  local name="$1"
  local repo="" archive_name=""
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)   arch=amd64 ;;
    aarch64|arm64)  arch=arm64 ;;
    armv7l)         arch=armv7 ;;
  esac

  case "$name" in
    nuclei)
      repo="projectdiscovery/nuclei"
      ;;
    subfinder)
      repo="projectdiscovery/subfinder"
      ;;
    httpx)
      repo="projectdiscovery/httpx"
      ;;
    amass)
      repo="owasp-amass/amass"
      ;;
    *) warn "unknown release binary: $name"; return 1 ;;
  esac

  if command -v "$name" >/dev/null 2>&1; then
    log "$name already on PATH ($(command -v "$name")) — skipping release download"
    return 0
  fi

  local ver
  ver=$(github_latest_tag "$repo")
  if [[ -z "$ver" ]]; then
    warn "could not determine latest version of $name from $repo"
    return 1
  fi

  # URL conventions (verified against current releases — May 2026):
  #   projectdiscovery (nuclei/subfinder/httpx):
  #       linux:   <name>_<ver>_linux_<arch>.zip
  #       darwin:  <name>_<ver>_macOS_<arch>.zip   (capital M, capital S)
  #   amass v5+:
  #       <name>_<os>_<arch>.tar.gz                (lowercase os, no version in name)
  local url archive_ext pd_os
  if [[ "$os" == "darwin" ]]; then
    pd_os="macOS"
  else
    pd_os="$os"
  fi
  if [[ "$name" == "amass" ]]; then
    url="https://github.com/$repo/releases/download/v${ver}/amass_${os}_${arch}.tar.gz"
    archive_ext="tar.gz"
  else
    url="https://github.com/$repo/releases/download/v${ver}/${name}_${ver}_${pd_os}_${arch}.zip"
    archive_ext="zip"
  fi

  local tmp
  tmp=$(mktemp -d)
  log "downloading $name $ver  →  $url"
  if ! curl -fSL --retry 3 --retry-delay 2 -o "$tmp/$name.$archive_ext" "$url"; then
    warn "$name download failed ($url)"
    rm -rf "$tmp"
    return 1
  fi
  if [[ "$archive_ext" == "zip" ]]; then
    ( cd "$tmp" && unzip -q "$name.$archive_ext" )
  else
    ( cd "$tmp" && tar -xzf "$name.$archive_ext" )
  fi
  # Each archive lays the binary out slightly differently. Find it.
  local bin_path
  bin_path=$(find "$tmp" -type f -name "$name" -perm -u+x 2>/dev/null | head -n1)
  if [[ -z "$bin_path" ]]; then
    bin_path=$(find "$tmp" -type f -name "$name" 2>/dev/null | head -n1)
  fi
  if [[ -z "$bin_path" ]]; then
    warn "extracted archive but no '$name' binary found"
    rm -rf "$tmp"
    return 1
  fi
  install -m 0755 "$bin_path" "$PREFIX/bin/$name" || { warn "install failed for $name"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  log "installed $name → $PREFIX/bin/$name"
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
    post_install_sanity
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
