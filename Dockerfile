# ngehe — multi-arch (amd64 + arm64) container with every detector + handoff
# tool pre-installed. Built for users who don't want to pollute their host
# or who are on platforms where the upstream binaries are awkward to install
# (Apple Silicon, glibc/musl mismatches, locked-down servers).
#
# Build locally:        docker build -t ngehe:dev .
# Multi-arch build:     docker buildx build --platform linux/amd64,linux/arm64 -t ngehe:dev .
# Run:                  docker run --rm --network host -v "$PWD:/work" ngehe:dev surface -d example.com

# ---- Stage 1: build ngehe binary ----------------------------------------
# Bookworm only ships up to golang:1.22 at the time of writing; ngehe needs
# 1.25+ (see go.mod), so use the trixie tag which tracks recent Go releases.
FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/ngehe .

# Also build kerbrute from source here (we have Go anyway). The upstream
# release artifacts (ropnop/kerbrute v1.0.3) don't include arm64 binaries,
# so building from source is the only reliable cross-arch path.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/ropnop/kerbrute /src/kerbrute \
    && cd /src/kerbrute \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
       go build -trimpath -ldflags="-s -w" -o /out/kerbrute .

# ---- Stage 2: fetch projectdiscovery + amass release binaries -----------
# We use upstream release tarballs (same path install.sh takes on hosts
# where apt doesn't carry these). Pinning versions makes the image
# reproducible; bump them periodically.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS extras

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Versions pinned for reproducibility — keep these in sync with install.sh
# behavior (which always fetches "latest"). Override at build time:
#   --build-arg NUCLEI_VER=3.4.7
ARG NUCLEI_VER=3.4.7
ARG SUBFINDER_VER=2.9.0
ARG HTTPX_VER=1.9.0
ARG AMASS_VER=5.1.1

WORKDIR /tmp
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) ARCH=amd64 ;; \
        arm64) ARCH=arm64 ;; \
        *) echo "Unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch_pd() { \
        local name="$1" ver="$2" url; \
        url="https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${name}_${ver}_linux_${ARCH}.zip"; \
        echo "→ ${name} ${ver}"; \
        curl -fsSL -o "/tmp/${name}.zip" "$url"; \
        unzip -q -d "/tmp/${name}" "/tmp/${name}.zip"; \
        install -m 0755 "/tmp/${name}/${name}" "/out/${name}"; \
    }; \
    fetch_pd nuclei    "$NUCLEI_VER"; \
    fetch_pd subfinder "$SUBFINDER_VER"; \
    fetch_pd httpx     "$HTTPX_VER"; \
    echo "→ amass ${AMASS_VER}"; \
    curl -fsSL -o /tmp/amass.tar.gz \
        "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_linux_${ARCH}.tar.gz"; \
    tar -xzf /tmp/amass.tar.gz -C /tmp; \
    find /tmp -type f -name amass -perm -u+x -exec install -m 0755 {} /out/amass \; ; \
    rm -rf /tmp/*.zip /tmp/*.tar.gz /tmp/nuclei /tmp/subfinder /tmp/httpx /tmp/amass_*

# Pre-bake nuclei templates so first scan is instant (and the image is
# self-contained: scanning works offline). This is the bulk of the image
# size — ~1GB. Set --build-arg NO_TEMPLATES=1 to skip and produce a smaller
# image (~250MB); first --nuclei run will then download templates.
ARG NO_TEMPLATES=0
RUN if [ "$NO_TEMPLATES" = "0" ]; then \
        echo "Fetching nuclei templates (one-time, ~1GB)…"; \
        /out/nuclei -update-templates -silent || true; \
    fi

# ---- Stage 3: runtime ----------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Required by ngehe + the web/box pentest toolkit. Everything via apt
# where possible; Python tools via pipx; a couple of release binaries
# (kerbrute, dalfox) handled below.
#
# Categories:
#   ngehe deps:   ca-certificates, nmap, jq, dnsutils, curl
#   web pentest:  sqlmap, ffuf, gobuster
#   AD / box:     smbclient, ldap-utils, hashcat, python3-impacket, ruby (evil-winrm)
#   shell tools:  netcat, socat, ssh-client, proxychains4
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq dnsutils \
      git \
      nmap \
      sqlmap ffuf gobuster \
      hashcat \
      pipx python3-dev \
      smbclient ldap-utils \
      ruby ruby-dev gcc make pkg-config libffi-dev libssl-dev \
      ncat socat openssh-client proxychains4 \
    && rm -rf /var/lib/apt/lists/*

# Install latest stable Rust via rustup — Debian's apt rust is 1.63 which is
# too old for NetExec's transitive deps (libc 0.2.186 needs rustc >= 1.65).
# We remove the toolchain in the cleanup stage so it doesn't bloat the image.
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path \
    && rustc --version

# Python tools via pipx (PEP 668 blocks raw pip on Debian bookworm).
# Four install sources:
#   impacket          — full upstream (registers GetNPUsers.py, GetUserSPNs.py,
#                       secretsdump.py, ticketer.py, etc. as commands).
#                       Debian's python3-impacket only ships a partial subset
#                       AND strips the .py source files, so we use pipx instead.
#   bloodhound        — BloodHound collector (PyPI: "bloodhound", v1.9+)
#   netexec           — modern crackmapexec (NOT on PyPI, git install)
#   enum4linux-ng     — SMB / LDAP enumeration (NOT on PyPI, git install)
RUN PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install impacket \
    && PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install bloodhound \
    && PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/Pennyw0rth/NetExec \
    && PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/cddmp/enum4linux-ng \
    && rm -rf /root/.cache/pip

# Add impacket-<name> symlinks to match Kali's command naming (the per-
# finding playbook hints reference `impacket-GetNPUsers` etc. — without
# symlinks users would have to remember the `GetNPUsers.py` form pipx
# installs by default).
RUN set -eux; \
    cd /usr/local/bin; \
    for script_py in *.py; do \
        [ -f "$script_py" ] || continue; \
        base="${script_py%.py}"; \
        ln -sf "$script_py" "impacket-$base"; \
    done; \
    echo "impacket commands available:"; \
    ls -1 /usr/local/bin/ | grep -E '^(impacket-|.*\.py$)' | sort | head -40

# evil-winrm — Windows shell over WinRM. Ruby gem, no apt package on Debian.
RUN gem install evil-winrm --no-document \
    && rm -rf /root/.gem/ruby/*/cache

# kerbrute is copied from the builder stage (we built it from source there
# because upstream doesn't publish arm64 release binaries).
# (See COPY block further down.)
ARG TARGETARCH

# dalfox — XSS scanner. Asset naming convention is dalfox-<os>-<arch>.tar.gz
# (hyphens, no version in filename — differs from projectdiscovery's tools).
# The extracted file is named dalfox-linux-<arch>, not dalfox, so we install
# the literal extracted path.
RUN set -eux; \
    case "$TARGETARCH" in amd64) ARCH=amd64 ;; arm64) ARCH=arm64 ;; *) echo "unsupported"; exit 1 ;; esac; \
    DALFOX_VER=$(curl -sLI -o /dev/null -w "%{url_effective}" https://github.com/hahwul/dalfox/releases/latest | sed -E 's|.*/tag/v?||'); \
    curl -fSL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox-linux-${ARCH}.tar.gz"; \
    mkdir -p /tmp/dalfox-extract && tar -xzf /tmp/dalfox.tar.gz -C /tmp/dalfox-extract; \
    install -m 0755 "/tmp/dalfox-extract/dalfox-linux-${ARCH}" /usr/local/bin/dalfox; \
    rm -rf /tmp/dalfox.tar.gz /tmp/dalfox-extract

# PayloadsAllTheThings — payload reference repo. Shallow-clone keeps it ~50MB.
# Available at /opt/PayloadsAllTheThings. Symlink to /opt/payloads for brevity.
# git is already installed (we needed it for pipx-from-github above).
RUN git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings /opt/PayloadsAllTheThings \
    && ln -s /opt/PayloadsAllTheThings /opt/payloads \
    && rm -rf /opt/PayloadsAllTheThings/.git

# Shrink image: drop build-only deps. Removed: git (clone done), ruby-dev/
# gcc/make/python3-dev/pkg-config/libffi-dev/libssl-dev were only needed
# during build (pipx compiled C+Rust extensions, evil-winrm gem built its
# native parts, PayloadsAllTheThings was cloned). Plus the rustup toolchain
# under /root/.cargo + /root/.rustup which is ~700MB unneeded at runtime.
# Runtime doesn't need any of them.
RUN apt-get remove --purge -y \
      git \
      ruby-dev gcc make \
      python3-dev pkg-config libffi-dev libssl-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
              /root/.cargo /root/.rustup

# ngehe binary + kerbrute (both built from source in the builder stage).
COPY --from=builder /out/ngehe    /usr/local/bin/ngehe
COPY --from=builder /out/kerbrute /usr/local/bin/kerbrute

# Extras + templates (copied from the staging image)
COPY --from=extras /out/nuclei    /usr/local/bin/nuclei
COPY --from=extras /out/subfinder /usr/local/bin/subfinder
COPY --from=extras /out/httpx     /usr/local/bin/httpx
COPY --from=extras /out/amass     /usr/local/bin/amass
COPY --from=extras /root/nuclei-templates /root/nuclei-templates

# /work is the mount point for HAR captures + config + output. Users mount
# their CWD here:  docker run -v "$PWD:/work" …
WORKDIR /work

# Drop into ngehe by default. Override entrypoint to get a shell:
#   docker run --rm -it --entrypoint bash ghcr.io/chud-lori/ngehe
ENTRYPOINT ["ngehe"]
CMD ["--help"]

LABEL org.opencontainers.image.title="ngehe"
LABEL org.opencontainers.image.description="Pentest CLI + container. ngehe as the primary entry point, with the full web+box pentest toolkit bundled: nuclei (templates pre-baked) + amass + subfinder + httpx + nmap + sqlmap + ffuf + gobuster + dalfox + hashcat + impacket + bloodhound-python + netexec + enum4linux-ng + evil-winrm + kerbrute + smbclient + ldap-utils + ncat + socat + proxychains4. PayloadsAllTheThings cloned to /opt/PayloadsAllTheThings."
LABEL org.opencontainers.image.source="https://github.com/chud-lori/ngehe"
LABEL org.opencontainers.image.licenses="Apache-2.0"
