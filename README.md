# ngehe

Pentest CLI for authorized assessments, HTB boxes, and CTFs. ngehe discovers a target's attack surface — web + non-HTTP services — and tests for the OWASP Top 10 plus common HTB attack vectors (SSH, FTP, SMB, LDAP/AD, Kerberos, default credentials) from a single binary.

Status: alpha. Useful in real engagements, not yet a finished product.

Website: [chud-lori.github.io/ngehe](https://chud-lori.github.io/ngehe/)

## What ngehe Does

Three top-level commands.

### `ngehe box <target>`

Full-spectrum scan. Shells out to nmap, then dispatches per-service scanners (SSH, FTP, SMB, LDAP, SNMP, DNS, DBs) plus the web recon flow against any HTTP ports. The "I just got an HTB IP" entry point.

```bash
ngehe box --target 10.10.11.5 --domain target.htb --markdown box.md
```

Requires `nmap` on PATH. For AD-flavored boxes also see `ngehe bloodhound` and `ngehe kerberos asrep / kerberoast` flags (described under HOWTO).

### `ngehe recon <target>`

Point this at a URL you've never seen — an HTB IP, a freshly-discovered subdomain, a staging server. ngehe will:

- Fingerprint the technology (server, framework, CMS, session cookie names, body markers)
- Probe for sensitive files using SecLists' `quickhits` wordlist plus content fingerprinting (.git, .env, AWS creds, server-status, phpinfo)
- Walk the SecLists `common.txt` directory bruteforce wordlist
- Categorize findings by HTTP status and exploitability

```bash
ngehe recon --target http://10.10.11.5 --markdown recon.md
```

### `ngehe surface <domain>`

Subdomain enumeration + live-host probing using established open-source scanners: **amass** (OWASP, comprehensive passive), **subfinder** (projectdiscovery, fast passive), and **httpx** (projectdiscovery, probe + tech fingerprint). With `--nuclei`, also runs projectdiscovery's template scanner against the live hosts.

```bash
ngehe surface --domain target.htb                  # prints colored summary to terminal
ngehe surface --domain target.htb --markdown surface.md   # save markdown report
ngehe surface --domain target.htb --out s.jsonl    # save JSONL for jq
ngehe surface --domain target.htb --nuclei         # add CVE / misconfig templates
```

Output mode is opt-in: default is terminal print (with ANSI colors and a "Suggested attack chain" header for critical/high findings); pass `--out` or `--markdown` to write a file instead. Same behavior for `recon`, `scan`, and `box`.

Each tool is opt-out via `--no-amass` / `--no-subfinder` / `--no-httpx`; missing binaries are skipped (no hard failure). Install them with `./install.sh --with-extras`. Live URLs are printed to stdout at the end — chain into `ngehe recon` / `ngehe scan` / `ngehe box`:

```bash
ngehe surface -d target.htb | while read url; do
  ngehe scan --target "$url" --config ngehe.yaml
done
```

### `ngehe scan`

Three input modes — pick whichever you have.

```bash
# Mode 1 — HAR (best signal). Capture real traffic in Burp / DevTools.
ngehe scan --har capture.har --config ngehe.yaml --markdown findings.md

# Mode 2 — OpenAPI. Synthesize requests from the spec.
ngehe scan --openapi openapi.yaml --base https://api.example.com --config ngehe.yaml

# Mode 3 — URL only. ngehe crawls common paths and synthesizes requests with
# common parameter names (id, q, file, path, url, cmd, host, msg, ...).
# Lower signal than HAR (we're guessing params), but works from just a URL.
ngehe scan --target http://10.10.11.5 --config ngehe.yaml --markdown findings.md

# Add nuclei templates (CVEs, default-config, exposures) on top of the native detectors:
ngehe scan --har capture.har --config ngehe.yaml --nuclei --markdown findings.md
```

## External Scanner Integrations

ngehe shells out to four established open-source scanners when present on PATH. Each integration emits findings into the same JSONL with `source:` set so you can filter native vs upstream.

| Tool | Module / flag | Purpose |
|---|---|---|
| **nuclei** (projectdiscovery) | `scan --nuclei`, `box --nuclei`, `surface --nuclei` | Template-based scanner — thousands of community CVE / misconfig / exposure templates |
| **amass** (OWASP) | `ngehe surface` | Comprehensive passive subdomain enumeration |
| **subfinder** (projectdiscovery) | `ngehe surface` | Fast passive subdomain enumeration |
| **httpx** (projectdiscovery) | `ngehe surface` | Probe hostnames for live HTTP + tech fingerprint |

All four install via `./install.sh --with-extras` (uses apt on Debian-family distros, brew on macOS, upstream release binaries from each project's GitHub releases as a portable fallback). They're opt-in: if a binary is missing, ngehe prints a hint and skips it without failing the run.

For deeper post-finding exploitation, install separately: `hashcat`, `sqlmap`, `bloodhound`, `impacket` — these are documented as next-step handoffs in the per-finding `next` field. The Docker image bundles all of them so you don't need to install anything on the host.

## Non-Web Service Scanners (ngehe box)

Bundled service modules. Each fires automatically when nmap detects the relevant service.

| Service | Module | What it does |
|---|---|---|
| SSH | `ssh-banner`, `ssh-old-openssh`, `ssh-libssh-auth-bypass`, `ssh-cve-2018-15473`, `ssh-auth-methods`, `ssh-none-auth-allowed` | Banner grab, version-based CVE flags (libssh CVE-2018-10933, OpenSSH ≤7.7 user enum), auth method enumeration |
| FTP | `ftp-banner`, `ftp-anonymous-allowed`, `ftp-anonymous-listing` | Anonymous login + file listing |
| SMB | `smb-null-session-allowed`, `smb-anonymous-allowed`, `smb-guest-allowed` | Share enumeration with null / anonymous / guest |
| LDAP | `ldap-anonymous-bind`, `ldap-root-dse`, `ldap-user-enum`, `ldap-asrep-roastable` | Anonymous bind, domain controller info, full user list, accounts with DONT_REQ_PREAUTH |
| SNMP | `snmp-community-accepted` | Common community strings (public, private, ...) |
| DNS | `dns-axfr-allowed`, `dns-subdomain` | Zone transfer + subdomain bruteforce |
| MySQL / Postgres / MSSQL / Redis | `db-default-creds-*`, `db-no-auth-redis` | Default credential check; Redis unauth INFO |
| Active Directory | `kerberos-asrep-roast`, `kerberos-kerberoast` | hashcat-format hash extraction via gokrb5 |
| BloodHound | `bloodhound-collect` | LDAP-based subset collection (users / computers / groups) in BloodHound JSON schema |
| HTTP NTLM | `ntlm-spray-hit` | Password spray against HTTP NTLM endpoints |

## Detector Library — OWASP Coverage

| OWASP | Detector | What it does |
|---|---|---|
| **A01 Broken Access Control** | `bola-cross-user-access` | Replay request as each other session; flag when offender gets a similar response |
| | `broken-auth-anon-access` | Same request without auth — flag 2xx |
| | `idor-mutated-id` | Permute numeric / UUID IDs in path + JSON body |
| | `lfi-path-traversal` | `../../etc/passwd`, encoding variants, `php://filter`, `file://` |
| **A02 Cryptographic Failures** | `jwt-alg-none` | Server accepted unsigned token |
| | `jwt-weak-secret-*` | HS256 token re-signed with weak secret accepted |
| | `jwt-no-exp-check` | Token with `exp=0` accepted |
| | `jwt-kid-injection` | Path-traversal `kid` accepted |
| | `jwt-no-iss-check` / `jwt-no-aud-check` | Issuer / audience not validated |
| **A03 Injection** | `sqli-error-based` | Single-quote payload triggered DB error string |
| | `sqli-time-based` | `SLEEP(5)` / `WAITFOR DELAY` caused response delay |
| | `cmdi-marker` | Shell command output reflected in response (RCE confirmed) |
| | `cmdi-time-based` | Sleep payload caused response delay (blind RCE) |
| | `ssti` | Template expression `{{1337*1331}}` evaluated to `1779547` |
| | `xss-reflected` | Payload reflected unescaped into HTML context |
| **A05 Security Misconfiguration** | `sensitive-file` | Curated probes for .git, .env, AWS creds, phpinfo with content fingerprinting |
| | `sensitive-path` | Broad SecLists quickhits.txt probes (low-signal coverage) |
| | `dir-discovery` | SecLists common.txt directory bruteforce |
| | `default-credentials` | Curated web admin creds tested against configured login URLs |
| **A06 Vulnerable Components** | `tech-fingerprint` | Identifies server, framework, CMS, runtime versions for manual CVE lookup |
| | `server-header` / `x-powered-by` | Raw header disclosure |
| **A07 Authentication Failures** | `default-credentials` | (see A05) |
| | `jwt-*` | (see A02) |
| **A08 Software & Data Integrity** | `mass-assign-reflected` | Injected `isAdmin`/`role`/`owner`/... echoed in response |
| | `mass-assign-accepted` | Same injection succeeded silently |
| **A10 Server-Side Request Forgery** | `ssrf` | Cloud metadata services (AWS/GCP/Azure), `file://`, loopback, gopher/dict wrappers |

## Wordlists

ngehe embeds three wordlists from [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) (MIT, the de-facto standard collection used by `ffuf`, `gobuster`, `dirsearch`, `feroxbuster`):

| File | Source | Size |
|---|---|---|
| Common paths | `Discovery/Web-Content/common.txt` | 4750 entries |
| Sensitive files | `Discovery/Web-Content/quickhits.txt` | 2567 entries |
| Default credentials | `Passwords/Default-Credentials/default-passwords.csv` | 2876 entries |

Plus a small curated subset of universally-useful web admin credentials for fast default-creds scans.

See [`internal/wordlist/NOTICE.md`](internal/wordlist/NOTICE.md) for attribution.

## Architecture

```text
            ┌───────────────────────────────────────┐
            │           target / capture            │
            └───┬──────────────────┬────────────────┘
                ▼                  ▼
       ┌──────────────────┐   ┌──────────────────┐
       │  ngehe recon    │   │   ngehe scan    │
       │  (URL only)      │   │  (HAR / OpenAPI) │
       └────────┬─────────┘   └────────┬─────────┘
                ▼                      ▼
       ┌─────────────────────────────────────────┐
       │ fingerprint   sensitive    dirbust      │
       │ sqli  cmdi  ssti  lfi  ssrf  xss  creds │
       │ bola  jwt-abuse  id-mutate  mass-assign │
       └────────────────────┬────────────────────┘
                            ▼
                ┌────────────────────────┐
                │ JSONL + markdown report│
                └────────────────────────┘
```

Each detector is a separate package under `internal/detector/` and `internal/recon/`. They share `httpx`, `fuzz`, `oracle`, `finding`, and `wordlist` utilities.

### `ngehe chain <findings.jsonl>`

Guided exploit walkthrough. After any scan you have a JSONL with per-rule playbook hints in the `next` field; `ngehe chain` walks them interactively, displays the playbook for each critical/high finding, and prompts you to type/confirm the command to run. The command shells out via `bash` with stdio attached, so reverse-shell listeners, evil-winrm sessions, sqlmap prompts, etc. behave normally. **The bridge between "ngehe found a thing" and "I have a shell."**

```bash
ngehe surface -d example.com --nuclei --out findings.jsonl
ngehe chain findings.jsonl
ngehe chain findings.jsonl --all     # include medium / low findings, not just critical / high
```

Best run inside the container — every handoff tool (`hashcat`, `evil-winrm`, `netexec`, `impacket-*`, etc.) is pre-installed.

## Container

Don't want to install on your host? Use the bundled Docker image instead. Works on Linux, macOS (Apple Silicon + Intel), Windows / WSL — same image, no platform-specific compile headaches.

```bash
# Pull + scan in one go (the wrapper handles mounts/network/templates).
./scripts/ngehe surface -d example.com --nuclei
./scripts/ngehe box --target 10.10.11.5 --markdown box.md

# Drop into a shell with every tool on PATH:
./scripts/ngehe --shell
```

The image is ~2GB and bundles **the full web + box pentest toolkit** — ngehe is the primary entry point, but every tool you'd reach for during an engagement is on PATH:

- **ngehe + integrations**: nuclei (templates pre-baked) + amass + subfinder + httpx
- **Web**: nmap, sqlmap, ffuf, gobuster, dalfox
- **AD / box**: hashcat, impacket (full Python suite), netexec, evil-winrm, kerbrute, enum4linux-ng, smbclient, ldap-utils, bloodhound-python
- **Networking**: ncat, socat, openssh-client, proxychains4
- **Reference**: PayloadsAllTheThings cloned to `/opt/PayloadsAllTheThings`

No `--with-extras`, no `apt install`, no Python venv juggling, no `nuclei -update-templates` — pull once and every command works.

Build locally:

```bash
docker build -t ngehe:dev .
NGEHE_IMAGE=ngehe:dev ./scripts/ngehe doctor
```

Or use docker compose:

```bash
docker compose run --rm ngehe surface -d example.com
```

Raw `docker run` (skip the wrapper):

```bash
docker run --rm -it \
  --network host \
  -v "$PWD:/work" \
  -v ngehe-nuclei-templates:/root/nuclei-templates \
  ghcr.io/chud-lori/ngehe:latest surface -d example.com --nuclei
```

**macOS caveat:** Docker Desktop's `--network host` runs through a VM bridge. Scanning your own LAN works (RFC1918 reachable), but a few edge cases (raw-socket nmap modes) need `--cap-add=NET_RAW --cap-add=NET_ADMIN`. ngehe uses TCP connect scans by default, so the basic flow just works.

See [Dockerfile](Dockerfile) for build args (template skip, version pinning) and [compose.yaml](compose.yaml) for the canonical mount layout.

## Install

One-line installer (detects brew/apt/dnf/pacman/apk, installs `nmap`, builds + drops ngehe in `/usr/local/bin`):

```bash
git clone https://github.com/chud-lori/ngehe.git
cd ngehe
sudo ./install.sh                         # base install (ngehe + nmap)
sudo ./install.sh --with-extras           # also install nuclei + amass + subfinder + httpx
```

Non-root install to `~/.local/bin`:

```bash
PREFIX=$HOME/.local ./install.sh --with-extras
```

Uninstall:

```bash
sudo ./install.sh --uninstall                   # ngehe binary only
sudo ./install.sh --uninstall --with-extras     # also remove nuclei + amass + subfinder + httpx
sudo ./install.sh --uninstall --purge           # nuke EVERYTHING: above + nmap + ~/nuclei-templates
                                                # + tool config dirs + Go module cache
```

The plain `--uninstall` is conservative: it only removes the `ngehe` binary. `--with-extras` also removes the four scanner packages (apt remove / brew uninstall / `~/go/bin/*` / `~/.local/bin/*`) but keeps config dirs and the nuclei template cache.

`--purge` is the full wipe — drops nmap, deletes `~/nuclei-templates` (~1GB), removes config dirs in `~/.config/{nuclei,subfinder,amass,httpx}`, runs `go clean -modcache` to clear any leftover modules (including the `vulncheck-oss/go-exploit` webshell fixtures that some scanners flag). The Go toolchain itself is left alone (ngehe never installed it); the purge step prints the apt/brew/tarball-removal commands if you want to remove Go too.

Manual:

```bash
go build -o ngehe .
sudo install -m 0755 ngehe /usr/local/bin/ngehe
# you still need: brew install nmap   (macOS)
#                 sudo apt install nmap  (debian/ubuntu)
```

After install, verify deps:

```bash
ngehe doctor
```

Required: `nmap` (for `ngehe box`). Recommended: `hashcat` (crack krb5asrep / krb5tgs / JWT hashes), `sqlmap` (deeper SQLi after ngehe flags it), `bloodhound` (ingest ngehe's AD JSON).

## HTB Quick Start

```bash
# 1. Full-spectrum scan (requires nmap). Hits every open port.
ngehe box --target 10.10.11.5 --domain target.htb --markdown box.md

# 2. If a web app is in scope: capture real traffic (Burp / mitmproxy / browser HAR).
# 3. Write ngehe.yaml with sessions + default-creds URLs.
ngehe init --out ngehe.yaml

# 4. Active web scan — every detector.
ngehe scan --har capture.har --config ngehe.yaml --markdown web.md
```

For AD-heavy boxes, after `ngehe box` reveals LDAP/Kerberos services and surfaces user names, hand off to `impacket` or use ngehe's lightweight `kerberos asrep` / `kerberoast` modules from a future CLI subcommand wiring. The Go-side primitives are in `internal/scanner/kerberos/`.

See [HOWTO.md](HOWTO.md) for a full walkthrough.

## Output

Every finding includes a **`next` field** — concrete exploit guidance for that bug class. The markdown report opens with a **"Suggested attack chain"** section that orders the critical/high findings and gives you the literal payload / curl command / hashcat invocation to move from finding to shell.

JSONL excerpt (one finding per line):

```json
{
  "rule": "ssti",
  "severity": "critical",
  "method": "GET",
  "url": "http://target/api/greet?name=%7B%7B1337%2A1331%7D%7D",
  "path": "/api/greet",
  "param": "query:name",
  "payload": "{{1337*1331}}",
  "evidence": "Jinja2/Twig/Liquid evaluated 1337*1331 → 1779547",
  "why": "template expression was evaluated server-side — SSTI confirmed (RCE chain available)",
  "next": "RCE via template. Engine identified in evidence — chain to OS commands:\n  Jinja2:    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n  Twig:      {{['id']|filter('system')}}\n  ..."
}
```

Filter to actionable findings:

```bash
# Just the attack-chain candidates
jq 'select(.severity == "critical" or .severity == "high") | {rule, url, next}' findings.jsonl
```

## Companion Tools

ngehe is the active component of a three-tool defensive/offensive stack:

- [cornela](https://github.com/chud-lori/cornela) — Linux container kernel auditor (eBPF). Host hardening, escape-risk detection.
- [milog](https://github.com/chud-lori/milog) — nginx + system monitor. Log scanning, exploit detection, host-integrity audits.
- **ngehe** — web pentest CLI. Active testing during authorized assessments and CTFs.

The three tools share a JSONL output convention.

## Safety Model

ngehe is for authorized engagements.

- Use only against systems you own, have written permission to test, or that are explicitly designed as CTF / HTB targets.
- Some detectors send payloads (SLEEP, command-injection markers, traversal sequences) that may trigger WAF alerts or get you blacklisted. Coordinate with the asset owner before scanning production.
- ngehe does NOT exploit findings end-to-end — it identifies them. SSTI → RCE, SQLi → data extraction, etc. require manual follow-up.
- Capture and config files contain real tokens. Treat them as secrets.

## License

Apache-2.0. SecLists wordlists are MIT; see `internal/wordlist/NOTICE.md`.
