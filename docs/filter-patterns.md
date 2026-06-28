# Filter pattern cookbook

A curated library of regular expressions for the `sources[].pattern` field, grouped
by the kind of service you are protecting. Copy a block, point `target` at your
log source, and dry-run it with `simple-blocker check` before trusting it.

Every pattern here is designed to catch *malicious behaviour* — vulnerability
scanners, brute-force attempts, path traversal, injection probes — while leaving
legitimate traffic untouched.

---

## Before you copy a pattern

A few rules that apply to **every** pattern in this document:

1. **One named capture group `(?P<ip>...)` is mandatory.** The daemon extracts
   the offending address from it. Without it the source fails to load. (A bare
   first capturing group is accepted as a fallback, but always name it `ip`.)

2. **The engine is Go's RE2 (`regexp`), not PCRE.** This is fast and safe (no
   catastrophic backtracking) but it means **no lookahead `(?=...)`, no
   lookbehind `(?<=...)`, and no backreferences `\1`.** If you paste a pattern
   from a PCRE/fail2ban source that uses those, it will fail to compile. Rewrite
   it with plain alternation and character classes.

3. **One match = one offense.** The pattern is run against each log line; a line
   that matches counts once toward the sliding `window`. Offenses accumulate per
   IP and trip the `ban_schedule`. So a pattern that is *too broad* bans real
   users; a pattern that is *too narrow* misses scanners. Tune with `check`.

4. **The captured token is validated.** Anything the `(?P<ip>...)` group grabs
   that is not a real IP is silently ignored, so a permissive IP class is safe.
   Two reusable IP classes:

   | Use | Snippet |
   |-----|---------|
   | IPv4 only | `(?P<ip>\d{1,3}(?:\.\d{1,3}){3})` |
   | Dual-stack, **anchored** (capture sits right after a fixed delimiter like `from ` or `[`) | `\[?(?P<ip>[0-9a-fA-F:.]+)\]?` |
   | Dual-stack, **floating** (capture follows `.*` / a variable run of words) | `(?P<ip>\d{1,3}(?:\.\d{1,3}){3}\|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)` |

   Use a dual-stack class when you have `firewall.enforce_ipv6: true` and your
   service is reachable over IPv6; otherwise the IPv4 class is tighter.

   > **Why two dual-stack forms?** The permissive `[0-9a-fA-F:.]+` also matches
   > the hex letters `a`–`f`, so if it follows a lazy `.*?` it will happily grab
   > the first *letter* of an ordinary word (the `f` in `Failed`, the `e` in
   > `Client`) instead of the address. The daemon then discards that non-IP and
   > **never bans**. Only use the permissive form when the capture is immediately
   > preceded by a fixed literal (`from `, `[`, `'@'`). When the capture floats
   > after `.*`, use the IP-*shaped* form above — its IPv6 alternative requires a
   > colon and its IPv4 alternative requires a dotted quad, so words can't match.

5. **Anchor to the offending request, not the response alone.** For web logs,
   pair the suspicious path with a `404`/`403`/`444` status where you can — a
   `200` to `/wp-login.php` on a real WordPress site is a legitimate user.

6. **`(?i)` makes a pattern case-insensitive.** Useful for path probes
   (`/WP-Admin/`, `/.ENV`) that scanners randomly case to dodge naive filters.
   Put it at the very start of the pattern: `(?i)...`.

7. **Test before you deploy.** `simple-blocker check -source <name>` (add
   `-follow` to stream) prints every matching line with the captured IP
   highlighted and the action that *would* be taken — and bans nothing.

> **Log format assumption.** The web patterns below assume the common/combined
> access-log format, where the client IP is the **first** field on the line
> (`45.9.1.2 - - [date] "GET /path HTTP/1.1" 404 ...`). If you run behind a
> reverse proxy / CDN, the first field may be the proxy. Log and match the real
> client IP (e.g. nginx `$http_x_forwarded_for` / a `realip` module, or Apache
> `mod_remoteip`) or you will ban your own proxy.

---

## Web servers (nginx / Apache / any HTTP access log)

The single richest source of scanner noise. Below, several focused patterns —
prefer **several narrow sources** over one giant alternation, so `check` output
and tuning stay legible. All assume combined-log format (client IP first).

### 1. WordPress / CMS login & admin probes

Scanners hammer `wp-login.php`, `/wp-admin/`, `xmlrpc.php` (brute force +
amplification), and common CMS admin panels even on sites that don't run them.

```yaml
- type: docker            # or journal, file — whatever carries your access log
  name: web-cms-probe
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"[A-Z]+\s+\S*(?:/wp-login\.php|/wp-admin/|/xmlrpc\.php|/wp-json/wp/v2/users|/administrator/|/typo3/|/bitrix/)\S*'
```

> If you *do* run WordPress, scope this to failures so real logins survive — add
> a trailing status class: `...\S*\s+HTTP/\d\.\d"\s+(?:401|403|404)\s`.
>
> This list sticks to product-specific admin paths. Generic login endpoints like
> `/admin/login` or `/user/login` are deliberately left out — they're legitimate
> on many custom apps, and matching them status-less would ban real users. If you
> want to watch them, add them only with the failure-status class above.

### 2. Sensitive-file & secret disclosure attempts

Probes for credentials, configs, dotfiles, backups, and version-control dirs.
These paths should essentially never be requested by a legitimate browser, so
matching the path alone (any status) is safe and catches the scanner on its
*first* request — before it finds anything.

```yaml
- type: docker
  name: web-secret-probe
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"[A-Z]+\s+\S*(?:/\.env|/\.git/|/\.svn/|/\.aws/|/\.ssh/|/etc/passwd|/etc/shadow|/wp-config\.php|/config\.php\.bak|/\.htpasswd|/\.htaccess|/server-status|/\.DS_Store|/credentials|/id_rsa|/database\.yml|/settings\.py)\S*'
```

### 3. Path-traversal & local-file-inclusion

The `../` ladder and its URL-encoded forms (`%2e%2e`, `..%2f`, `....//`), plus
classic LFI targets like `/proc/self/environ`.

```yaml
- type: docker
  name: web-traversal
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"[A-Z]+\s+\S*(?:\.\./|\.\.%2f|%2e%2e%2f|%252e|\.\.\\|/proc/self/|/etc/passwd|win\.ini|boot\.ini)\S*'
```

### 4. Risky file extensions returning 404 (generic scanner sweep)

The catch-all from `config.example.yaml`: any request for a script/archive/
backup extension that 404s is almost certainly a scanner walking a wordlist.

```yaml
- type: docker
  name: web-badext-404
  target: my-nginx-1
  pattern: '(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?"[A-Z]+\s+\S*\.(?:php|phtml|php5|asp|aspx|jsp|cgi|exe|sh|sql|bak|old|swp|gz|tar|zip|7z|env|ini|log|xml)\S*\s+HTTP/\d\.\d".*\s404\s'
```

### 5. Web-shell & backdoor filenames

Common dropped-shell names (`shell.php`, `c99.php`, `alfa.php`, `wso.php`) and
upload-probe paths.

```yaml
- type: docker
  name: web-shell-probe
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"[A-Z]+\s+\S*(?:shell|c99|c100|r57|wso|alfa|b374k|adminer|filemanager|cmd\.php|eval-stdin\.php|backdoor)\S*\.php\S*'
```

### 6. SQL-injection & XSS in the query string

Signature tokens (`union select`, `or 1=1`, `sleep(`, `<script>`, `onerror=`)
in the request line. Kept conservative to limit false positives on
search/analytics traffic.

```yaml
- type: docker
  name: web-injection
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"[A-Z]+\s+\S*(?:union(?:\s|\+|%20)+select|or(?:\s|\+|%20)+1=1|sleep\(\d|benchmark\(|information_schema|<script>|onerror=|javascript:|/etc/passwd|concat\(|0x[0-9a-f]{8})\S*'
```

### 7. Tooling & vuln-scanner user agents

Catches scanners that announce themselves (sqlmap, nikto, nmap, masscan, etc.).
Trivially spoofed, so treat as a low bar — but it nets the lazy ones cheaply.
This one matches the **User-Agent** field, so it works on combined-log format.

```yaml
- type: docker
  name: web-bad-agent
  target: my-nginx-1
  pattern: '(?i)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|fimap|acunetix|netsparker|httrack|python-requests|curl/[0-9]|go-http-client|libwww-perl)\S*"'
```

### 8. Proxy / open-relay abuse (CONNECT & absolute-URI)

Bots probing whether your server is an open forward proxy.

```yaml
- type: docker
  name: web-proxy-abuse
  target: my-nginx-1
  pattern: '(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*"(?:CONNECT\s+\S+:\d+|[A-Z]+\s+https?://)'
```

---

## SSH (systemd journal)

The default source. SSH brute force is relentless; match the several failure
shapes `sshd` emits. The dual-stack capture handles IPv6 brute force too.

The IP here *floats* after `.*?`, so it uses the IP-shaped dual-stack class (see
the caveat above) — the permissive class would grab the `f` in `Failed`. The
prefix is split into two alternatives because newer OpenSSH logs the address
*without* a `from`/`by` immediately before it — e.g. `Connection closed by
invalid user admin 1.2.3.4 port 22 [preauth]` — so that family is matched
separately (with the `user <name>` part optional, to also catch the bare
`Connection closed by 1.2.3.4` form).

```yaml
- type: journal
  name: ssh
  target: ssh                # systemd unit/identifier
  since: -1d
  pattern: '(?:(?:Failed password|Invalid user|authentication failure|Did not receive identification string|maximum authentication attempts exceeded|Bad protocol version identification).*?(?:from|by)\s+|Connection (?:closed|reset) by (?:(?:invalid |authenticating )?user \S+ )?)\[?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)\]?'
```

> Keep the original narrow `Invalid user \S+ from \[?(?P<ip>[0-9a-fA-F:.]+)\]?`
> source too if you want separate offense tallies — its capture is anchored
> right after `from `, so the permissive class is safe there. Always `check`
> this broader one: SSH log wording varies by distro/OpenSSH version.

---

## Mail servers

### Postfix / Dovecot — SASL auth failures (journal)

Brute force against SMTP-AUTH and IMAP/POP login. Run **one source each** for
Postfix and Dovecot — their log shapes differ, and RE2 has no backreferences so
you can't reuse one capture across both with `(?P=ip)`. In both, the IP is
anchored (after `[` / `rip=`), so the permissive dual-stack class is safe.

```yaml
# Postfix SASL auth failures
- type: journal
  name: postfix-auth
  target: postfix
  since: -1d
  pattern: 'warning:\s+\S+\[(?P<ip>[0-9a-fA-F:.]+)\]:\s+SASL\s+\S+\s+authentication failed'

# Dovecot IMAP/POP/managesieve login failures
- type: journal
  name: dovecot-auth
  target: dovecot
  since: -1d
  pattern: '(?:imap|pop3|managesieve)-login: (?:Disconnected|Aborted login|Auth failed).*\brip=(?P<ip>[0-9a-fA-F:.]+)'
```

### Postfix — relay / recipient abuse

Spambots probing for an open relay or doing recipient enumeration.

```yaml
- type: journal
  name: mail-relay-abuse
  target: postfix
  since: -1d
  pattern: 'NOQUEUE:\s+reject:.*\[(?P<ip>[0-9a-fA-F:.]+)\].*(?:Relay access denied|User unknown|Recipient address rejected|blocked using)'
```

---

## FTP (vsftpd / proftpd, journal)

```yaml
- type: journal
  name: ftp-auth
  target: vsftpd
  since: -1d
  pattern: '(?:FAIL LOGIN|authentication failure|Login failed).*?\[?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)\]?'
```

---

## Databases & caches exposed to the network

If a DB is internet-reachable (it shouldn't be), repeated auth failures are
attacks. Match the server's auth-failure line.

```yaml
# MySQL / MariaDB (general_log or error log carrying "Access denied")
- type: journal
  name: mysql-auth
  target: mysql
  since: -1d
  pattern: "Access denied for user '\\S+'@'(?P<ip>[0-9a-fA-F:.]+)'"

# PostgreSQL
- type: journal
  name: postgres-auth
  target: postgresql
  since: -1d
  pattern: '(?:password authentication failed|no pg_hba\.conf entry) for.*?(?:host|client)\s+"?(?P<ip>[0-9a-fA-F:.]+)"?'

# Redis (unauthenticated command probes / AUTH failures)
- type: docker
  name: redis-probe
  target: my-redis-1
  pattern: '(?i)(?:WRONGPASS|NOAUTH|unauthenticated).*?(?:addr=)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
```

---

## VPN / remote access

```yaml
# OpenVPN auth failures
- type: journal
  name: openvpn-auth
  target: openvpn
  since: -1d
  pattern: '(?:AUTH_FAILED|TLS Error|VERIFY ERROR).*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+'
```

---

## Application-level brute force (your own app logs)

If your app logs failed logins, give it a structured marker (e.g.
`auth.failed ip=1.2.3.4`) and match that — far more robust than parsing prose.

```yaml
- type: docker
  name: app-login-fail
  target: my-app-1
  pattern: 'auth\.failed\b.*\bip=(?P<ip>[0-9a-fA-F:.]+)'
```

---

## Tuning & avoiding self-inflicted outages

- **Always `check` first**, ideally with `-follow` over real traffic for a few
  minutes. Look for any legitimate request the pattern catches.
- **Whitelist your own infrastructure** — monitoring, uptime checks, your office
  IP, CI runners, the reverse proxy/CDN egress ranges — in the config
  `whitelist`. Whitelist always wins, even against a tripped pattern.
- **Match failures, not paths, on services you actually run.** A path-only
  WordPress rule is perfect on a host with no WordPress and dangerous on one
  with it.
- **Pick thresholds per pattern's confidence.** High-confidence sources
  (`/.env`, `/etc/passwd`, web-shell names) justify a low `ban_schedule`
  threshold — those are never legitimate. Fuzzier ones (bad user-agent, generic
  404 sweep) deserve a couple of strikes' grace via the offense count.
- **Behind a proxy, capture the real client IP** (see the log-format note up
  top) or your bans hit the proxy and take down everyone.
- **Prefer several narrow sources over one mega-regex.** Separate sources keep
  `check` output and `status` offense tallies meaningful, and one
  false-positive prone rule won't poison the rest.
- **Watch your own logs.** `journalctl -u simple-blocker -f` shows every ban;
  if a ban looks wrong, `simple-blocker whitelist add <ip>` lifts it and
  prevents a recurrence.

---

## Quick reference — reusable fragments

| Need | Fragment |
|------|----------|
| IPv4 capture | `(?P<ip>\d{1,3}(?:\.\d{1,3}){3})` |
| Dual-stack, anchored after a literal (bracketed v6 ok) | `\[?(?P<ip>[0-9a-fA-F:.]+)\]?` |
| Dual-stack, floating after `.*` (won't grab words) | `(?P<ip>\d{1,3}(?:\.\d{1,3}){3}\|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)` |
| Case-insensitive whole pattern | prefix with `(?i)` |
| HTTP method + path | `"[A-Z]+\s+\S*<PATH>\S*` |
| Trailing status class | `\s+HTTP/\d\.\d"\s+(?:401|403|404|444)\s` |
| Any of several literals | `(?:foo|bar|baz)` |

Remember: **no** `(?=...)`, `(?<=...)`, or `\1` — RE2 doesn't support them.
