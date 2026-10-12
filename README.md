# Home SOC Lab: Building a Detection Pipeline with Wazuh and DVWA

<img width="1919" height="970" alt="Screenshot 2026-09-07 111845" src="https://github.com/user-attachments/assets/7cd70b13-185f-4fcd-8442-a735cc7520d9" />

## Overview

This project involved building a small-scale Security Operations Center (SOC) lab on repurposed hardware to practice both offensive and defensive security skills. The goal was to deploy an intentionally vulnerable web application, monitor it with a SIEM, and write custom detection rules to catch real attacks as they happen, end to end, from exploitation to alert, including full investigation of each alert.

## Hardware

- Dell Inspiron 15 (repurposed from a prior OpenMediaVault NAS setup)
- Intel Celeron 1007U (dual-core, 1.5GHz)
- 3.7GB RAM
- 465GB storage

This is well below the officially recommended specs for the tools used (Wazuh's indexer alone recommends 4GB+), which made resource management and startup timing a real, ongoing constraint throughout the build.

## Architecture

```
[Attacker Browser / Hydra] --> [DVWA container (Apache + PHP)] --> logs to host filesystem
                 |                                                         |
                 v                                                         v
         [SSH on host]  <---------------------------------------  [Wazuh Agent on host]
                                                                            |
                                                                            v
                                                           [Wazuh Manager - custom rules]
                                                                            |
                                                                            v
                                                          [Wazuh Indexer + Dashboard]
```

**Stack components (all containerized via Docker):**
- **Portainer**: visual Docker management
- **DVWA (Damn Vulnerable Web Application)**: intentionally vulnerable target for offensive practice
- **Wazuh Manager, Indexer, Dashboard**: SIEM stack for log analysis, alerting, and visualization
- **Wazuh Agent**: installed directly on the Debian host (not inside the DVWA container) to monitor host-level activity, DVWA's Apache logs, SSH authentication logs, and a File Integrity Monitoring target directory

## Build Process

1. Wiped a prior OpenMediaVault installation and performed a clean Debian install.
2. Installed Docker and Docker Compose.
3. Deployed Portainer for visual container management.
4. Deployed DVWA as an attack target.
5. Deployed the Wazuh single-node stack (manager, indexer, dashboard) via Docker Compose.
6. Installed a Wazuh agent on the host and enrolled it with the manager.
7. Mounted DVWA's Apache logs to the host filesystem so the agent could read them.
8. Wrote and debugged custom Wazuh detection rules for SQL injection and XSS.
9. Created a disposable test account and used Hydra to simulate an SSH brute-force attack.
10. Wrote a correlation rule to detect brute-force patterns (not just individual failed logins).
11. Set up File Integrity Monitoring on a copy of DVWA's web root and verified real-time change detection.
12. Added command injection coverage for DVWA's command execution page, after working out what Apache's access log can and cannot show.
13. Connected MyTRE, a custom ATT&CK-mapped adversary emulation framework, as an automated attack source, with a small HTTP receiver on the lab host whose log is also collected by the Wazuh agent.
14. Extended File Integrity Monitoring to `~/.ssh` and `/tmp` and wrote custom rules for SSH key persistence and attacker tool drops.

## Custom Detection Rules

| Rule ID | Detects | Trigger |
|---|---|---|
| 100010 | SQL Injection | URL-encoded single quote (`%27`) |
| 100011 | SQL Injection | SQL keywords (`UNION`, `SELECT`) in URL |
| 100012 | XSS (Cross-Site Scripting) | Encoded `<script>` tags in URL |
| 100013 | SSH Brute-Force | 5+ failed SSH logins from the same source IP within 60 seconds (correlation rule, built on top of Wazuh's default `sshd` failure rule 5760) |
| 100014 | Command Injection (endpoint) | HTTP POST to `/vulnerabilities/exec/` (level 7, parent rules `31100,31108`) |
| 100015 | MyTRE receiver telemetry | Any receiver log line containing `event=http_request` (level 3) |
| 100016 | MyTRE receiver telemetry | Receiver request that returned `status=200` (level 5, child of 100015) |
| 100017 | SSH key persistence | `authorized_keys` modified or added, via FIM (level 10, parents `550,554`) |
| 100018 | Attacker tool transfer | New file added under `/tmp`, via FIM (level 8, parent `554`) |

All were tested and verified using `wazuh-logtest` where applicable, then confirmed live against real attack traffic in the dashboard.

## Attack Scenario 1: SQL Injection & XSS

(See "Debugging Process" below for the full story on rules 100010/100011/100012.)

- SQL injection via DVWA's SQLi module (`1' OR '1'='1`) triggered rule 100010, level 10 alert.
- Reflected XSS via a quote-free payload (`<script>alert(1)</script>`) triggered rule 100012, level 10 alert, with no overlap.

## Attack Scenario 2: SSH Brute-Force (Simulated with Hydra)

**Setup:** Created a disposable low-privilege test account (`bruteforcetest`) with a weak password, rather than risk real credentials. Used THC-Hydra, a real-world penetration testing tool, to attempt a dictionary-based login attack over SSH.

**Attack:**
```
hydra -l bruteforcetest -P passwords.txt ssh://<host> -V
```
5 incorrect passwords followed by 1 correct one (`password`) were attempted in rapid succession.

**Detection gap identified:** Wazuh's default ruleset logs every failed SSH attempt individually (rule 5760, level 5) but does not escalate repeated failures into a higher-severity pattern alert. This is a known limitation of relying on defaults alone.

**Tuning performed:** Wrote a correlation rule (100013) using Wazuh's `frequency`/`timeframe`/`same_source_ip` mechanism to escalate 5+ failures from one IP within 60 seconds into a single level-10 brute-force alert.

**Investigation of the resulting alert:**
- `data.srcip: 192.168.0.115`, `data.dstuser: bruteforcetest` identify the source and the targeted account
- `full_log` and `previous_output` fields show the raw, correlated sshd failure log lines, including sequential source ports, a signature of automated/scripted login attempts rather than manual human retries
- **Conclusion:** Pattern consistent with automated credential-stuffing/brute-force activity. Real-world next steps would include checking for a subsequent successful login from the same source, and considering IP-based rate-limiting or MFA enforcement.

## Attack Scenario 3: File Integrity Monitoring (FIM)

**Setup:** Configured Wazuh's `syscheckd` module to monitor a copy of DVWA's web root in real time (`realtime="yes"` in `ossec.conf`), rather than relying on the default 12-hour scheduled scan interval.

**Attack:** Appended unauthorized content to `login.php` to simulate a file tampering / backdoor-planting scenario, a common real-world attack against web application login pages.

**Detection:** Wazuh's default rule 550 ("Integrity checksum changed") fired within seconds, in real-time mode.

**Investigation of the resulting alert:**
- Cryptographic proof of change: MD5, SHA1, and SHA256 hashes all differ between `*_before` and `*_after` fields
- File size change (4243 to 4323 bytes) and precise modification timestamps provided
- `full_log` includes a clean, human-readable summary suitable for a ticket/report
- Alert is automatically mapped to compliance frameworks (PCI DSS 11.5, HIPAA 164.312.c.1/c.2, NIST 800-53 SI.7, GDPR II_5.1.f), demonstrating how FIM ties directly into real compliance requirements
- **Conclusion:** Unauthorized modification of a security-sensitive application file (login page) was detected in real time with full forensic detail (who, what, when, and cryptographic proof), consistent with how a real SOC would catch a webshell or credential-harvesting backdoor being planted.

## Attack Scenario 4: Command Injection

**Setup:** DVWA's Command Injection module (security level Low) passes user input from a ping form straight into a shell command.

**Attack:** Submitted `127.0.0.1; whoami` and later `127.0.0.1; id` in the form. The page returned the normal ping output followed by `www-data` and `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, confirming arbitrary commands were running on the server as the web server user.

**Detection gap identified:** The form submits its input as an HTTP POST body, and Apache's access log never records POST bodies. The raw log line for the attack showed only `POST /vulnerabilities/exec/ HTTP/1.1`, with no trace of `; whoami`. Payload-matching rules like the SQLi and XSS ones (which read the URL) had nothing to match.

**Tuning performed:** Wrote rule 100014 to alert on any POST to the vulnerable endpoint, at level 7 rather than 10. It flags that the vulnerable page was used, but it cannot tell a harmless `127.0.0.1` from an injected command, so the lower severity is deliberate. The rule did not fire at first: `wazuh-logtest` showed Wazuh's built-in rule 31108 ("Ignored URLs (simple queries)", level 0) swallowing the plain URL before a rule built on parent 31100 could see it. Declaring both parents (`<if_sid>31100,31108</if_sid>`) fixed it.

**Investigation of the resulting alert:**
- Alert showed `rule.id: 100014`, level 7, groups including `command_injection`
- `data.protocol: POST`, `data.url: /vulnerabilities/exec/`, and `data.srcip` identify the request and its source
- `full_log` is the raw Apache access line, which confirms what the log did and did not capture
- **Conclusion:** Use of a known-vulnerable command execution endpoint was detected end to end. Detecting the injected command itself would need a different log source, such as auditd watching for `www-data` spawning shell commands like `whoami` or `id`, which is a planned next step.

## Attack Scenario 5: Automated Red Team Run with MyTRE

**Setup:** MyTRE (Python, ATT&CK-mapped adversary emulation, 16 technique modules) runs from a separate Windows machine against the lab host. Its 16-stage assessment campaign covers SSH access, command injection against DVWA, file upload, persistence and more. A small HTTP receiver on the host (port 8081, run as a systemd service) accepts uploads, and its log is collected by the Wazuh agent.

**Result:** 15 of 16 stages succeeded in 61.54 seconds. The one failure was the vulnerability scan stage, which is the correct outcome because the host is patched and no CVE matched.

**What Wazuh caught during the run:**
- Rule 100014 fired live on the command injection stage
- Default SSH authentication rules (5715, 5501, 5502, 5740) fired on every SSH stage
- Receiver telemetry rule 100016 fired on accepted uploads (after the fix described under "Debugging Process")

**Conclusion:** The red/blue loop works end to end: an automated attack run produces matching alerts from custom and default rules on the same host.

## Attack Scenario 6: SSH Key Persistence (FIM on `~/.ssh`)

**Setup:** Added `/home/fareed/.ssh` to the agent's real-time FIM configuration (`check_all="yes"`), monitoring the whole folder so a new key file is caught as well as edits to `authorized_keys`. `report_changes` was deliberately left off so private key contents are never stored in Wazuh's diff cache.

**Attack:** Appended an unauthorized public key to `authorized_keys`, the way an attacker would plant persistence after getting a foothold.

**Detection:** Wazuh's default rule 550 fired within seconds, but it labels the event as generic file tampering (T1565.001, Impact). Custom rule 100017 matches only `authorized_keys` and raises the alert to level 10 with the correct mapping, **T1098.004 (SSH Authorized Keys, Persistence)**.

**Investigation of the resulting alert:**
- The size change (408 to 481 bytes) and the MD5, SHA1 and SHA256 before/after values prove the file changed and how
- Owner, permissions and modification times identify the account and the time of change
- **Conclusion:** A persistence attempt was detected in real time with full forensic detail. Real-world next steps would be to check the added key against known keys and review recent logins for that account.

## Attack Scenario 7: Attacker Tool Drop in `/tmp`

**Setup:** Added `/tmp` (a RAM-backed tmpfs, nearly empty on this host) to real-time FIM so new files are reported as they appear.

**Attack:** Wrote a fake tool (`/tmp/fim-test-tool2.sh`) into `/tmp`, simulating an attacker staging a tool after initial access. This is the same behavior MyTRE's upload stage performs.

**Detection:** Default rule 554 ("File added to the system", level 5) fires on any new file. Custom rule 100018 narrows it to files under `/tmp` and raises it to level 8 as a possible tool transfer, mapped to **T1105 (Ingress Tool Transfer)**.

**Investigation of the resulting alert:** The alert gives the file path, size, permissions, owner and SHA256, enough to look the file up on a threat intelligence service.

**Known limitation:** The ATT&CK fields did not appear in the alert output for rule 100018, even though the rule definition contains the mapping and the technique exists in Wazuh's ATT&CK database. The cause was not found, so the mapping is recorded in this document and the rule file.

## Debugging Process (Key Findings)

Getting these rules working was not a straight line, and the debugging process itself is arguably the most demonstrable part of this project:

- **Wrong parent rule ID:** Initial SQLi rules referenced `if_sid 31108`; using `wazuh-logtest` to trace a raw log line through decoding showed the actual matching rule was `31100`. Root cause of rules silently never firing.
- **The same trap from the other side:** For the command injection rule, `31100` was the wrong parent. A plain URL with no special characters is matched by rule 31108 (level 0, ignored) first, so the rule needed both parents. Lesson: the right parent depends on what the URL looks like, and `wazuh-logtest` is the only reliable way to find out.
- **URL encoding blind spot:** Rules had to match the URL-encoded form of payloads (`%27`), not literal raw text, since browsers always encode special characters in requests.
- **POST bodies are invisible to access logs:** Apache logs the request line, not the form data, so injection in a POST body cannot be matched by content. Detection fell back to the endpoint, with a lower severity to reflect the lower confidence.
- **Manager restarts drop the agent connection:** Each manager restart (needed to reload rule changes) briefly disconnected the agent, causing tests run during that window to silently produce no results.
- **Rule overlap / false positive:** An XSS payload containing a quote character also matched the SQLi rule, since Wazuh's rule engine stops at the first match. A `negate` condition was attempted and didn't behave as expected; the decision was made to accept and document the overlap rather than over-engineer detection logic for a lab environment.
- **XML syntax error:** A raw, unencoded `<script>` tag inside a rule's `<url>` field broke XML parsing silently. Fixed by using only the encoded form.
- **Receiver telemetry rule never fired live:** Rule 100016 matched in offline testing but produced no live alerts. The original rule 100015 matched on the text `mytre_receiver`. The log timestamp format and the collector's log format were ruled out one at a time with `wazuh-logtest`, and a one-line change to match `event=http_request` instead fixed it. Why the original match failed was not fully explained, so the fix is verified but the root cause is not.
- **Testing against the wrong address:** A test request to `localhost` failed because the receiver listens only on the host's LAN address. A failed test was the test's fault, not the pipeline's, which is why each step was checked before changing any rule.
- **Safe-change routine:** Every rule or config edit was preceded by a timestamped backup, followed by one change, validation with `wazuh-analysisd -t` (exit code 0), a restart, and a live attack to confirm the alert.
- **Generic alerts, specific rules:** Default FIM rules 550 and 554 fire for any file, with generic ATT&CK tags. Child rules scoped to specific paths (`authorized_keys`, `/tmp`) turn them into alerts that name the attacker behavior.
- **Hydra against DVWA's web login failed entirely:** DVWA issues a fresh session cookie and CSRF token (`user_token`) on every page load, and the login form silently rejects submissions without a valid, current token. This made Hydra's stateless attack pattern unreliable against the web form. **Pivoted to SSH brute-forcing instead**, a more standard and reliable real-world brute-force target, and arguably a stronger demonstration since it required creating a dedicated test account and tuning a genuinely new correlation rule.
- **Docker volume mount overwrote container files:** Attempting to mount an empty host directory directly onto DVWA's `/var/www/html` inside the running container replaced (not merged with) the container's existing files, breaking DVWA. Resolved by instead using `docker cp` to take a one-time copy of the web root onto the host for FIM monitoring, avoiding any risk to the live container.

## Kill Chain & MITRE ATT&CK Mapping

Each detection rule was mapped against the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK to tie the lab's alerts back to standard industry frameworks:

| Rule | Incident | Kill Chain Stage | MITRE ATT&CK ID |
|---|---|---|---|
| 100010 | SQL Injection (encoded quote) | Exploitation | T1190 - Exploit Public-Facing Application |
| 100011 | SQL Injection (keywords) | Exploitation | T1190 - Exploit Public-Facing Application |
| 100012 | XSS (script tag) | Exploitation | T1190 - Exploit Public-Facing Application |
| 100013 | SSH Brute-Force | Exploitation (credential access attempt) | T1110.001 - Brute Force: Password Guessing |
| 100014 | Command Injection (endpoint) | Exploitation | T1190 - Exploit Public-Facing Application |
| 100017 | SSH key persistence (authorized_keys changed) | Installation (persistence) | T1098.004 - Account Manipulation: SSH Authorized Keys |
| 100018 | Tool dropped in `/tmp` | Installation / Command and Control (tool staging) | T1105 - Ingress Tool Transfer |
| 550 (FIM) | Unauthorized file modification | Installation (persistence/backdoor being planted) | T1505.003 - Server Software Component: Web Shell |

Rules 100015 and 100016 are lab telemetry for the MyTRE receiver, not attack detections, so they are not mapped. Note the distinction between the later stages: SQLi, XSS, command injection, and brute-force attempts all represent an attacker trying to gain an initial foothold (**Exploitation**), while the FIM alerts (web root tampering, SSH key changes, tools dropped in `/tmp`) represent a different stage entirely: an attacker who may already have access, planting something persistent or staging tools (**Installation**). Mapping alerts to the correct Kill Chain stage, not just the correct rule, is what turns a list of alerts into a coherent incident narrative.

## Operational Notes

- The Wazuh indexer (OpenSearch-based) takes 5-10 minutes to fully initialize on this CPU after every start. A shell script (`homelab.sh`) standardizes starting, stopping, and checking status of the full stack.
- Given RAM constraints, the stack is run on-demand rather than kept online continuously.
- The agent monitors in real time: the DVWA web root copy, `~/.ssh` and `/tmp`, plus scheduled scans of `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and `/boot`.
- Custom rules live in the manager's `local_rules.xml` (inside a Docker volume). Each edit follows a backup, validate, restart, test routine.
- Remote access to the lab (dashboard, SSH) is provided via Tailscale (WireGuard-based mesh VPN), avoiding any direct exposure of DVWA or Wazuh to the public internet.

## Skills Demonstrated

- Linux system administration (Debian install, systemd services, user/permission management)
- Docker and Docker Compose (multi-container orchestration, volume mounting, networking)
- SIEM deployment and configuration (Wazuh manager/indexer/dashboard)
- Log source onboarding (exposing containerized application logs to a host-based agent)
- Custom detection rule authoring, including both signature-based rules and stateful correlation rules (frequency/timeframe)
- Systematic debugging using purpose-built tooling (`wazuh-logtest`) rather than trial-and-error guessing
- Offensive tooling: THC-Hydra for credential brute-forcing
- Understanding of common web attack patterns (SQLi, XSS, command injection) and their encoded/real-world representations
- Red/blue loop: running an automated adversary emulation framework (MyTRE) and verifying which of its stages the SIEM catches
- Writing child rules that sharpen default FIM alerts into specific, ATT&CK-mapped detections (SSH key persistence, tool staging)
- Reasoning about log-source limitations (POST bodies absent from access logs) and setting alert severity to match detection confidence
- File Integrity Monitoring configuration and real-time alert investigation
- Full alert lifecycle investigation: trigger, verification via raw log/forensic data, conclusion
- Practical trade-off judgment (pivoting attack vectors when one proved unreliable; accepting rule overlap rather than over-engineering a lab environment)
- Secure remote access configuration (Tailscale VPN)

## Next Steps

- Detect the command injection payload itself (not just the endpoint) using auditd to watch for the web server user spawning shell commands
- Add a correlation rule for SSH brute force followed by a successful login (repeated 5716 failures, then 5715)
- Find out why the ATT&CK fields are missing from rule 100018 alerts
- Add privilege escalation simulation
- Investigate and resolve the host's IPv6 connectivity issue
- Patch the CVE-2021-35331-affected packages identified by Wazuh's vulnerability detection module
