# Home SOC Lab: Building a Detection Pipeline with Wazuh and DVWA

<img width="1919" height="970" alt="Screenshot 2026-09-07 111845" src="https://github.com/user-attachments/assets/7cd70b13-185f-4fcd-8442-a735cc7520d9" />

## Overview

This project involved building a small-scale Security Operations Center (SOC) lab on repurposed hardware to practice both offensive and defensive security skills. The goal was to deploy an intentionally vulnerable web application, monitor it with a SIEM, and write custom detection rules to catch real attacks as they happen — end to end, from exploitation to alert, including full investigation of each alert.

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
- **Portainer** — visual Docker management
- **DVWA (Damn Vulnerable Web Application)** — intentionally vulnerable target for offensive practice
- **Wazuh Manager, Indexer, Dashboard** — SIEM stack for log analysis, alerting, and visualization
- **Wazuh Agent** — installed directly on the Debian host (not inside the DVWA container) to monitor host-level activity, DVWA's Apache logs, SSH authentication logs, and a File Integrity Monitoring target directory

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

## Custom Detection Rules

| Rule ID | Detects | Trigger |
|---|---|---|
| 100010 | SQL Injection | URL-encoded single quote (`%27`) |
| 100011 | SQL Injection | SQL keywords (`UNION`, `SELECT`) in URL |
| 100012 | XSS (Cross-Site Scripting) | Encoded `<script>` tags in URL |
| 100013 | SSH Brute-Force | 5+ failed SSH logins from the same source IP within 60 seconds (correlation rule, built on top of Wazuh's default `sshd` failure rule 5760) |

All were tested and verified using `wazuh-logtest` where applicable, then confirmed live against real attack traffic in the dashboard.

## Attack Scenario 1: SQL Injection & XSS

(See "Debugging Process" below for the full story — rules 100010/100011/100012.)

- SQL injection via DVWA's SQLi module (`1' OR '1'='1`) → correctly triggered rule 100010, level 10 alert.
- Reflected XSS via a quote-free payload (`<script>alert(1)</script>`) → correctly triggered rule 100012, level 10 alert, with no overlap.

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
- `data.srcip: 192.168.0.115`, `data.dstuser: bruteforcetest` — identifies source and targeted account
- `full_log` and `previous_output` fields show the raw, correlated sshd failure log lines, including sequential source ports — a signature of automated/scripted login attempts rather than manual human retries
- **Conclusion:** Pattern consistent with automated credential-stuffing/brute-force activity. Real-world next steps would include checking for a subsequent successful login from the same source, and considering IP-based rate-limiting or MFA enforcement.

## Attack Scenario 3: File Integrity Monitoring (FIM)

**Setup:** Configured Wazuh's `syscheckd` module to monitor a copy of DVWA's web root in real time (`realtime="yes"` in `ossec.conf`), rather than relying on the default 12-hour scheduled scan interval.

**Attack:** Appended unauthorized content to `login.php` to simulate a file tampering / backdoor-planting scenario — a common real-world attack against web application login pages.

**Detection:** Wazuh's default rule 550 ("Integrity checksum changed") fired within seconds, in real-time mode.

**Investigation of the resulting alert:**
- Cryptographic proof of change: MD5, SHA1, and SHA256 hashes all differ between `*_before` and `*_after` fields
- File size change (4243 → 4323 bytes) and precise modification timestamps provided
- `full_log` includes a clean, human-readable summary suitable for a ticket/report
- Alert is automatically mapped to compliance frameworks (PCI DSS 11.5, HIPAA 164.312.c.1/c.2, NIST 800-53 SI.7, GDPR II_5.1.f) — demonstrating how FIM ties directly into real compliance requirements
- **Conclusion:** Unauthorized modification of a security-sensitive application file (login page) was detected in real time with full forensic detail (who, what, when, and cryptographic proof), consistent with how a real SOC would catch a webshell or credential-harvesting backdoor being planted.

## Debugging Process (Key Findings)

Getting these rules working was not a straight line, and the debugging process itself is arguably the most demonstrable part of this project:

- **Wrong parent rule ID:** Initial SQLi rules referenced `if_sid 31108`; using `wazuh-logtest` to trace a raw log line through decoding showed the actual matching rule was `31100`. Root cause of rules silently never firing.
- **URL encoding blind spot:** Rules had to match the URL-encoded form of payloads (`%27`), not literal raw text, since browsers always encode special characters in requests.
- **Manager restarts drop the agent connection:** Each manager restart (needed to reload rule changes) briefly disconnected the agent, causing tests run during that window to silently produce no results.
- **Rule overlap / false positive:** An XSS payload containing a quote character also matched the SQLi rule, since Wazuh's rule engine stops at the first match. A `negate` condition was attempted and didn't behave as expected; the decision was made to accept and document the overlap rather than over-engineer detection logic for a lab environment.
- **XML syntax error:** A raw, unencoded `<script>` tag inside a rule's `<url>` field broke XML parsing silently. Fixed by using only the encoded form.
- **Hydra against DVWA's web login failed entirely:** DVWA issues a fresh session cookie and CSRF token (`user_token`) on every page load, and the login form silently rejects submissions without a valid, current token. This made Hydra's stateless attack pattern unreliable against the web form. **Pivoted to SSH brute-forcing instead** — a more standard and reliable real-world brute-force target, and arguably a stronger demonstration since it required creating a dedicated test account and tuning a genuinely new correlation rule.
- **Docker volume mount overwrote container files:** Attempting to mount an empty host directory directly onto DVWA's `/var/www/html` inside the running container replaced (not merged with) the container's existing files, breaking DVWA. Resolved by instead using `docker cp` to take a one-time copy of the web root onto the host for FIM monitoring, avoiding any risk to the live container.

## Kill Chain & MITRE ATT&CK Mapping

Each detection rule was mapped against the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK to tie the lab's alerts back to standard industry frameworks:

| Rule | Incident | Kill Chain Stage | MITRE ATT&CK ID |
|---|---|---|---|
| 100010 | SQL Injection (encoded quote) | Exploitation | T1190 – Exploit Public-Facing Application |
| 100011 | SQL Injection (keywords) | Exploitation | T1190 – Exploit Public-Facing Application |
| 100012 | XSS (script tag) | Exploitation | T1190 – Exploit Public-Facing Application |
| 100013 | SSH Brute-Force | Exploitation (credential access attempt) | T1110.001 – Brute Force: Password Guessing |
| 550 (FIM) | Unauthorized file modification | Installation (persistence/backdoor being planted) | T1505.003 – Server Software Component: Web Shell |

Note the distinction between the two later stages: SQLi, XSS, and brute-force attempts all represent an attacker trying to gain an initial foothold (**Exploitation**), while the FIM alert represents a different stage entirely — an attacker who may already have access, modifying a file to plant something persistent (**Installation**). Mapping alerts to the correct Kill Chain stage, not just the correct rule, is what turns a list of alerts into a coherent incident narrative.

## Operational Notes

- The Wazuh indexer (OpenSearch-based) takes 5-10 minutes to fully initialize on this CPU after every start. A shell script (`homelab.sh`) standardizes starting, stopping, and checking status of the full stack.
- Given RAM constraints, the stack is run on-demand rather than kept online continuously.
- Remote access to the lab (dashboard, SSH) is provided via Tailscale (WireGuard-based mesh VPN), avoiding any direct exposure of DVWA or Wazuh to the public internet.

## Skills Demonstrated

- Linux system administration (Debian install, systemd services, user/permission management)
- Docker and Docker Compose (multi-container orchestration, volume mounting, networking)
- SIEM deployment and configuration (Wazuh manager/indexer/dashboard)
- Log source onboarding (exposing containerized application logs to a host-based agent)
- Custom detection rule authoring, including both signature-based rules and stateful correlation rules (frequency/timeframe)
- Systematic debugging using purpose-built tooling (`wazuh-logtest`) rather than trial-and-error guessing
- Offensive tooling: THC-Hydra for credential brute-forcing
- Understanding of common web attack patterns (SQLi, XSS) and their encoded/real-world representations
- File Integrity Monitoring configuration and real-time alert investigation
- Full alert lifecycle investigation: trigger → verification via raw log/forensic data → conclusion
- Practical trade-off judgment (pivoting attack vectors when one proved unreliable; accepting rule overlap rather than over-engineering a lab environment)
- Secure remote access configuration (Tailscale VPN)

## Next Steps

- Expand attack coverage: command injection, privilege escalation simulation
- Incorporate RedSim (custom network attack simulation toolkit) as an additional attack source
- Investigate and resolve the host's IPv6 connectivity issue
- Patch the CVE-2021-35331-affected packages identified by Wazuh's vulnerability detection module
