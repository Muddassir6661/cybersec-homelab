# Home SOC Lab: Building a Detection Pipeline with Wazuh and DVWA

<img width="1919" height="970" alt="Screenshot 2026-09-07 111845" src="https://github.com/user-attachments/assets/7cd70b13-185f-4fcd-8442-a735cc7520d9" />

## Overview

This project involved building a small-scale Security Operations Center (SOC) lab on repurposed hardware to practice both offensive and defensive security skills. The goal was to deploy an intentionally vulnerable web application, monitor it with a SIEM, and write custom detection rules to catch real attacks as they happen — end to end, from exploitation to alert.

## Hardware

- Dell Inspiron 15 (repurposed from a prior OpenMediaVault NAS setup)
- Intel Celeron 1007U (dual-core, 1.5GHz)
- 3.7GB RAM
- 465GB storage

This is well below the officially recommended specs for the tools used (Wazuh's indexer alone recommends 4GB+), which made resource management and startup timing a real, ongoing constraint throughout the build — not just a one-time setup decision.

## Architecture

```
[Attacker Browser] --> [DVWA container (Apache + PHP)] --> logs to host filesystem
                                                                    |
                                                                    v
                                                       [Wazuh Agent on host]
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
- **Wazuh Agent** — installed directly on the Debian host (not inside the DVWA container) to monitor both host-level activity and DVWA's Apache logs

## Build Process

1. Wiped a prior OpenMediaVault installation and performed a clean Debian install (plain partitioning, no LVM/encryption, to keep things simple on constrained hardware).
2. Installed Docker and Docker Compose.
3. Deployed Portainer for visual container management.
4. Deployed DVWA as an attack target.
5. Deployed the Wazuh single-node stack (manager, indexer, dashboard) via Docker Compose.
6. Installed a Wazuh agent on the host and enrolled it with the manager.
7. Recreated the DVWA container with a volume mount exposing its Apache logs (`access.log`, `error.log`) to the host filesystem, so the Wazuh agent could read them.
8. Configured the Wazuh agent (`ossec.conf`) to monitor the DVWA log files as `localfile` sources.
9. Wrote and iteratively debugged custom Wazuh detection rules for SQL injection and XSS.

## Custom Detection Rules

Three custom rules were written in Wazuh's `local_rules.xml`:

| Rule ID | Detects | Trigger |
|---|---|---|
| 100010 | SQL Injection | URL-encoded single quote (`%27`) |
| 100011 | SQL Injection | SQL keywords (`UNION`, `SELECT`) in URL |
| 100012 | XSS (Cross-Site Scripting) | Encoded `<script>` tags in URL |

All three were tested and verified using `wazuh-logtest` (Wazuh's built-in rule-testing tool) before being confirmed live against real DVWA traffic in the dashboard.

## Debugging Process (Key Findings)

Getting these rules working was not a straight line, and the debugging process itself is arguably the most demonstrable part of this project:

- **Wrong parent rule ID:** Initial rules referenced `if_sid 31108`, assumed to be the parent rule for parsed Apache access logs. Using `wazuh-logtest` to trace a raw log line through decoding showed the actual matching rule was `31100`, not `31108`. This was the root cause of rules silently never firing.
- **URL encoding blind spot:** The first rule attempt searched for literal text like `OR '1'='1`, but browsers URL-encode requests — the actual log line contained `1%27+OR+%271%27%3D%271`. Rules had to match the encoded form (`%27`), not the raw payload text.
- **Manager restarts drop the agent connection:** Each time the Wazuh manager container restarted (necessary to reload rule changes), the agent briefly lost connection (`Connection refused`) and paused log collection for ~15-30 seconds. Tests run during this window silently produced no results, which initially looked like a rule failure rather than a timing issue.
- **Rule overlap / false positive:** An XSS payload containing `'XSS'` also matched the SQLi rule (100010) because of the quote character in `'XSS'`, since Wazuh's rule engine stops at the first match within a rule group. Attempted to resolve this with a `negate` condition on the SQLi rule; this did not behave as expected, so the decision was made to accept the overlap rather than over-engineer detection logic for a lab environment — a legitimate trade-off, not an unresolved bug.
- **XML syntax error:** A raw (unencoded) `<script>` tag was mistakenly placed inside a rule's `<url>` field, which XML parsed as a nested tag rather than literal text, silently breaking the ruleset. Fixed by using only the URL-encoded form.

## Verified Results

- SQL injection via DVWA's SQLi module (`1' OR '1'='1`) → correctly triggered rule 100010, level 10 alert.
- Reflected XSS via a quote-free payload (`<script>alert(1)</script>`) → correctly triggered rule 100012, level 10 alert, with no overlap.
- Wazuh's built-in vulnerability detection module also independently flagged a real CVE (CVE-2021-35331, affecting `tcl8.6`/`libtcl8.6`) introduced as a dependency of an unrelated system utility — an unplanned but genuine demonstration of the vulnerability scanning module working correctly.

## Operational Notes

- The Wazuh indexer (OpenSearch-based) takes 5-10 minutes to fully initialize on this CPU after every start, due to hardware constraints. A shell script (`homelab.sh`) was written to standardize starting, stopping, and checking the status of the full stack.
- Given the RAM constraints, the stack is run on-demand rather than kept online continuously.

## Skills Demonstrated

- Linux system administration (Debian install, systemd services, user/permission management)
- Docker and Docker Compose (multi-container orchestration, volume mounting, networking)
- SIEM deployment and configuration (Wazuh manager/indexer/dashboard)
- Log source onboarding (exposing containerized application logs to a host-based agent)
- Custom detection rule authoring (Wazuh XML ruleset syntax)
- Systematic debugging using purpose-built tooling (`wazuh-logtest`) rather than trial-and-error guessing
- Understanding of common web attack patterns (SQLi, XSS) and their encoded/real-world representations
- Practical trade-off judgment (accepting rule overlap rather than over-engineering a lab environment)

## Next Steps

- Expand attack coverage: brute-force login detection, command injection
- Incorporate RedSim (custom network attack simulation toolkit) as an additional attack source against the lab
- Investigate and resolve the host's IPv6 connectivity issue
- Consider patching the CVE-2021-35331-affected packages
