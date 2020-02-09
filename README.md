# Rapidly Hardening an IT Environment

This document provides high-level guidance for rapidly hardening an IT environmment (containing Windows and Linux devices). Other key points of reference should be the ACSC's [Strategies to Mitigate Cyber Security Incidents](https://www.cyber.gov.au/publications/strategies-to-mitigate-cyber-security-incidents) and CIS's [Top 20 Security Controls](https://www.cisecurity.org/controls/cis-controls-list/).

## Identify and understand the environment
* Scan internal IP address ranges to identify devices (e.g., using [nmap](https://nmap.org/) or the SpiceWorks IP scanner)
* Identify applications and services running on devices (e.g., using [WMIC](https://helpdeskgeek.com/how-to/generate-a-list-of-installed-programs-in-windows/))
* Identify network connectivity and Internet egress points
* Identify privileged and service accounts (e.g., using the [`net localgroup`](https://superuser.com/questions/339071/where-can-i-see-the-list-of-administrators-in-windows-7) or [`net group` command](https://social.technet.microsoft.com/Forums/windows/en-US/455e7ec7-5d77-4fda-9b95-1eea0380fc49/how-to-find-users-who-have-local-administratordomain-admin-rights-through-command-line?forum=itproxpsp), or a tool such as [CyberArk DNA](https://www.cyberark.com/discover-privileged-accounts-exist-cyberark-dna/))

## Protect the environment
### Protect endpoints (i.e. workstations and servers)
* Patch operating systems (e.g., using WSUS) and applications to the latest available version
* Enable host firewalls (e.g., Windows Defender Firewall) to prevent workstation-workstation communication
* Deploy anti-virus (e.g., [Windows Defender](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10) or [Sophos Home](https://home.sophos.com/en-us/index2.aspx) on Windows, or [Clam AV](https://www.clamav.net/) on Linux)
* Enable application whitelisting (e.g., using AppLocker or WDAC) and implement [Microsoft recommended block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
* Block potentially malicious extensions (e.g., `.PS1`, `.HTA`, `.CHM`) from executing
* [Limit Microsoft Office macro execution](https://www.cyber.gov.au/publications/microsoft-office-macro-security)
* Secure client applications (e.g., Chrome) using standards such as [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Disable Powershell v2](https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/) and enable [Constrained Language mode](https://www.petri.com/protect-malware-enforcing-powershell-constrained-language-mode)

### Protect network infrastructure and connectivity
* Secure the boundary by deploying and configuring firewalls, IDS, IPS, web proxies, and email scanning appliances
* Filter email and web content (e.g., block known malicious sites, block [commonly abused TLDs](https://www.spamhaus.org/statistics/tlds/), block commonly malicious file types, sandbox executables)
* Prevent endpoints from directly communicating with the Internet and enforce proxying
* [Segregate/segment network](https://www.cyber.gov.au/publications/implementing-network-segmentation-and-segregation) into defined zones

### Protect identities
* Set secure (i.e., long) password policies and ensure compliance
* Limit domain administrator membership and securely manage passwords
* Limit local administrator membership and securely manage passwords (e.g., using [LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899))
* Prevent local users from logging in over the network
* Prevent service accounts from logging in interactively

## Detect and respond to attacks
* Generate logging on endpoints (e.g., generating Windows Event Logging using the [NSA baseline](https://github.com/nsacyber/Event-Forwarding-Guidance) or [SwiftOnSecurity's Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config))
* Generate network logging (e.g., DNS, DHCP, web/proxy, netflow)
* Deploy honeypots as tripwires to alert on attacker activity (e.g., using [Honeyd](http://www.honeyd.org/))
* Forward endpoint and network logs and collate in a SIEM (e.g., [OSSIM](https://cybersecurity.att.com/products/ossim), Splunk Free, [ELK](https://www.elastic.co/what-is/elk-stack))
* Perform analysis of collated logs to identify and triage potentially malicious events
* Deploy tooling to enable investigations and incident response (e.g., OSQuery, Google Rapid Response)
* Develop monitoring processes
* Develop response processes
* Deploy tooling to manage incident response (e.g., [The Hive](https://thehive-project.org/), [FIR](https://github.com/certsocietegenerale/FIR), [Yeti](https://github.com/yeti-platform/yeti), [Cortex](https://github.com/TheHive-Project/Cortex))
