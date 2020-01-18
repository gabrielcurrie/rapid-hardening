# Rapidly Hardening an IT Environment

This document provides high-level guidance for rapidly hardening an IT environmment (containing Windows and Linux devices). Other key points of reference should be the ACSC's [Strategies to Mitigate Cyber Security Incidents](https://www.cyber.gov.au/publications/strategies-to-mitigate-cyber-security-incidents) and CIS's [Top 20 Security Controls](https://www.cisecurity.org/controls/cis-controls-list/).

## Identify and understand the environment
* Scan internal IP address ranges to identify devices (e.g., using tools such as nmap or SpiceWorks IP scanner)
* Identify applications and services running on devices
* Identify network connectivity and Internet egress points
* Identify privileged and service accounts

## Protect the environment
### Protect endpoints (i.e. workstations and servers)
* Patch operating systems (e.g., using WSUS) and applications
* Block potentially malicious extensions (e.g., PS1, HTA, CHM) from executing
* Enable application whitelisting (e.g., using AppLocker)
* Limit Microsoft Office macro execution
* Secure client applications (e.g., Chrome)
* Deploy anti-virus (e.g., [Windows Defender](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10) or [Sophos Home](https://home.sophos.com/en-us/index2.aspx) on Windows, or [Clam AV](https://www.clamav.net/) on Linux)
* Enable host firewalls (e.g., Windows Defender Firewall)

### Protect network infrastructure and connectivity
* Secure the boundary (deploy firewalls, IDS, IPS)
* Filter email and web content (e.g., block commonly abused TLDs, block commonly malicious file types, sandbox executables)
* Prevent endpoints from directly communicating with the Internet
* Segregate/segment network into defined zones: https://www.cyber.gov.au/publications/implementing-network-segmentation-and-segregation

### Protect identities
* Set secure password policy and ensure compliance
* Limit domain administrator membership and securely manage passwords
* Limit local administrator membership and securely manage passwords

### Protect data

## Detect and respond to attacks
* Generate logging on endpoints (e.g., Windows Event Logging using the NSA baseline)
* Generate network logging (e.g., DNS, DHCP, web/proxy, netflow)
* Deploy honeypots as tripwires to alert on attacker activity (e.g., Honeyd)
* Forward endpoint and network logs and collate in a SIEM (e.g., OSSIM, Splunk Free)
* Perform analysis of collated logs to identify and triage potentially malicious events
* Deploy tooling to enable log analysis (e.g., OSQuery, Google Rapid Response)
* Develop monitoring processes
* Develop response processes
