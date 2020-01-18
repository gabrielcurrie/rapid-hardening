# Rapidly Hardening an IT Environment

This document provides high-level guidance for rapidly hardening an IT environmment (containing Windows and Linux devices). Other key points of reference should be the ACSC's [Strategies to Mitigate Cyber Security Incidents](https://www.cyber.gov.au/publications/strategies-to-mitigate-cyber-security-incidents) and CIS's [Top 20 Security Controls](https://www.cisecurity.org/controls/cis-controls-list/).

## Endpoints
* Patch operating systems (e.g., using WSUS) and applications
* Block potentially malicious extensions (e.g., PS1, HTA, CHM) from executing
* Enable application whitelisting (e.g., using AppLocker)
* Limit Microsoft Office macro execution
* Secure client applications (e.g., Chrome)
* Deploy anti-virus (e.g., [Windows Defender](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10) or [Sophos Home](https://home.sophos.com/en-us/index2.aspx) on Windows, or [Clam AV](https://www.clamav.net/) on Linux)
* Enable host firewalls (e.g., Windows Defender Firewall)
* Generate logging (e.g., Windows Event Logging using the NSA baseline)

## Network
* Secure the boundary (deploy firewalls, IDS, IPS)
* Filter email and web content (e.g., block commonly abused TLDs, block commonly malicious file types, sandbox executables)
* Prevent endpoints from directly communicating with the Internet
* Segregate/segment network into defined zones: https://www.cyber.gov.au/publications/implementing-network-segmentation-and-segregation
* Generate logging

## Identity
* Set secure password policy and ensure compliance
* Limit domain administrator membership and securely manage passwords
* Limit local administrator membership and securely manage passwords

## Data

## Monitoring and Response
* Collect endpoint and network logs in 
* Collate endpoint and network logs in a SIEM (e.g., OSSIM, Splunk Free)
* Perform analysis of collated logs
* Deploy tooling to enable analysis (e.g., OSQuery, Google Rapid Response)
* Deploy honeypots (e.g., Honeyd)
* Develop monitoring processes
* Develop response processes
