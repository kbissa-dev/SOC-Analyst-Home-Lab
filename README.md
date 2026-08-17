\# SOC Analyst Home Lab



A hands-on cybersecurity home lab focused on developing practical junior SOC analyst skills through security monitoring, investigation, detection and incident-response exercises.



\## Lab Environment



* Windows 10 target VM
* Kali Linux VM
* Ubuntu Linux VM
* Oracle VirtualBox VM
* Windows Security Event Logs
* Sysmon
* Microsoft Sentinel / KQL - being added



\## Skills Being Developed



* Security alert triage and investigation
* Windows security log analysis
* Authentication investigation
* SIEM monitoring
* Microsoft Sentinel
* Kusto Query Language (KQL)
* Network traffic analysis
* MITRE ATT\&CK
* Detection Engineering
* Incident response documentation
* SOC playbook development
* Python security automation



\## Investigation 



\### Investigation 001 - Windows Failed Logon followed by Successful Logon



Investigated two Windows failed authentication events (Event ID 4625) followed by a successful authentication (Event ID 4624).



The investigation examined the account, timestamps, Logon Type, failure status, source information and event sequence to determine whether the activity warranted escalation.



\*\*Assessment:\*\* Likely benign.



\[View Investigation 001](investigations/001-windows-failed-logon/investigation.md)



\## Repository Structure



```text

SOC-Analyst-Home-Lab/

├── investigations/    # SOC investigation case reports and evidence

├── detections/        # Detection rules and detection logic

├── kql/               # Microsoft Sentinel / KQL queries

├── playbooks/         # Incident response and triage playbooks

└── scripts/           # Python and security automation

