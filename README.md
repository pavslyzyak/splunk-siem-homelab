# splunk-siem-homelab

Windows-based SIEM homelab focused on authentication monitoring, process creation analysis, PowerShell detection, and Windows event log investigation using Splunk Enterprise.

## Project Overview

This project demonstrates the deployment and configuration of Splunk Enterprise for Windows security monitoring and log analysis within a local homelab environment.

The environment was configured to ingest and analyse:
- Windows Security logs
- Windows System logs
- Windows Application logs

The project focuses on:
- Authentication monitoring
- Failed logon detection
- Process creation monitoring
- Service installation monitoring
- PowerShell activity analysis
- Dashboard visualisation
- Basic detection engineering and filtering

---

## Technologies Used

- Splunk Enterprise 10.2
- Windows 11
- Splunk Add-on for Microsoft Windows
- SPL (Search Processing Language)

---

## Log Sources Configured

| Log Source | Purpose |
|---|---|
| Security | Authentication and process monitoring |
| System | Service installation and persistence monitoring |
| Application | Application and software event monitoring |

---

## Key Event Codes Monitored

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 7045 | Service installation |

---

## Detection Use Cases

### Failed Authentication Monitoring
Used EventCode 4625 to identify failed Windows authentication attempts and monitor suspicious login activity.

### Successful Authentication Monitoring
Tracked successful logon activity using EventCode 4624 to establish authentication baselines.

### Process Creation Monitoring
Monitored EventCode 4688 to analyse newly created processes and identify potentially suspicious execution activity.

### PowerShell Monitoring
Filtered process creation events to identify PowerShell execution activity commonly associated with attacker techniques and administrative tooling.

### Service Installation Monitoring
Monitored EventCode 7045 to detect newly installed Windows services and review associated service accounts and execution paths.

---

## Dashboard Development

## Screenshots

### Authentication Dashboard
![Authentication Dashboard](screenshots/10-authentication-dashboard.png)

### Authentication Summary Query
![Authentication Summary](screenshots/11-authentication-summary-query.png)

### Service Installation Monitoring
![Service Installation Monitoring](screenshots/14-service-installation-detailed-table.png)

### PowerShell Process Monitoring
![PowerShell Monitoring](screenshots/16-powershell-process-monitoring.png)

---

## Skills Demonstrated

- SIEM deployment and configuration
- Windows log analysis
- SPL query development
- Dashboard creation
- Authentication monitoring
- Threat detection fundamentals
- Process creation monitoring
- PowerShell activity monitoring
- Service installation analysis
- Detection engineering and filtering

---

## Project Structure

```text
screenshots/
queries/
reports/
configs/
```

---

## Author

Pav Slyzyak
