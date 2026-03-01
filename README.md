# PORT-OF-ENTRY-THREAT-HUNT

# Threat Investigation Report — azuki-sl

**Classification:** Confidential
**Device:** azuki-sl
**Incident Window:** November 19, 2025 12:00 AM – November 21, 2025 12:00 AM
**Prepared:** 2025-11-21

---

## Table of Contents

1. [Incident Summary](#1-incident-summary)
2. [Executive Summary](#2-executive-summary)
3. [Attack Timeline](#3-attack-timeline)
4. [Findings Summary](#4-findings-summary)
5. [Indicators of Compromise](#5-indicators-of-compromise)
6. [Recommendations](#6-recommendations)

---

## 1. Incident Summary

| Field | Value |
|---|---|
| **Device** | azuki-sl |
| **Incident Window** | Nov 19, 2025 12:00 AM – Nov 21, 2025 12:00 AM |
| **Compromised Account** | `kenji.sato` |
| **Initial Access IP** | `88.97.178.12` (Public) |
| **C2 Server** | `78.141.196.6:443` (HTTPS) |
| **Lateral Movement Target** | `10.1.0.188` |
| **Exfiltration Channel** | `discord.com` via `curl.exe` |
| **MITRE ATT&CK Coverage** | Full kill chain — Initial Access through Exfiltration |

---

## 2. Executive Summary

Between November 19 and 21, 2025, a threat actor gained unauthorized access to endpoint **azuki-sl** using compromised credentials belonging to account `kenji.sato`. The attacker logged in from a public IP (`88.97.178.12`), performed network reconnaissance, established persistence, dumped credentials, exfiltrated data to Discord, and moved laterally to an internal host at `10.1.0.188`.

The attacker demonstrated a high level of operational tradecraft throughout the intrusion: masquerading malicious files and scheduled tasks as legitimate Windows components, disabling antivirus coverage over key directories, clearing Windows event logs to hinder forensic analysis, and creating a hidden backdoor account for long-term persistence.

---

## 3. Attack Timeline

### Phase 1 — Initial Access

On **November 19 at 6:36 PM UTC**, the attacker successfully authenticated to `azuki-sl` from the public IP `88.97.178.12` using the account `kenji.sato`. This was the earliest externally-sourced `LogonSuccess` event recorded in `DeviceLogonEvents` for this device.

**KQL Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where RemoteIP != ""
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```

---

### Phase 2 — Discovery & Reconnaissance

Shortly after gaining access, the attacker ran `ARP.EXE -a` to enumerate the local subnet by querying the ARP cache. This revealed neighboring IP addresses on the network, providing a map of potential lateral movement targets. The command was executed via PowerShell with an `ExecutionPolicy Bypass` flag.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where ProcessCommandLine has "arp"
| project TimeGenerated, AccountName, ActionType, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Phase 3 — Defense Evasion

The attacker modified Windows Defender's exclusion list via registry changes to prevent detection of malicious files. Three file extensions were whitelisted (`.bat`, `.ps1`, `.exe`), and two directory paths were added to Defender's exclusion list:

- `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- `C:\ProgramData\WindowsCache`

A staging directory named `WindowsCache` was created under `C:\ProgramData\` to mimic a legitimate Windows folder and avoid casual inspection.

**KQL Queries Used:**
```kql
-- Extensions exclusions
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey has "Exclusions\\Extensions"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc

-- Path exclusions
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey has "Exclusions\\Paths"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

---

### Phase 4 — Payload Delivery & Persistence

The attacker used `certutil.exe` and PowerShell's `Invoke-WebRequest` to download malicious payloads from the C2 server at `78.141.196.6:8080`. Two primary executables were deposited into the staging directory:

- **`svchost.exe`** — C2 beacon masquerading as a legitimate Windows service process
- **`mm.exe`** — Credential dumping tool (Mimikatz-style), named to avoid signature detection

A scheduled task named **"Windows Update Check"** was created to execute the C2 beacon (`C:\ProgramData\WindowsCache\svchost.exe`) daily at 02:00 AM, establishing persistent access.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine has "http"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has "/create"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### Phase 5 — Credential Access

The attacker executed `mm.exe` with Mimikatz-style arguments to extract plaintext credentials and NTLM hashes from LSASS memory:

```
mm.exe privilege::debug sekurlsa::logonpasswords exit
```

The `sekurlsa::logonpasswords` module was used specifically to harvest credentials from active logon sessions, including those belonging to other accounts on the system.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mm.exe"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

---

### Phase 6 — C2 Communication

The malicious `svchost.exe` beacon established an outbound HTTPS connection to `78.141.196.6` on **port 443**, deliberately using standard encrypted web traffic to blend in with legitimate internet activity. The connection was confirmed via `DeviceNetworkEvents`, filtered by the binary's non-standard folder path in `C:\ProgramData\WindowsCache`.

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated asc
```

---

### Phase 7 — Exfiltration

A PowerShell script (`wupdate.ps1`) was downloaded from the C2 server to the user's Temp directory and executed to automate the exfiltration chain. The attacker created a zip archive named `export-data.zip` inside the `WindowsCache` staging directory, then uploaded it to **Discord** using `curl.exe` over HTTPS:

```
curl.exe → discord.com:443
```

Discord was selected as the exfiltration channel because outbound HTTPS traffic to `discord.com` appears legitimate and is rarely blocked by enterprise firewalls.

**KQL Queries Used:**
```kql
-- Find exfiltration archive
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName has "zip"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc

-- Find exfiltration network connection
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```

---

### Phase 8 — Anti-Forensics

Following exfiltration, the attacker used `wevtutil.exe` to clear Windows event logs and destroy forensic evidence. Logs were cleared in the following order:

1. **Security** — first priority; contains logon events, privilege changes, and authentication records
2. **System**
3. **Application**

The attacker also used `wevtutil.exe` to uninstall and reinstall Windows Defender platform manifests, likely attempting to reset or disrupt Defender telemetry.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "wevtutil"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### Phase 9 — Backdoor Account Creation

A backdoor local account named `support` was created and immediately added to the local Administrators group, ensuring persistent elevated access even if the `kenji.sato` credentials were later revoked:

```
net1 user support ********** /add
net.exe localgroup Administrators support /add
```

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("net user", "net1 user", "localgroup")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### Phase 10 — Lateral Movement

Using credentials harvested by `mm.exe`, the attacker stored remote credentials for the `fileadmin` account targeting `10.1.0.188`, then initiated an RDP session using `mstsc.exe`:

```
cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:**********
mstsc.exe /v:10.1.0.188
```

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## 4. Findings Summary

| # | Finding | Value / Answer | Data Source |
|---|---|---|---|
| 1 | Initial access source IP | `88.97.178.12` | DeviceLogonEvents |
| 2 | Compromised account | `kenji.sato` | DeviceLogonEvents |
| 3 | Network enumeration command | `ARP.EXE -a` | DeviceProcessEvents |
| 4 | Malicious staging directory | `C:\ProgramData\WindowsCache` | DeviceFileEvents |
| 5 | AV exclusions added (extensions) | `.bat`, `.ps1`, `.exe` | DeviceRegistryEvents |
| 6 | AV exclusion paths added | `...\Local\Temp` & `C:\ProgramData\WindowsCache` | DeviceRegistryEvents |
| 7 | Download tools used | `certutil.exe`, `powershell.exe` | DeviceProcessEvents |
| 8 | Persistence scheduled task name | `Windows Update Check` | DeviceProcessEvents |
| 9 | Scheduled task executable | `C:\ProgramData\WindowsCache\svchost.exe` | DeviceProcessEvents |
| 10 | C2 server IP | `78.141.196.6` | DeviceNetworkEvents |
| 11 | C2 communication port | `443` (HTTPS) | DeviceNetworkEvents |
| 12 | Credential dumping tool | `mm.exe` (Mimikatz) | DeviceFileEvents |
| 13 | Mimikatz module used | `sekurlsa::logonpasswords` | DeviceProcessEvents |
| 14 | Exfiltration archive | `export-data.zip` | DeviceFileEvents |
| 15 | Exfiltration cloud service | `discord.com` | DeviceNetworkEvents |
| 16 | First event log cleared | `Security` | DeviceProcessEvents |
| 17 | Backdoor account created | `support` (local Administrator) | DeviceProcessEvents |
| 18 | Attack automation script | `wupdate.ps1` | DeviceFileEvents |
| 19 | Lateral movement target IP | `10.1.0.188` | DeviceProcessEvents |
| 20 | Lateral movement tool | `mstsc.exe` (RDP) | DeviceProcessEvents |

---

## 5. Indicators of Compromise

### Network IOCs

| Type | Value | Description |
|---|---|---|
| IP | `88.97.178.12` | Attacker initial access source IP |
| IP | `78.141.196.6` | C2 server (payload delivery + beacon) |
| IP:Port | `78.141.196.6:8080` | Payload download endpoint |
| IP:Port | `78.141.196.6:443` | C2 beacon (HTTPS) |
| Domain | `discord.com` | Exfiltration destination |

### File & Process IOCs

| Path | Description |
|---|---|
| `C:\ProgramData\WindowsCache\svchost.exe` | Malicious C2 beacon |
| `C:\ProgramData\WindowsCache\mm.exe` | Credential dumper (Mimikatz) |
| `C:\ProgramData\WindowsCache\export-data.zip` | Exfiltration archive |
| `C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` | Attack automation script |

### Registry IOCs

| Key | Change |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions` | Added `.bat`, `.ps1`, `.exe` |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` | Added `...\Temp` and `C:\ProgramData\WindowsCache` |

### Account IOCs

| Account | Notes |
|---|---|
| `kenji.sato` | Compromised — used for initial access |
| `support` | Backdoor — local Administrator, created by attacker |
| `fileadmin` | Credential harvested and used for lateral movement to `10.1.0.188` |

---

## 6. Recommendations

### Immediate (0–24 hours)

- [ ] Isolate `azuki-sl` from the network and initiate a full reimaging
- [ ] Disable and investigate the `kenji.sato` account; reset credentials across all systems where it is used
- [ ] Delete the backdoor `support` account from all affected machines
- [ ] Block `78.141.196.6` and `88.97.178.12` at the network perimeter immediately
- [ ] Investigate `10.1.0.188` for signs of lateral movement compromise
- [ ] Revoke cached credentials associated with `fileadmin`

### Short-Term (1–7 days)

- [ ] Hunt for `WindowsCache` directories and the presence of `mm.exe` or `wupdate.ps1` across all endpoints
- [ ] Review and remove all Windows Defender exclusions not authorised by policy
- [ ] Search for the scheduled task "Windows Update Check" on all Windows hosts
- [ ] Audit all local Administrator group memberships for unauthorised accounts
- [ ] Review `DeviceNetworkEvents` for other hosts making outbound connections to `discord.com` or `78.141.196.6`

### Long-Term (1–4 weeks)

- [ ] Enforce MFA on all accounts, particularly for remote/RDP access
- [ ] Implement application allowlisting to prevent `certutil.exe` and `mstsc.exe` misuse
- [ ] Deploy Windows Defender Credential Guard to prevent LSASS memory dumping
- [ ] Configure Windows event log forwarding to a SIEM to prevent local log tampering
- [ ] Establish alerts for registry modifications under `Windows Defender\Exclusions`
- [ ] Block outbound connections to consumer cloud services (Discord, Dropbox, etc.) unless explicitly required

---

*Report generated from KQL investigation of Microsoft Defender for Endpoint logs via Log Analytics Workspace.*
*Investigation window: Nov 19, 2025 12:00 AM UTC — Nov 21, 2025 12:00 AM UTC*
