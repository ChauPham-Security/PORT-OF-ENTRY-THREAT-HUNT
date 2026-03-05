# Threat Hunt Report

**Port of Entry Cyber Range SOC**
**Incident Timeframe:** November 19–21, 2025
**Target Device:** azuki-sl
**Report Date:** February 27, 2026

---

## Executive Summary

This report documents the findings of a threat hunt conducted against the azuki-sl device within the Port of Entry Cyber Range SOC environment. The investigation covers the period of November 19–21, 2025, during which a threat actor gained unauthorised access via Remote Desktop Protocol (RDP) and carried out a full attack chain including discovery, defence evasion, persistence, credential access, data collection, exfiltration, and lateral movement.

The attacker gained initial access using compromised credentials belonging to the user `kenji.sato`, connecting from the external IP address `88.97.178.12`. Following initial access, the attacker established a hidden staging directory, disabled Windows Defender, downloaded malicious tools, established command and control communications, dumped credentials, exfiltrated data via Discord, and created a backdoor administrator account before moving laterally to another internal machine.

---

## Attack Timeline Overview

| Time (UTC) | MITRE Tactic | Activity |
|---|---|---|
| Nov 19, 6:36 PM | Initial Access | RDP login from `88.97.178.12` as `kenji.sato` |
| Nov 19, 7:04 PM | Discovery | `ARP.EXE -a` executed to enumerate network neighbours |
| Nov 19, 7:05 PM | Defence Evasion | WindowsCache staging directory created and hidden |
| Nov 19, 7:05 PM | Defence Evasion | Windows Defender exclusions added for extensions and paths |
| Nov 19, 7:07 PM | Defence Evasion | `certutil.exe` used to download `svchost.exe` and `mm.exe` |
| Nov 19, 7:08 PM | Persistence | Scheduled task 'Windows Update Check' created |
| Nov 19, 7:08 PM | Command & Control | `svchost.exe` beacons to C2 server `78.141.196.6:443` |
| Nov 19, 7:08 PM | Credential Access | `mm.exe` (Mimikatz) executed — `sekurlsa::logonpasswords` |
| Nov 19, 7:08 PM | Collection | `export-data.zip` created in staging directory |
| Nov 19, 7:09 PM | Exfiltration | `export-data.zip` uploaded to Discord via `curl.exe` |
| Nov 19, 7:09 PM | Impact | Backdoor account 'support' created and added to Administrators |
| Nov 19, 7:10 PM | Lateral Movement | RDP connection initiated to `10.1.0.188` using `mstsc.exe` |

---

## Findings Summary

| Flag | Category | Title | Answer |
|---|---|---|---|
| 1 | Initial Access | Remote Access Source | `88.97.178.12` |
| 2 | Initial Access | Compromised User Account | `kenji.sato` |
| 3 | Discovery | Network Reconnaissance | `ARP.EXE -a` |
| 4 | Defence Evasion | Malware Staging Directory | `C:\ProgramData\WindowsCache` |
| 5 | Defence Evasion | File Extension Exclusions | `3` |
| 6 | Defence Evasion | Temporary Folder Exclusion | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| 7 | Defence Evasion | Download Utility Abuse | `certutil.exe` |
| 8 | Persistence | Scheduled Task Name | `Windows Update Check` |
| 9 | Persistence | Scheduled Task Target | `C:\ProgramData\WindowsCache\svchost.exe` |
| 10 | Command & Control | C2 Server Address | `78.141.196.6` |
| 11 | Command & Control | C2 Communication Port | `443` |
| 12 | Credential Access | Credential Theft Tool | `mm.exe` |
| 13 | Credential Access | Memory Extraction Module | `sekurlsa::logonpasswords` |
| 14 | Collection | Data Staging Archive | `export-data.zip` |
| 15 | Exfiltration | Exfiltration Channel | `Discord` |
| 16 | Anti-Forensics | Log Tampering | `Security` |
| 17 | Impact | Persistence Account | `support` |
| 18 | Execution | Malicious Script | `wupdate.ps1` |
| 19 | Lateral Movement | Secondary Target | `10.1.0.188` |
| 20 | Lateral Movement | Remote Access Tool | `mstsc.exe` |

---

## Detailed Findings

---

### Flag 1: Remote Access Source

| | |
|---|---|
| **Flag** | Flag 1 |
| **Category** | Initial Access |
| **Title** | Remote Access Source |

**Question**

Identify the source IP address of the Remote Desktop Protocol connection?

**Answer**

> **88.97.178.12**

**Analysis**

I used the `DeviceLogonEvents` table because it records all login activity including the source IP address, account used, and whether the login was successful. I filtered for successful logons with a non-empty `RemoteIP` field to identify external connections. The results showed a successful login from the public IP address `88.97.178.12`, confirming this as the attacker's entry point via RDP.

**KQL Query**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where RemoteIP != ""
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```
**Querry result**

<img width="869" height="361" alt="Screenshot 2026-03-04 at 6 42 32 PM" src="https://github.com/user-attachments/assets/273ee506-8f8b-405b-9401-92587609ca06" />


---

### Flag 2: Compromised User Account

| | |
|---|---|
| **Flag** | Flag 2 |
| **Category** | Initial Access |
| **Title** | Compromised User Account |

**Question**

Identify the user account that was compromised for initial access?

**Answer**

> **kenji.sato**

**Analysis**

No new query was needed for this flag. Using the same results from Flag 1, the `AccountName` field in the `DeviceLogonEvents` results identified the user account that authenticated during the suspicious RDP session from `88.97.178.12` as `kenji.sato`, confirming this account was compromised.

**KQL Query**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where RemoteIP != ""
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```

---

### Flag 3: Network Reconnaissance

| | |
|---|---|
| **Flag** | Flag 3 |
| **Category** | Discovery |
| **Title** | Network Reconnaissance |

**Question**

Identify the command and argument used to enumerate network neighbours?

**Answer**

> **ARP.EXE -a**

**Analysis**

Since the question asks about a command used for network enumeration, I used the `DeviceProcessEvents` table because it records all process execution and command lines. I filtered for common network discovery commands in the `ProcessCommandLine` field, focusing on `arp` which is a built-in Windows tool used to display the ARP cache and reveal other IP addresses and MAC addresses on the local subnet. The results confirmed `ARP.EXE -a` was executed, where the `-a` argument lists all known network neighbours.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where ProcessCommandLine has "arp"
| project TimeGenerated, AccountName, ActionType, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

<img width="880" height="234" alt="Screenshot 2026-03-04 at 6 44 42 PM" src="https://github.com/user-attachments/assets/04eb7229-4439-47f0-a067-5185a6e96ada" />


---

### Flag 4: Malware Staging Directory

| | |
|---|---|
| **Flag** | Flag 4 |
| **Category** | Defence Evasion |
| **Title** | Malware Staging Directory |

**Question**

Identify the PRIMARY staging directory where malware was stored?

**Answer**

> **C:\ProgramData\WindowsCache**

**Analysis**

Since the question asks about a directory being created, I used the `DeviceFileEvents` table because it records all file and folder creation activity on the device. I filtered for activity initiated by `kenji.sato` and reviewed the `FolderPath` field for suspicious directories. I excluded known legitimate processes like Chrome and focused on PowerShell-initiated activity. A folder named `WindowsCache` was created under `C:\ProgramData\` — a path that does not legitimately exist in Windows and was created to blend in with system directories. Shortly after, malicious files were downloaded directly into it, confirming it as the primary staging directory.

**KQL Query**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

<img width="881" height="358" alt="Screenshot 2026-03-04 at 6 45 27 PM" src="https://github.com/user-attachments/assets/3ecacae3-b3ba-4bda-a524-eaaec7a95647" />

---

### Flag 5: File Extension Exclusions

| | |
|---|---|
| **Flag** | Flag 5 |
| **Category** | Defence Evasion |
| **Title** | File Extension Exclusions |

**Question**

How many file extensions were excluded from Windows Defender scanning?

**Answer**

> **3**

**Analysis**

Since the question asks about Windows Defender exclusions, I used the `DeviceRegistryEvents` table because Windows Defender stores its security settings in the Windows Registry, and any changes to those settings are logged here. I filtered for modifications to the `Exclusions\Extensions` registry key under Windows Defender configuration and counted the unique file extensions in the `RegistryValueName` field. The results returned 3 unique file extensions (`.bat`, `.ps1`, `.exe`) that were excluded from scanning.

**KQL Query**

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey has "Exclusions\\Extensions"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
**Querry result**

<img width="873" height="329" alt="Screenshot 2026-03-04 at 6 45 52 PM" src="https://github.com/user-attachments/assets/94d9bb43-85e2-40c4-8ee2-db3c511d31eb" />

---

### Flag 6: Temporary Folder Exclusion

| | |
|---|---|
| **Flag** | Flag 6 |
| **Category** | Defence Evasion |
| **Title** | Temporary Folder Exclusion |

**Question**

What temporary folder path was excluded from Windows Defender scanning?

**Answer**

> **C:\Users\KENJI~1.SAT\AppData\Local\Temp**

**Analysis**

This flag is similar to Flag 5 but instead of looking for extension exclusions, I filtered for `Exclusions\Paths` under the Windows Defender registry key. The `RegistryValueName` field revealed that the user's Temp folder was added as an excluded path. This is the directory where malicious scripts like `wupdate.ps1` were downloaded and executed, so the attacker excluded it from Windows Defender scanning to create a safe zone for their tools.

**KQL Query**

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey has "Exclusions\\Paths"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
**Querry result**

<img width="869" height="282" alt="Screenshot 2026-03-04 at 6 47 09 PM" src="https://github.com/user-attachments/assets/b71db9e1-e288-4791-a1f3-6bccef478505" />

---

### Flag 7: Download Utility Abuse

| | |
|---|---|
| **Flag** | Flag 7 |
| **Category** | Defence Evasion |
| **Title** | Download Utility Abuse |

**Question**

Identify the Windows-native binary the attacker abused to download files?

**Answer**

> **certutil.exe**

**Analysis**

Since the question asks about a Windows-native binary used to download files, I used the `DeviceProcessEvents` table and filtered the `ProcessCommandLine` field for any commands containing `http` to identify download activity. The results showed `certutil.exe` being executed with the `-urlcache -f` arguments followed by a URL pointing to the C2 server. This is a known Living Off the Land technique where attackers abuse this built-in Windows certificate utility to download malicious files while evading detection.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine has "http"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

<img width="871" height="345" alt="Screenshot 2026-03-04 at 6 48 21 PM" src="https://github.com/user-attachments/assets/79ff0a2e-f579-4c86-8f01-44dbc4d3b6f1" />

---

### Flag 8: Scheduled Task Name

| | |
|---|---|
| **Flag** | Flag 8 |
| **Category** | Persistence |
| **Title** | Scheduled Task Name |

**Question**

Identify the name of the scheduled task created for persistence?

**Answer**

> **Windows Update Check**

**Analysis**

Since the question asks about a scheduled task being created, I used the `DeviceProcessEvents` table because it records all process execution and command lines. Scheduled tasks in Windows are managed by `schtasks.exe`, so I filtered for both `schtasks` and `/create` to narrow results down to task creation events only. The `/tn` parameter in the `ProcessCommandLine` field specifies the task name. The attacker named it `Windows Update Check` — a name deliberately chosen to blend in with legitimate Windows maintenance activity and avoid raising suspicion.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has "/create"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

<img width="887" height="255" alt="Screenshot 2026-03-04 at 6 55 45 PM" src="https://github.com/user-attachments/assets/96338126-e287-40bf-a53e-ace9990ed950" />

---

### Flag 9: Scheduled Task Target

| | |
|---|---|
| **Flag** | Flag 9 |
| **Category** | Persistence |
| **Title** | Scheduled Task Target |

**Question**

Identify the executable path configured in the scheduled task?

**Answer**

> **C:\ProgramData\WindowsCache\svchost.exe**

**Analysis**

No new query was needed for this flag. The answer comes from the same `schtasks.exe /create` command line identified in Flag 8. The `/tr` parameter tells Windows what program to execute when the scheduled task triggers. Reading the value after `/tr` in the same result revealed the malicious executable path. The attacker named it `svchost.exe` to disguise it as a legitimate Windows process.

**Querry result**

<img width="869" height="256" alt="Screenshot 2026-03-04 at 6 56 35 PM" src="https://github.com/user-attachments/assets/603877b8-3b47-4027-b491-1244ec9a1102" />


---

### Flag 10: C2 Server Address

| | |
|---|---|
| **Flag** | Flag 10 |
| **Category** | Command & Control |
| **Title** | C2 Server Address |

**Question**

Identify the IP address of the command and control server?

**Answer**

> **78.141.196.6**

**Analysis**

Since the question asks about a C2 server address, I used the `DeviceNetworkEvents` table because it records all outbound and inbound network connections made by the device. I filtered specifically for `svchost.exe` running from the `WindowsCache` folder to distinguish it from the legitimate Windows `svchost.exe` processes. The `RemoteIP` field in the results identified the external IP address the malware was communicating with, confirming `78.141.196.6` as the C2 server.

**KQL Query**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 11: C2 Communication Port

| | |
|---|---|
| **Flag** | Flag 11 |
| **Category** | Command & Control |
| **Title** | C2 Communication Port |

**Question**

Identify the destination port used for command and control communications?

**Answer**

> **443**

**Analysis**

No new query was needed for this flag. The answer comes directly from the `RemotePort` field in the same `DeviceNetworkEvents` results from Flag 10. The malware communicated over port `443`, which is the standard HTTPS port. The attacker intentionally used this port to blend C2 traffic in with normal encrypted web traffic and avoid detection.

---

### Flag 12: Credential Theft Tool

| | |
|---|---|
| **Flag** | Flag 12 |
| **Category** | Credential Access |
| **Title** | Credential Theft Tool |

**Question**

Identify the filename of the credential dumping tool?

**Answer**

> **mm.exe**

**Analysis**

Since the question asks about a credential dumping tool, I used the `DeviceFileEvents` table to look for executable files dropped into the staging directory. I filtered for `.exe` files created inside the `WindowsCache` folder. The results returned two executables — `svchost.exe` which was already identified as the C2 malware, and `mm.exe`. The very short and generic name of `mm.exe` is a strong indicator that it is a renamed credential dumping tool, as attackers commonly rename tools like Mimikatz to short meaningless names to avoid signature-based detection.

**KQL Query**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

---

### Flag 13: Memory Extraction Module

| | |
|---|---|
| **Flag** | Flag 13 |
| **Category** | Credential Access |
| **Title** | Memory Extraction Module |

**Question**

Identify the module used to extract logon passwords from memory?

**Answer**

> **sekurlsa::logonpasswords**

**Analysis**

Since the question asks about the specific module used to extract passwords, I used the `DeviceProcessEvents` table to look at how `mm.exe` was executed. I filtered directly for `mm.exe` as the filename and examined the `ProcessCommandLine` field. The results showed the full command `mm.exe privilege::debug sekurlsa::logonpasswords exit`, confirming this is a Mimikatz-style tool. Mimikatz modules follow a recognisable `module::command` syntax, and `sekurlsa::logonpasswords` is the specific module used to extract plaintext passwords and credential hashes from LSASS memory.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mm.exe"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 14: Data Staging Archive

| | |
|---|---|
| **Flag** | Flag 14 |
| **Category** | Collection |
| **Title** | Data Staging Archive |

**Question**

Identify the compressed archive filename used for data exfiltration?

**Answer**

> **export-data.zip**

**Analysis**

Since the question asks about a compressed archive used for data exfiltration, I used the `DeviceFileEvents` table because it records all file creation activity on the device. I filtered for any filename containing `zip` and reviewed the `FolderPath` field to confirm it was created inside the `WindowsCache` staging directory. The results returned `export-data.zip`, confirming this is the archive the attacker created to bundle stolen data before sending it out of the network.

**KQL Query**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName has "zip"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 15: Exfiltration Channel

| | |
|---|---|
| **Flag** | Flag 15 |
| **Category** | Exfiltration |
| **Title** | Exfiltration Channel |

**Question**

Identify the cloud service used to exfiltrate stolen data?

**Answer**

> **Discord**

**Analysis**

Since the question asks about which cloud service was used to exfiltrate data, I used the `DeviceNetworkEvents` table because it records all network connections made by processes on the device. I filtered for connections initiated by processes referencing the `WindowsCache` staging directory, where the stolen ZIP file was stored. The `RemoteUrl` field in the results showed `curl.exe` making an outbound HTTPS connection to `discord.com` over port `443`, confirming that Discord was used as the exfiltration channel. Attackers commonly abuse platforms like Discord because their HTTPS traffic blends in with normal web traffic.

**KQL Query**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```
**Querry result**

---

### Flag 16: Log Tampering

| | |
|---|---|
| **Flag** | Flag 16 |
| **Category** | Anti-Forensics |
| **Title** | Log Tampering |

**Question**

Identify the first Windows event log cleared by the attacker?

**Answer**

> **Security**

**Analysis**

Since the question asks about Windows event logs being cleared, I used the `DeviceProcessEvents` table because it records all process execution and command lines. I filtered for `wevtutil.exe` which is the built-in Windows tool used to manage and clear event logs. Results were ordered in ascending order by time to identify which log was cleared first. The `ProcessCommandLine` field showed `wevtutil.exe cl Security`, confirming the Security event log was the first to be cleared. The Security log is the most forensically valuable log in Windows as it records login activity, privilege changes, and other security-related events, making it the attacker's first priority to erase.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "wevtutil"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 17: Persistence Account

| | |
|---|---|
| **Flag** | Flag 17 |
| **Category** | Impact |
| **Title** | Persistence Account |

**Question**

Identify the backdoor account username created by the attacker?

**Answer**

> **support**

**Analysis**

Since the question asks about a backdoor account being created, I used the `DeviceProcessEvents` table and filtered for account creation commands using `net user`, `net1 user`, and `localgroup`. Both `net.exe` and `net1.exe` were included in the search because Windows sometimes logs the backend process `net1.exe` instead of `net.exe` when executing these commands. The results showed the attacker created a user account named `support` and immediately added it to the Administrators group using `net localgroup Administrators support /add`, giving it full control over the device as a hidden backdoor account.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("net user", "net1 user", "localgroup")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 18: Malicious Script

| | |
|---|---|
| **Flag** | Flag 18 |
| **Category** | Execution |
| **Title** | Malicious Script |

**Question**

Identify the PowerShell script file used to automate the attack chain?

**Answer**

> **wupdate.ps1**

**Analysis**

Since the question asks about a PowerShell script used to automate the attack chain, I used the `DeviceFileEvents` table to look for script files created on the device. I filtered for processes containing `powershell` in the command line and added a filter for `.ps1` file extensions. The results contained many automatically generated PowerShell policy test files starting with `__PSScriptPolicyTest` — these are normal files Windows generates whenever PowerShell runs, so they were excluded to reduce noise. The remaining result was a suspicious file named `wupdate.ps1`, downloaded from the C2 server into the user's Temp folder. The name `wupdate` is short for Windows Update, a deliberate attempt by the attacker to disguise the script as a legitimate Windows process.

**KQL Query**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "powershell"
| where FileName endswith ".ps1"
| where FileName !startswith "__PSScript"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**
---

### Flag 19: Secondary Target

| | |
|---|---|
| **Flag** | Flag 19 |
| **Category** | Lateral Movement |
| **Title** | Secondary Target |

**Question**

What IP address was targeted for lateral movement?

**Answer**

> **10.1.0.188**

**Analysis**

Since the question asks about a lateral movement target, I used the `DeviceProcessEvents` table and filtered for both `mstsc` and `cmdkey`. These two tools are commonly used together for lateral movement — `cmdkey.exe` is used to store credentials for a remote machine, and `mstsc.exe` is the Windows Remote Desktop tool used to connect to it. The results showed the attacker first stored credentials for `10.1.0.188` under the username `fileadmin` using `cmdkey.exe`, then immediately used `mstsc.exe` to RDP into that machine, confirming it as the lateral movement target.

**KQL Query**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**Querry result**

---

### Flag 20: Remote Access Tool

| | |
|---|---|
| **Flag** | Flag 20 |
| **Category** | Lateral Movement |
| **Title** | Remote Access Tool |

**Question**

Identify the remote access tool used for lateral movement?

**Answer**

> **mstsc.exe**

**Analysis**

No new query was needed for this flag. The answer comes directly from the same results as Flag 19. The `ProcessCommandLine` field showed `mstsc.exe` being executed with the `/v:10.1.0.188` argument, which tells it to connect to that specific IP address via RDP. `mstsc.exe` is the built-in Windows Remote Desktop tool, making it a preferred choice for attackers during lateral movement because it blends in with legitimate administrative activity and is less likely to raise suspicion.

---

## Conclusion

This threat hunt successfully identified and documented a full attack chain carried out against the azuki-sl device. The threat actor demonstrated a high level of operational sophistication, leveraging built-in Windows tools throughout the intrusion to blend in with legitimate activity and evade detection.

Key findings include the use of a compromised user account for initial RDP access, hidden staging directory creation, systematic Windows Defender evasion, Living Off the Land binary abuse for downloading tools, Mimikatz-based credential dumping, data exfiltration via Discord, backdoor account creation, and lateral movement to an internal target.

The attacker's use of native Windows utilities such as `certutil.exe`, `schtasks.exe`, `wevtutil.exe`, `net.exe`, and `mstsc.exe` throughout the attack chain highlights the importance of behavioural detection over signature-based approaches in modern threat hunting.

---

## Recommendations

1. Immediately reset the password for `kenji.sato` and review all accounts for unauthorised access.
2. Remove the backdoor account `support` from the system and the Administrators group.
3. Block the C2 IP address `78.141.196.6` at the network perimeter firewall.
4. Remove all Windows Defender exclusions added by the attacker and perform a full system scan.
5. Investigate the lateral movement target `10.1.0.188` for signs of compromise.
6. Implement network detection rules for outbound connections to Discord and other cloud platforms from endpoints.
7. Enable enhanced logging and alerting for scheduled task creation, registry modifications, and account creation events.
8. Restrict the use of `certutil.exe` and other LOLBins for network downloads via application control policies.
