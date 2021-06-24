---
title: "Threathunting: PowerShell remoting for lateral movement"
layout: post
category: [Threathunting, Splunk, Elastic Siem, WinRM] 
tags: [powershell, WinRM, remote, lateral movement, threathunting]
---

## PowerShell remoting for lateral movement.

### What is PowerShell remoting. 
> "Using the WS-Management protocol, Windows PowerShell remoting lets you run any Windows PowerShell command on one or more remote computers. You can establish persistent connections, start interactive sessions, and run scripts on remote computers.
> To use Windows PowerShell remoting, the remote computer must be configured for remote management. For more information, including instructions, see [About Remote Requirements](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements).
> Once you have configured Windows PowerShell remoting, many remoting strategies are available to you. This article lists just a few of them. For more information, see [About Remote](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote)."

### Attacker's Goals: 
Windows Remote Management (WinRM) enables users to interact with remote systems, including running executable on remote endpoints. Attackers can use WinRM to execute code and move laterally within a compromised network. 
<!--break-->

<table>
  <tr>
    <th>ATT&CK Tactic</th>
    <td><a href="https://attack.mitre.org/tactics/TA0008/">Lateral Movement</a></td>
  </tr>
  <tr>
    <th>ATT&CK Technique</th>
    <td><a href="https://attack.mitre.org/techniques/T1021/006/">Remote Services: Windows Remote Management</a></td>
  </tr>
  <tr>
    <th>Severity</th>
    <td>Informational</td>
  </tr>
</table>

### Lab setup: 
Kali machine (Hostname: KALI): 192.168.35.6

Windows Server 2019 Domain Controller (Hostname: DEALER): 192.168.35.5

Domain: BLACKJACK.local

User: ACE (Domain Admin account)

#### Monitoring:
- Local Splunk intance running on DEALER
- Elastic Cloud with Winlogbeat setup. 

## Execution: 

**Use case 1 (evil-winrm):**

Connecting from my KALI instance to DEALER using evil-winrm. 

```bash
┌──(kali㉿kali)-[~/Documents/projects]
└─$ evil-winrm -i 192.168.35.5 -u ACE -p 'P@$$W0rD'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ACE\Documents>
```

Running ipconfig and whoami within session. 

```bash 
*Evil-WinRM* PS C:\Users\ACE\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::2c59:a185:a7ad:3759%8
   IPv4 Address. . . . . . . . . . . : 192.168.35.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.35.1
```

```bash 
*Evil-WinRM* PS C:\Users\ACE\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ============================================
blackjack\ace S-1-5-21-160870316-2314245498-532306953-1103


GROUP INFORMATION
-----------------

Group Name                                       Type             SID                                         Attributes
================================================ ================ =========================================== 
Everyone                                         Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
**TRUNC**
Mandatory Label\High Mandatory Level             Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
**TRUNC**
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

## Observations: 

**Splunk:** 

The following three events where created when spawning a shell using evil-winrm. 

- Event ID 4672: Special privileges assigned to new logon.
- Event ID 4624: An account was successfully logged on.
- Event ID 1: Process Create (rule: ProcessCreate) 

**Event ID 4672:**

```sql
Special privileges assigned to new logon.

Subject:
	Security ID:		S-1-5-21-160870316-2314245498-532306953-1104
	Account Name:		jack_winrm
	Account Domain:		BLACKJACK
	Logon ID:		0x64D3D4

Privileges:		SeSecurityPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeTakeOwnershipPrivilege
			SeDebugPrivilege
			SeSystemEnvironmentPrivilege
			SeLoadDriverPrivilege
			SeImpersonatePrivilege
			SeDelegateSessionUserImpersonatePrivilege
			SeEnableDelegationPrivilege
```

**Event ID 4624:** 

We can see that this activity will generate a logon type 3 (Network) with the logon process being *NtlmSsp* and authentication package *NTML*

```sql
An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-160870316-2314245498-532306953-1104
	Account Name:		jack_winrm
	Account Domain:		BLACKJACK
	Logon ID:		0x64D3D4
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	-
	Source Port:		-

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128
```

**Event ID 1:** 

We can see when connected with WinRM *svchost* will spawn and process for *wsmprovhost*. 

```sql 
06/24/2021 06:33:18 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=1
EventType=4
ComputerName=dealer.blackjack.local
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=76122
Keywords=None
TaskCategory=Process Create (rule: ProcessCreate)
OpCode=Info
Message=Process Create:
RuleName: -
UtcTime: 2021-06-24 13:33:18.445
ProcessGuid: {a95c9ede-899e-60d4-e391-2d0300000000}
ProcessId: 6276
Image: C:\Windows\System32\wsmprovhost.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host process for WinRM plug-ins
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: wsmprovhost.exe
CommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
CurrentDirectory: C:\Windows\system32\
User: BLACKJACK\jack_winrm
LogonGuid: {a95c9ede-899e-60d4-478e-2d0300000000}
LogonId: 0x64D3D4
TerminalSessionId: 0
IntegrityLevel: High
Hashes: MD5=09F572A6ED60FDE02F8B9471AA896EBC,SHA256=12FA07164960F1C7362404449E4755F7DB494DDA7D369D8EABB2B56D92EBEC67,IMPHASH=75953E6C912ADB7F5C32D66F1A60AA30
ParentProcessGuid: {a95c9ede-5df7-60d2-c773-000000000000}
ParentProcessId: 760
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p
```

Using the Logon ID we can track any child processes being created within the Logon sessions. 

> Logon ID:	0x64D3D4

We are able to see all child process will have a parent image of  *wsmprovhost.exe*. 

*whoami.exe* process being spawned: 

```sql
Process Create:
RuleName: -
UtcTime: 2021-06-22 13:58:33.536
ProcessGuid: {a95c9ede-ec89-60d1-2530-650000000000}
ProcessId: 6516
Image: C:\Windows\System32\whoami.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: whoami - displays logged on user information
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: whoami.exe
CommandLine: "C:\Windows\system32\whoami.exe" /all
CurrentDirectory: C:\Users\ACE\Documents\
User: BLACKJACK\ACE
LogonGuid: {a95c9ede-ec7f-60d1-d4d3-640000000000}
LogonId: 0x64D3D4
TerminalSessionId: 0
IntegrityLevel: High
Hashes: MD5=43C2D3293AD939241DF61B3630A9D3B6,SHA256=1D5491E3C468EE4B4EF6EDFF4BBC7D06EE83180F6F0B1576763EA2EFE049493A,IMPHASH=7FF0758B766F747CE57DFAC70743FB88
ParentProcessGuid: {a95c9ede-ec7f-60d1-c7d7-640000000000}
ParentProcessId: 5336
ParentImage: C:\Windows\System32\wsmprovhost.exe
ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
```

*ipconfig.exe* process  being spawned:

```sql
Process Create:
RuleName: -
UtcTime: 2021-06-22 14:00:44.431
ProcessGuid: {a95c9ede-ed0c-60d1-69a6-6a0000000000}
ProcessId: 3800
Image: C:\Windows\System32\ipconfig.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: IP Configuration Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: ipconfig.exe
CommandLine: "C:\Windows\system32\ipconfig.exe"
CurrentDirectory: C:\Users\ACE\Documents\
User: BLACKJACK\ACE
LogonGuid: {a95c9ede-ec7f-60d1-d4d3-640000000000}
LogonId: 0x64D3D4
TerminalSessionId: 0
IntegrityLevel: High
Hashes: MD5=3D33188ECD39ECFEEA2E08996891C76E,SHA256=C5DBBDDD1193C7ADCA1E30CD17B8C7AF6A76C406DD84DC164BB959C135F1AA70,IMPHASH=15167A60983BFC39B2DA4F53B9B1F28C
ParentProcessGuid: {a95c9ede-ec7f-60d1-c7d7-640000000000}
ParentProcessId: 5336
ParentImage: C:\Windows\System32\wsmprovhost.exe
ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
```

Below image show a timeline view of all events within the given Logon sessions. 
![](/assets/images/powershell_remoting_threathunting//windows_timeline.png)

**Elastic Cloud:**

Reviewing the same logs within Elastic Cloud. 

![](/assets/images/powershell_remoting_threathunting/elk_timeline_events.png)

![](/assets/images/powershell_remoting_threathunting/elk_timeline_graph.png)

## Detection: 

**Detection initial WinRM session:** 

**Splunk SPL:** 

```sql 
index="wineventlogs" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="C:\\Windows\\System32\\svchost.exe" Image="*wsmprovhost.exe*"
```

**Detection child processes spawned by WinRM session:** 

**Splunk SPL:** 

```sql 
index="wineventlogs" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*wsmprovhost.exe*"
```

**Tracking all events for giving session:**

**Splunk SPL:**

```sql
index="wineventlogs" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" LogonId=0x20A2F24
```

### References: 
<a href="https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1">https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1</a>

<a href="https://github.com/Hackplayers/evil-winrm">https://github.com/Hackplayers/evil-winrm</a>

