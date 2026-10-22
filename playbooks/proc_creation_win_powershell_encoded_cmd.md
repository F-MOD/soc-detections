# Playbook: PowerShell Execution With Encoded Command

| Field | Value |
|---|---|
| Rule | [`proc_creation_win_powershell_encoded_cmd.yml`](../rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) |
| MITRE ATT&CK | T1059.001 (PowerShell), T1027 (Obfuscated Files or Information) |
| Severity | Medium |
| Log source | Sysmon EID 1 / Windows Security 4688 (with command line logging) |

## 1. What this alert means

PowerShell was launched with the `-EncodedCommand` parameter (or one of its abbreviations such as `-enc` or `-e`). The script is passed as Base64, so it cannot be read at a glance. There are legitimate uses, but it is a very common technique in malware, macro droppers and C2 frameworks.

## 2. Triage (first 5-10 minutes)

1. **Decode the command.** Base64 → UTF-16LE. In CyberChef: `From Base64` + `Decode text (UTF-16LE)`. In PowerShell:
```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<string>'))
```
2. **Check the parent process.** What launched it?
   - Suspicious: `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `wscript.exe`, `cmd.exe` spawned from a browser, `w3wp.exe`.
   - Common: management agents (SCCM `CcmExec.exe`, Intune, RMM tools), known scheduled tasks.
3. **User and host.** Standard user, admin or service account? Workstation or server?
4. **Decoded content.** Look for clear indicators:
   - Downloads: `IEX`, `Invoke-Expression`, `DownloadString`, `Net.WebClient`, `Invoke-WebRequest`
   - Further obfuscation: `FromBase64String`, `-join`, `[char]`, compression (`IO.Compression`)
   - Evasion: `AmsiUtils`, `Set-MpPreference`, `-WindowStyle Hidden`, `-nop`
5. **Follow-up activity on the host** (±15 min): network connections from the process, child processes, files created, registry changes.

## 3. Common false positives

- Administration and deployment scripts (SCCM, Intune, GPO).
- EDR, RMM or backup agents that routinely run encoded PowerShell.
- Internal IT tooling with a known, repetitive parent process, user and content.

**How to confirm:** same parent + same service account + same decoded content seen before in the environment and documented.

## 4. Decision

| Situation | Action |
|---|---|
| Legitimate, known and documented parent and content | Close as false positive and propose a narrow exclusion (parent + user + content hash, never just "powershell") |
| Benign content but unknown origin | Check with the asset owner before closing |
| Office/browser/script parent, remote download, AMSI/Defender evasion or connection to an external IP/domain | **Escalate** |

## 5. Information to include when escalating

- Host, user, timestamp and full parent process (with its command line)
- Decoded command
- Extracted IPs, domains or URLs and their reputation
- Child processes and observed network connections
- Recommended containment actions (isolate host, block IOCs, reset credentials)

## 6. References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)