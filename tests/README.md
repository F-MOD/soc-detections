# Detection Testing

Every rule is tested against **public datasets of simulated attacks**, never against data from a real environment.

## Environment

- **Azure Data Explorer** free cluster ([dataexplorer.azure.com/freecluster](https://dataexplorer.azure.com/freecluster))
- Datasets ingested as JSON, one table per dataset
- Test queries use raw **Sysmon field names** (`Image`, `CommandLine`), so they differ slightly from the converted queries in `queries/kql/`, which use Defender XDR field names

## Datasets

| Dataset | Source | Description |
|---|---|---|
| `empire_launcher_vbs` | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip) | PowerShell Empire stager launched from a malicious VBS file |

## Test results

| Rule | Dataset | Events | Hits | True positives | False positives | Result |
|---|---|---|---|---|---|---|
| [PowerShell Encoded Command](../rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) | `empire_launcher_vbs` | ~2,000 | 1 | 1 | 0 | ✅ Pass |

## Findings

### PowerShell Encoded Command × empire_launcher_vbs

- **Hit:** `powershell.exe -noP -sta -w 1 -enc ...` launched by `wscript.exe` (user `THESHIRE\pgustavo`, host `WORKSTATION5`).
- **Decoded payload:** PowerShell Empire stager that:
  - disables Script Block Logging and AMSI,
  - downloads an RC4-encrypted agent from `http://10.10.10.5/news.php` using `Net.WebClient` with a spoofed IE11 User-Agent,
  - decrypts it and runs it in memory with `IEX`.
- **Triage outcome (per playbook):** suspicious parent + remote download + AMSI evasion → **Escalate**.