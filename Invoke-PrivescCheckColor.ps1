<#
.SYNOPSIS
    Color wrapper for PrivescCheck. Run this AFTER dot-sourcing PrivescCheck.ps1.

.DESCRIPTION
    Requires PrivescCheck.ps1 to be dot-sourced first, or in the same folder.

    USAGE (two files in same folder):
        powershell -ep bypass -c ". .\PrivescCheck.ps1; . .\ColorFilter.ps1; Invoke-PrivescCheckColor"

    USAGE (extended + filter):
        powershell -ep bypass -c ". .\PrivescCheck.ps1; . .\ColorFilter.ps1; Invoke-PrivescCheckColor -Extended -SeverityFilter Med"

    evil-winrm:
        upload PrivescCheck.ps1
        upload ColorFilter.ps1
        . .\PrivescCheck.ps1
        . .\ColorFilter.ps1
        Invoke-PrivescCheckColor -Extended

.PARAMETER Extended
    Pass -Extended to Invoke-PrivescCheck.
.PARAMETER SeverityFilter
    Hide output lines below this level: High, Med, Low, Info (default: show all).
#>
[CmdletBinding()]
param(
    [switch]$Extended,
    [switch]$Audit,
    [switch]$Force,
    [ValidateSet("High","Med","Low","Info","All")]
    [string]$SeverityFilter = "All"
)

function Invoke-PrivescCheckColor {
    param(
        [switch]$Extended,
        [switch]$Audit,
        [switch]$Force,
        [ValidateSet("High","Med","Low","Info","All")]
        [string]$SeverityFilter = "All"
    )

    $ESC = [char]27
    $Red     = "${ESC}[91m"
    $Yellow  = "${ESC}[93m"
    $Cyan    = "${ESC}[96m"
    $Green   = "${ESC}[92m"
    $Magenta = "${ESC}[95m"
    $White   = "${ESC}[97m"
    $Gray    = "${ESC}[37m"
    $Bold    = "${ESC}[1m"
    $Reset   = "${ESC}[0m"

    $SevRank = @{ High = 3; Med = 2; Low = 1; Info = 0; All = -1 }
    $FilterRank = $SevRank[$SeverityFilter]
    if ($null -eq $FilterRank) { $FilterRank = -1 }

    $Highs = @()
    $Total = 0

    # Header
    Write-Host ""
    Write-Host "${Bold}${Red}======================================================================${Reset}"
    Write-Host "${Bold}${White}  PrivescCheck :: Color Output Wrapper${Reset}"
    Write-Host "${Bold}${Red}======================================================================${Reset}"
    Write-Host "${Gray}  Engine: PrivescCheck by @itm4n (BSD 3-Clause)${Reset}"
    Write-Host ""
    Write-Host "  ${Bold}${Red}[+]${Reset} = Actionable finding    ${Bold}${Yellow}[conf]${Reset} = Configuration issue"
    Write-Host "  ${Cyan}[*]${Reset} = Info / enum data      ${Green}[!]${Reset} = Nothing found / passed"
    Write-Host ""

    # Check engine is loaded
    if (-not (Get-Command Invoke-PrivescCheck -ErrorAction SilentlyContinue)) {
        Write-Host "${Bold}${Red}  ERROR: Invoke-PrivescCheck not found.${Reset}"
        Write-Host "${Yellow}  Dot-source PrivescCheck.ps1 first:${Reset}"
        Write-Host "${Gray}    . .\PrivescCheck.ps1${Reset}"
        return
    }

    # Build params
    $ip = @{}
    if ($Extended) { $ip["Extended"] = $true }
    if ($Audit)    { $ip["Audit"]    = $true }
    if ($Force)    { $ip["Force"]    = $true }

    # Sensitive keywords to highlight in magenta
    $Keywords = @(
        'SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege',
        'SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege',
        'SeTakeOwnershipPrivilege','SeLoadDriverPrivilege',
        'AlwaysInstallElevated','Unquoted','Autologon','DefaultPassword',
        'cleartext','plaintext','password','NTLM','SAM','credential'
    )

    function Highlight-Keywords {
        param([string]$Line)
        foreach ($kw in $Keywords) {
            if ($Line -match [regex]::Escape($kw)) {
                $Line = $Line -replace "(?i)($([regex]::Escape($kw)))", "${Magenta}${Bold}`$1${Reset}"
            }
        }
        return $Line
    }

    # Run engine and colorize output line by line
    Invoke-PrivescCheck @ip | ForEach-Object {
        $line = "$_"
        $s    = $line.Trim()

        # Section banners (the ASCII box lines from Write-Banner)
        if ($s -match '^\+[-+]+\+$' -or $s -match '^\| TEST \|') {
            # Determine color from content
            if ($s -match 'VULN') {
                Write-Host "${Bold}${Red}${line}${Reset}"
            } elseif ($s -match 'CONF') {
                Write-Host "${Bold}${Yellow}${line}${Reset}"
            } else {
                Write-Host "${Cyan}${line}${Reset}"
            }
            return
        }

        # Actionable findings - RED
        if ($s -match '^\[\+\]') {
            $Total++
            $Highs += $s
            if ($FilterRank -le 3) {
                Write-Host "${Bold}${Red}$(Highlight-Keywords $line)${Reset}"
            }
            return
        }

        # Info findings - CYAN
        if ($s -match '^\[\*\]') {
            $Total++
            if ($FilterRank -le 0) {
                Write-Host "${Cyan}$(Highlight-Keywords $line)${Reset}"
            }
            return
        }

        # Nothing found - GREEN
        if ($s -match '^\[!\]') {
            if ($FilterRank -le -1) {
                Write-Host "${Green}${line}${Reset}"
            }
            return
        }

        # Data rows (table content under findings) - highlight keywords, dim color
        if ($s -ne "") {
            if ($FilterRank -le 0) {
                Write-Host "${Gray}$(Highlight-Keywords $line)${Reset}"
            }
            return
        }

        # Blank lines
        Write-Host ""
    }

    # Summary
    Write-Host ""
    Write-Host "${Bold}${White}======================================================================${Reset}"
    Write-Host "${Bold}${White}  SUMMARY${Reset}"
    Write-Host "${Bold}${White}======================================================================${Reset}"
    Write-Host ""
    Write-Host "  ${Bold}${Red}Actionable [+]: $($Highs.Count)${Reset}   ${Cyan}Total lines: $Total${Reset}"
    Write-Host ""

    if ($Highs.Count -gt 0) {
        Write-Host "${Bold}${Red}  Focus on these:${Reset}"
        Write-Host "${Gray}  $(- * 58)${Reset}"
        foreach ($h in $Highs) {
            Write-Host "  ${Bold}${Red}>>>${Reset} ${Red}$($h -replace '^\[\+\]\s*','')${Reset}"
        }
    } else {
        Write-Host "${Green}  No actionable findings.${Reset}"
    }
    Write-Host ""
}

# Auto-run if not dot-sourced
if ($MyInvocation.InvocationName -ne ".") {
    $p = @{}
    if ($Extended)                  { $p["Extended"]       = $true }
    if ($Audit)                     { $p["Audit"]          = $true }
    if ($Force)                     { $p["Force"]          = $true }
    if ($SeverityFilter -ne "All")  { $p["SeverityFilter"] = $SeverityFilter }
    Invoke-PrivescCheckColor @p
}
