#Requires -Version 2

<#
.SYNOPSIS
    Color-enhanced output wrapper for PrivescCheck.

.DESCRIPTION
    Wraps PrivescCheck (github.com/itm4n/PrivescCheck) and replaces its plain-text
    terminal output with ANSI severity-colored rendering. All detection logic is
    unmodified and belongs entirely to the original author.

    The wrapper intercepts Write-CheckBanner and Write-CheckResult after the original
    script loads, replacing them with color-aware equivalents. No check functions,
    enumeration logic, or severity assignments are altered.

    Severity color mapping:
        High    - Red    (immediate privilege escalation vector)
        Medium  - Yellow (exploitable misconfiguration)
        Low     - Cyan   (informational, low-confidence finding)
        Info    - Cyan   (enumeration data, no direct risk)
        None    - Green  (check completed, no finding)

    Sensitive strings found in result output (privilege names, credential keywords,
    writable system paths, identity strings) are highlighted inline in a distinct
    color for fast visual triage.

.NOTES
    Original tool  : PrivescCheck by Thomas Lacroix (@itm4n)
    Original source: https://github.com/itm4n/PrivescCheck
    Original license: BSD 3-Clause

    This wrapper was written for OSCP preparation and authorized penetration testing.
    It introduces no new detection capability. Credit for all findings belongs to
    the PrivescCheck project.

.PARAMETER Extended
    Passed through to Invoke-PrivescCheck. Enables extended check coverage.

.PARAMETER Audit
    Passed through to Invoke-PrivescCheck. Enables audit-level checks.

.PARAMETER Experimental
    Passed through to Invoke-PrivescCheck. Enables experimental checks.

.PARAMETER Risky
    Passed through to Invoke-PrivescCheck. Enables checks that may trigger
    endpoint protection. Use with caution.

.PARAMETER Force
    Passed through to Invoke-PrivescCheck. Bypasses the admin privilege warning.

.PARAMETER Report
    Passed through to Invoke-PrivescCheck. Writes output to a report file.

.PARAMETER Format
    Passed through to Invoke-PrivescCheck. Report format: TXT, HTML, CSV, XML.

.PARAMETER SeverityFilter
    Suppress results below this severity level. Accepted values:
    High, Medium, Low, Info, None. Default is None (show all).

.PARAMETER NoColor
    Disable ANSI escape sequences. Use when redirecting output to a file
    or when the terminal does not support ANSI codes.

.PARAMETER NoLogo
    Suppress the header block.

.PARAMETER SourceScript
    Explicit path or URL to PrivescCheck.ps1. When not specified the wrapper
    checks the local directory then downloads from the GitHub release URL.

.EXAMPLE
    powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor"

.EXAMPLE
    powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -Extended -SeverityFilter Medium"

.EXAMPLE
    powershell -ep bypass -c ". .\Invoke-PrivescCheckColor.ps1; Invoke-PrivescCheckColor -Extended -Audit -Report out -Format HTML"

.EXAMPLE
    # In-memory execution, no disk write
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kowalski-analysis/PrivescCheck-Color/main/Invoke-PrivescCheckColor.ps1'); Invoke-PrivescCheckColor -Extended -SeverityFilter Medium
#>

[CmdletBinding()]
param(
    [switch] $Extended,
    [switch] $Audit,
    [switch] $Experimental,
    [switch] $Risky,
    [switch] $Force,
    [string] $Report,
    [string] $Format,
    [switch] $NoColor,
    [switch] $NoLogo,
    [ValidateSet("High","Medium","Low","Info","None")]
    [string] $SeverityFilter = "None",
    [string] $SourceScript   = ""
)

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# ANSI COLOR LAYER
# ---------------------------------------------------------------------------
# Detect whether the host terminal can render ANSI escape sequences.
# Conditions that disable color:
#   - -NoColor switch was passed
#   - Host has no window (non-interactive / output redirected)
#   - Running under PowerShell 2 where $Host.UI.RawUI.WindowSize is unreliable

$script:ColorEnabled = $false
if (-not $NoColor) {
    try {
        $w = $Host.UI.RawUI.WindowSize.Width
        if ($w -gt 0) { $script:ColorEnabled = $true }
    } catch { }
}

$ESC = [char]27

# Named ANSI codes kept in a hashtable for readability.
# Foreground colors use the bright variants (9x) for better contrast on
# dark terminal backgrounds common in pentest environments.
$script:Ansi = @{
    Reset      = "$ESC[0m"
    Bold       = "$ESC[1m"
    Red        = "$ESC[91m"
    Yellow     = "$ESC[93m"
    Cyan       = "$ESC[96m"
    Green      = "$ESC[92m"
    White      = "$ESC[97m"
    Gray       = "$ESC[37m"
    Magenta    = "$ESC[95m"
    DimGray    = "$ESC[2;37m"
}

function script:Ansi-Wrap {
    param([string]$Text, [string]$Code, [switch]$Bold)
    if (-not $script:ColorEnabled) { return $Text }
    $b = if ($Bold) { $script:Ansi.Bold } else { "" }
    return "$b$($script:Ansi[$Code])$Text$($script:Ansi.Reset)"
}

function script:Write-Colored {
    param([string]$Text, [string]$Color = "White", [switch]$NoNewline, [switch]$Bold)
    $out = Ansi-Wrap -Text $Text -Code $Color -Bold:$Bold
    if ($NoNewline) { Write-Host $out -NoNewline } else { Write-Host $out }
}

# ---------------------------------------------------------------------------
# SEVERITY CONFIGURATION
# ---------------------------------------------------------------------------
# Each severity level maps to a display color, a fixed-width label, and a
# numeric rank used by SeverityFilter comparisons.

$script:SevMap = @{
    High   = @{ Color = "Red";    Label = "[HIGH]  "; Rank = 4 }
    Medium = @{ Color = "Yellow"; Label = "[MED]   "; Rank = 3 }
    Low    = @{ Color = "Cyan";   Label = "[LOW]   "; Rank = 2 }
    Info   = @{ Color = "Cyan";   Label = "[INFO]  "; Rank = 1 }
    None   = @{ Color = "Green";  Label = "[PASS]  "; Rank = 0 }
}

$script:FilterRank = $script:SevMap[$SeverityFilter].Rank
if ($null -eq $script:FilterRank) { $script:FilterRank = 0 }

function script:Get-SevConf {
    param([string]$Severity)
    $key = if ($script:SevMap.ContainsKey($Severity)) { $Severity } else { "Info" }
    return $script:SevMap[$key]
}

function script:Passes-Filter {
    param([string]$Severity)
    $conf = Get-SevConf $Severity
    return $conf.Rank -ge $script:FilterRank
}

# ---------------------------------------------------------------------------
# KEYWORD HIGHLIGHTER
# ---------------------------------------------------------------------------
# Patterns that indicate sensitive data in check output. When found in a
# result property value, the matching substring is wrapped in magenta.
# The list is intentionally narrow — only strings with direct exploit or
# credential relevance are highlighted to avoid false urgency.

$script:SensitiveTerms = @(
    # Windows privilege names exploitable for local privilege escalation
    'SeImpersonatePrivilege',
    'SeAssignPrimaryTokenPrivilege',
    'SeTcbPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeDebugPrivilege',
    'SeTakeOwnershipPrivilege',
    'SeLoadDriverPrivilege',
    'SeRelabelPrivilege',
    'SeCreateTokenPrivilege',

    # Misconfiguration check names / keywords
    'AlwaysInstallElevated',
    'Unquoted',
    'AutoRun',
    'Autologon',
    'DefaultPassword',
    'CachedLogonPassword',

    # Credential-adjacent strings
    'password',
    'passwd',
    'cleartext',
    'plaintext',
    'NTLM',
    'SAM',
    'LSA',
    'credential',
    'token',
    'secret',

    # High-value security identities
    'NT AUTHORITY\\SYSTEM',
    'BUILTIN\\Administrators',
    'Everyone',
    'BUILTIN\\Users',

    # Writable paths in sensitive locations
    'C:\\Windows\\System32',
    'C:\\Windows\\SysWOW64',
    'C:\\Program Files\\'
)

function script:Highlight-Keywords {
    param([string]$Text)
    if (-not $script:ColorEnabled) { return $Text }
    foreach ($term in $script:SensitiveTerms) {
        $escaped = [regex]::Escape($term)
        if ($Text -match "(?i)$escaped") {
            $Text = $Text -replace "(?i)($escaped)",
                "$($script:Ansi.Magenta)$($script:Ansi.Bold)`$1$($script:Ansi.Reset)"
        }
    }
    return $Text
}

# ---------------------------------------------------------------------------
# RESULT RENDERER
# ---------------------------------------------------------------------------
$script:AllResults   = @()
$script:DIVIDER_MAIN = "-" * 72
$script:DIVIDER_SECT = "=" * 72

function script:Render-ResultObject {
    param($Obj, [string]$Color)
    if ($null -eq $Obj) { return }

    if ($Obj -is [System.Management.Automation.PSObject] -or $Obj -is [hashtable]) {
        $keys = if ($Obj -is [hashtable]) { $Obj.Keys } else { $Obj.PSObject.Properties.Name }
        foreach ($k in $keys) {
            $v = "$($Obj.$k)"
            if ($v -eq "" -or $v -eq $null) { continue }
            $keyPart = Ansi-Wrap -Text ("  " + $k.PadRight(30)) -Code "Gray"
            $valPart = Highlight-Keywords -Text $v

            # Escalate the value color to red if it contains a directly dangerous string
            $dangerous = ($v -match 'SeImpersonate|SeAssignPrimary|SeTcb|AlwaysInstallElevated|cleartext|Everyone|NT AUTHORITY\\SYSTEM')
            if ($dangerous) {
                $valPart = Ansi-Wrap -Text $valPart -Code "Red" -Bold
            } else {
                $valPart = Ansi-Wrap -Text $valPart -Code $Color
            }
            Write-Host "$keyPart  $valPart"
        }
    } else {
        $line = Highlight-Keywords -Text "$Obj"
        Write-Host (Ansi-Wrap -Text "  $line" -Code $Color)
    }
}

function global:Write-CheckBanner {
    # Intentionally suppressed. The check header is rendered inside
    # Write-CheckResult so that the severity label precedes the title
    # on the same line, matching the winPEAS/linPEAS triage style.
    param([object]$Check)
}

function global:Write-CheckResult {
    param([object]$CheckResult, [object]$Check)

    $script:AllResults += $CheckResult

    $severity = "None"
    if ($null -ne $CheckResult -and $null -ne $CheckResult.Severity) {
        $severity = $CheckResult.Severity.ToString()
    }

    if (-not (Passes-Filter -Severity $severity)) { return }

    $conf  = Get-SevConf -Severity $severity
    $color = $conf.Color
    $label = $conf.Label

    # Resolve display name — field naming is inconsistent across check modules
    $name = ""
    if ($null -ne $Check) {
        if ($Check.DisplayName) { $name = $Check.DisplayName }
        elseif ($Check.Name)    { $name = $Check.Name }
    }
    $id       = if ($null -ne $Check -and $Check.Id)          { $Check.Id }          else { "" }
    $category = if ($null -ne $Check -and $Check.Category)    { $Check.Category }    else { "" }
    $desc     = if ($null -ne $Check -and $Check.Description) { $Check.Description } else { "" }

    Write-Host (Ansi-Wrap -Text $script:DIVIDER_MAIN -Code $color)

    # Header line: [SEVERITY]  CATEGORY / Check Name
    $headerText = if ($category -ne "") { "$category  /  $name" } else { $name }
    Write-Host (Ansi-Wrap -Text "$label" -Code $color -Bold) -NoNewline
    Write-Host (Ansi-Wrap -Text $headerText -Code $color -Bold)

    if ($id -ne "") {
        Write-Host (Ansi-Wrap -Text "  ID: $id" -Code "DimGray")
    }
    if ($desc -ne "") {
        Write-Host (Ansi-Wrap -Text "  $desc" -Code "Gray")
    }

    Write-Host ""

    # Result data
    $raw = $CheckResult.ResultRaw
    if ($null -ne $raw) {
        if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) {
            foreach ($item in $raw) {
                Render-ResultObject -Obj $item -Color $color
            }
        } else {
            Render-ResultObject -Obj $raw -Color $color
        }
    } elseif ($null -ne $CheckResult.ResultString -and $CheckResult.ResultString -ne "") {
        $line = Highlight-Keywords -Text $CheckResult.ResultString
        Write-Host (Ansi-Wrap -Text "  $line" -Code $color)
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
function script:Write-Summary {
    Write-Host ""
    Write-Host (Ansi-Wrap -Text $script:DIVIDER_SECT -Code "White" -Bold)
    Write-Host (Ansi-Wrap -Text "  RESULTS SUMMARY" -Code "White" -Bold)
    Write-Host (Ansi-Wrap -Text $script:DIVIDER_SECT -Code "White" -Bold)
    Write-Host ""

    $counts = @{ High=0; Medium=0; Low=0; Info=0; None=0 }
    foreach ($r in $script:AllResults) {
        $s = if ($r.Severity) { $r.Severity.ToString() } else { "None" }
        if ($counts.ContainsKey($s)) { $counts[$s]++ }
    }

    $line = @(
        (Ansi-Wrap "High: $($counts.High)"     "Red"    -Bold),
        (Ansi-Wrap "Medium: $($counts.Medium)" "Yellow"      ),
        (Ansi-Wrap "Low: $($counts.Low)"       "Cyan"        ),
        (Ansi-Wrap "Info: $($counts.Info)"     "Cyan"        ),
        (Ansi-Wrap "Pass: $($counts.None)"     "Green"       )
    ) -join "    "
    Write-Host "  $line"
    Write-Host ""

    # Actionable findings list
    $actionable = $script:AllResults | Where-Object {
        $s = if ($_.Severity) { $_.Severity.ToString() } else { "None" }
        $s -eq "High" -or $s -eq "Medium"
    }

    if ($actionable.Count -gt 0) {
        Write-Host (Ansi-Wrap "  Actionable findings:" -Code "White" -Bold)
        Write-Host (Ansi-Wrap ("  " + "-" * 60) -Code "Gray")
        foreach ($r in $actionable) {
            $s    = $r.Severity.ToString()
            $conf = Get-SevConf -Severity $s
            $n    = if ($r.DisplayName) { $r.DisplayName } elseif ($r.Id) { $r.Id } else { "unknown" }
            $tag  = Ansi-Wrap $conf.Label $conf.Color -Bold
            Write-Host "  $tag  $n"
        }
    } else {
        Write-Host (Ansi-Wrap "  No High or Medium severity findings." -Code "Green")
    }

    Write-Host ""
    Write-Host (Ansi-Wrap $script:DIVIDER_SECT -Code "Gray")
    Write-Host (Ansi-Wrap "  PrivescCheck by @itm4n  --  https://github.com/itm4n/PrivescCheck" -Code "DimGray")
    Write-Host ""
}

# ---------------------------------------------------------------------------
# HEADER BLOCK
# ---------------------------------------------------------------------------
function script:Write-Header {
    if ($NoLogo) { return }

    $w = Ansi-Wrap -Text "PrivescCheck" -Code "White" -Bold
    $r = Ansi-Wrap -Text "color wrapper" -Code "Red"

    Write-Host ""
    Write-Host (Ansi-Wrap $script:DIVIDER_SECT -Code "Red" -Bold)
    Write-Host (Ansi-Wrap "  PrivescCheck  --  Color Output Wrapper" -Code "White" -Bold)
    Write-Host (Ansi-Wrap $script:DIVIDER_SECT -Code "Red" -Bold)
    Write-Host ""
    Write-Host (Ansi-Wrap "  Detection engine : PrivescCheck by @itm4n" -Code "Gray")
    Write-Host (Ansi-Wrap "  Source           : https://github.com/itm4n/PrivescCheck" -Code "Gray")
    Write-Host (Ansi-Wrap "  License          : BSD 3-Clause" -Code "Gray")
    Write-Host ""
    Write-Host (Ansi-Wrap "  Severity output:" -Code "White")
    Write-Host "  $(Ansi-Wrap '[HIGH]  ' 'Red'    -Bold) Immediate privilege escalation vector"
    Write-Host "  $(Ansi-Wrap '[MED]   ' 'Yellow')       Exploitable misconfiguration"
    Write-Host "  $(Ansi-Wrap '[LOW]   ' 'Cyan')         Low-confidence or informational finding"
    Write-Host "  $(Ansi-Wrap '[PASS]  ' 'Green')        Check completed, no issue found"
    Write-Host "  $(Ansi-Wrap 'keyword' 'Magenta')       Sensitive string highlighted inline"
    Write-Host ""
    if ($SeverityFilter -ne "None") {
        Write-Host (Ansi-Wrap "  Filter active: showing $SeverityFilter and above only" -Code "Yellow")
        Write-Host ""
    }
    Write-Host (Ansi-Wrap $script:DIVIDER_SECT -Code "Gray")
    Write-Host ""
}

# ---------------------------------------------------------------------------
# PRIVESCCHECK LOADER
# ---------------------------------------------------------------------------
function script:Load-PrivescCheck {
    param([string]$Source)

    $releaseUrl = "https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1"

    if ($Source -ne "") {
        if ($Source -match '^https?://') {
            Write-Colored "  Loading PrivescCheck from URL: $Source" "Cyan"
            try {
                $code = (New-Object Net.WebClient).DownloadString($Source)
                Invoke-Expression $code
                return $true
            } catch {
                Write-Colored "  Error: download failed. $_" "Red"
                return $false
            }
        }
        if (Test-Path $Source) {
            Write-Colored "  Loading PrivescCheck: $Source" "Cyan"
            . $Source
            return $true
        }
        Write-Colored "  Error: file not found: $Source" "Red"
        return $false
    }

    if (Get-Command -Name "Invoke-PrivescCheck" -ErrorAction SilentlyContinue) {
        Write-Colored "  PrivescCheck already loaded in session." "Green"
        return $true
    }

    $localPath = Join-Path (Split-Path -Parent $MyInvocation.PSCommandPath) "PrivescCheck.ps1"
    if (Test-Path $localPath) {
        Write-Colored "  Loading PrivescCheck from local directory." "Cyan"
        . $localPath
        return $true
    }

    Write-Colored "  Downloading PrivescCheck from GitHub releases..." "Cyan"
    try {
        $code = (New-Object Net.WebClient).DownloadString($releaseUrl)
        Invoke-Expression $code
        Write-Colored "  Download complete." "Green"
        return $true
    } catch {
        Write-Colored "  Download failed: $_" "Red"
        Write-Colored "  Load manually with:" "Yellow"
        Write-Colored "    IEX (New-Object Net.WebClient).DownloadString('$releaseUrl')" "Gray"
        return $false
    }
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
function Invoke-PrivescCheckColor {
    <#
    .SYNOPSIS
        Run PrivescCheck with color-coded severity output.
    #>
    [CmdletBinding()]
    param(
        [switch] $Extended,
        [switch] $Audit,
        [switch] $Experimental,
        [switch] $Risky,
        [switch] $Force,
        [string] $Report,
        [string] $Format,
        [switch] $NoColor,
        [switch] $NoLogo,
        [ValidateSet("High","Medium","Low","Info","None")]
        [string] $SeverityFilter = "None",
        [string] $SourceScript   = ""
    )

    if ($NoColor) { $script:ColorEnabled = $false }

    if ($PSBoundParameters.ContainsKey("SeverityFilter")) {
        $script:FilterRank = $script:SevMap[$SeverityFilter].Rank
        if ($null -eq $script:FilterRank) { $script:FilterRank = 0 }
    }

    Write-Header

    $loaded = Load-PrivescCheck -Source $SourceScript
    if (-not $loaded) { return }

    Write-Host (Ansi-Wrap "  Running checks..." -Code "Cyan")
    Write-Host (Ansi-Wrap $script:DIVIDER_MAIN -Code "Gray")
    Write-Host ""

    $invokeParams = @{}
    if ($Extended)     { $invokeParams["Extended"]     = $true }
    if ($Audit)        { $invokeParams["Audit"]        = $true }
    if ($Experimental) { $invokeParams["Experimental"] = $true }
    if ($Risky)        { $invokeParams["Risky"]        = $true }
    if ($Force)        { $invokeParams["Force"]        = $true }
    if ($Report)       { $invokeParams["Report"]       = $Report }
    if ($Format)       { $invokeParams["Format"]       = $Format }

    $script:AllResults = @()

    try {
        Invoke-PrivescCheck @invokeParams
    } catch {
        Write-Colored "  Scan error: $_" "Red"
    }

    Write-Summary
}

# ---------------------------------------------------------------------------
# AUTO-RUN when executed directly (not dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne "." -and $MyInvocation.Line -notmatch "^\s*\.") {
    $p = @{}
    if ($Extended)                                       { $p["Extended"]       = $true }
    if ($Audit)                                          { $p["Audit"]          = $true }
    if ($Experimental)                                   { $p["Experimental"]   = $true }
    if ($Risky)                                          { $p["Risky"]          = $true }
    if ($Force)                                          { $p["Force"]          = $true }
    if ($Report)                                         { $p["Report"]         = $Report }
    if ($Format)                                         { $p["Format"]         = $Format }
    if ($NoColor)                                        { $p["NoColor"]        = $true }
    if ($NoLogo)                                         { $p["NoLogo"]         = $true }
    if ($SourceScript)                                   { $p["SourceScript"]   = $SourceScript }
    if ($SeverityFilter -and $SeverityFilter -ne "None") { $p["SeverityFilter"] = $SeverityFilter }
    Invoke-PrivescCheckColor @p
}
