#Requires -Version 2
<#
.SYNOPSIS
    PrivescCheck with ANSI color output — single standalone file, no internet required.

.DESCRIPTION
    Merged self-contained script. Drop ONE file on the target and run it.
    Contains the full PrivescCheck detection engine (BSD 3-Clause, @itm4n)
    plus a severity-colored output layer for fast pentest triage.

    USAGE:
        powershell -ep bypass -c ". .\PrivescCheck-Color.ps1; Invoke-PrivescCheckColor"
        powershell -ep bypass -c ". .\PrivescCheck-Color.ps1; Invoke-PrivescCheckColor -Extended -SeverityFilter Medium"

    CLM / Constrained Language Mode bypass:
        Get-Content .\PrivescCheck-Color.ps1 | Out-String | Invoke-Expression
        Invoke-PrivescCheckColor -Extended

    evil-winrm:
        upload PrivescCheck-Color.ps1
        . .\PrivescCheck-Color.ps1
        Invoke-PrivescCheckColor -Extended -SeverityFilter Medium

    SEVERITY LEGEND:
        [HIGH]   Red       Direct privilege escalation vector
        [MED]    Yellow    Exploitable misconfiguration
        [LOW]    Cyan      Low-confidence / informational
        [PASS]   Green     Nothing found
        keyword  Magenta   Sensitive string highlighted inline

.NOTES
    Detection engine : PrivescCheck by Thomas Lacroix (@itm4n)
    Engine source    : https://github.com/itm4n/PrivescCheck
    Engine license   : BSD 3-Clause
    Color layer      : kowalski-analysis (offline standalone merge)

.PARAMETER Extended
    Enable extended checks.
.PARAMETER Audit
    Enable audit checks.
.PARAMETER Experimental
    Enable experimental checks.
.PARAMETER Risky
    Enable checks that may trigger AV/EDR.
.PARAMETER Force
    Skip the "already admin" warning.
.PARAMETER Report
    Write report to disk with this filename prefix.
.PARAMETER Format
    Report format: TXT, HTML, CSV, XML (comma-separated).
.PARAMETER SeverityFilter
    Only show findings at or above this level: High, Medium, Low, Info, None (default).
.PARAMETER NoColor
    Disable ANSI escape codes (pipe-safe).
.PARAMETER NoLogo
    Suppress the banner.
#>
[CmdletBinding()]
param(
    [switch]$Extended,
    [switch]$Audit,
    [switch]$Experimental,
    [switch]$Risky,
    [switch]$Force,
    [string]$Report         = "",
    [string]$Format         = "",
    [switch]$NoColor,
    [switch]$NoLogo,
    [ValidateSet("High","Medium","Low","Info","None")]
    [string]$SeverityFilter = "None"
)
Set-StrictMode -Off


# ===========================================================================
# COLOR ENGINE
# ===========================================================================
$script:ColorEnabled = $false
if (-not $NoColor) {
    try {
        $w = $Host.UI.RawUI.WindowSize.Width
        if ($w -gt 0) { $script:ColorEnabled = $true }
    } catch { }
}

$ESC = [char]27
$script:Ansi = @{
    Reset   = "$ESC[0m"
    Bold    = "$ESC[1m"
    Red     = "$ESC[91m"
    Yellow  = "$ESC[93m"
    Cyan    = "$ESC[96m"
    Green   = "$ESC[92m"
    White   = "$ESC[97m"
    Gray    = "$ESC[37m"
    Magenta = "$ESC[95m"
    DimGray = "$ESC[2;37m"
}

function script:cc {
    param([string]$Text, [string]$Code = "White", [switch]$B)
    if (-not $script:ColorEnabled) { return $Text }
    $b = if ($B) { $script:Ansi.Bold } else { "" }
    return "$b$($script:Ansi[$Code])$Text$($script:Ansi.Reset)"
}
function script:cw {
    param([string]$Text, [string]$Color = "White", [switch]$N, [switch]$B)
    $out = cc -Text $Text -Code $Color -B:$B
    if ($N) { Write-Host $out -NoNewline } else { Write-Host $out }
}

$script:SevMap = @{
    High   = @{ Color = "Red";   Label = "[HIGH] "; Rank = 4 }
    Medium = @{ Color = "Yellow";Label = "[MED]  "; Rank = 3 }
    Low    = @{ Color = "Cyan";  Label = "[LOW]  "; Rank = 2 }
    Info   = @{ Color = "Cyan";  Label = "[INFO] "; Rank = 1 }
    None   = @{ Color = "Green"; Label = "[PASS] "; Rank = 0 }
}
$script:FilterRank = $script:SevMap[$SeverityFilter].Rank
if ($null -eq $script:FilterRank) { $script:FilterRank = 0 }

function script:SevConf { param([string]$s)
    $k = if ($script:SevMap.ContainsKey($s)) { $s } else { "Info" }
    return $script:SevMap[$k]
}
function script:PassesFilter { param([string]$s)
    return (SevConf $s).Rank -ge $script:FilterRank
}

$script:Keywords = @(
    'SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege',
    'SeBackupPrivilege','SeRestorePrivilege','SeDebugPrivilege',
    'SeTakeOwnershipPrivilege','SeLoadDriverPrivilege','SeRelabelPrivilege',
    'SeCreateTokenPrivilege','AlwaysInstallElevated','Unquoted','AutoRun',
    'Autologon','DefaultPassword','CachedLogonPassword',
    'password','passwd','cleartext','plaintext','NTLM','SAM','LSA',
    'credential','token','secret',
    'NT AUTHORITY\SYSTEM','BUILTIN\Administrators','Everyone','BUILTIN\Users',
    'C:\Windows\System32','C:\Windows\SysWOW64','C:\Program Files\'
)
function script:HL { param([string]$Text)
    if (-not $script:ColorEnabled) { return $Text }
    foreach ($kw in $script:Keywords) {
        $re = [regex]::Escape($kw)
        if ($Text -match "(?i)$re") {
            $Text = $Text -replace "(?i)($re)",
                "$($script:Ansi.Magenta)$($script:Ansi.Bold)`$1$($script:Ansi.Reset)"
        }
    }
    return $Text
}

$script:AllResults   = @()
$script:DIV          = "-" * 70
$script:DIV2         = "=" * 70

function script:RenderObj { param($Obj, [string]$Color)
    if ($null -eq $Obj) { return }
    if ($Obj -is [System.Management.Automation.PSObject] -or $Obj -is [hashtable]) {
        $keys = if ($Obj -is [hashtable]) { $Obj.Keys } else { $Obj.PSObject.Properties.Name }
        foreach ($k in $keys) {
            $v = "$($Obj.$k)"
            if ($v -eq "" -or $null -eq $v) { continue }
            $kp  = cc ("  " + $k.PadRight(28)) "Gray"
            $vp  = HL $v
            $hot = ($v -match 'SeImpersonate|SeAssignPrimary|SeTcb|AlwaysInstallElevated|cleartext|Everyone|NT AUTHORITY.SYSTEM')
            $vp  = if ($hot) { cc $vp "Red" -B } else { cc $vp $Color }
            Write-Host "$kp  $vp"
        }
    } else {
        Write-Host (cc ("  " + (HL "$Obj")) $Color)
    }
}

# ===========================================================================
# INTERCEPT LAYER
# Write-Banner and Write-CheckBanner/Write-CheckResult are the output
# hooks PrivescCheck calls. We redefine them in GLOBAL scope here so that
# when the engine runs, our colored versions take over.
# ===========================================================================

# Intercept the original Write-Banner (ASCII box drawn by PrivescCheck)
# We re-implement it with color so each section header pops visually.
function global:Write-Banner {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Type,
        [string]$Note
    )

    $col = switch ($Type) {
        "Vuln" { "Red" }
        "Conf" { "Yellow" }
        default { "Cyan" }
    }
    $typeLabel = switch ($Type) {
        "Vuln" { "[VULN]" }
        "Conf" { "[CONF]" }
        default { "[INFO]" }
    }

    Write-Host ""
    Write-Host (cc $script:DIV2 $col -B)
    Write-Host (cc "  $typeLabel  $($Category.ToUpper()) > $Name" $col -B)
    if ($Note) { Write-Host (cc "  $Note" "Gray") }
    Write-Host (cc $script:DIV2 $col)
    Write-Host ""
}

# ===========================================================================
# RESULT ACCUMULATOR + COLORIZED FORMATTER
# Captures every "[+]", "[*]", "[!]" line written to host and re-emits
# it with severity-appropriate color. Also tracks counts for the summary.
# ===========================================================================

# We intercept by overriding Write-Host via a proxy. But PrivescCheck
# writes plain strings directly to the pipeline and via Write-Host.
# The cleanest intercept: capture pipeline output in Invoke-PrivescCheckColor
# and re-render each line. See the runner function below.

function script:ColorLine { param([string]$Line)
    $stripped = $Line.Trim()

    # Section banners are already handled by Write-Banner above
    # Classify output lines

    # Vulnerability hits (+ Found)
    if ($stripped -match '^\[\+\]') {
        $script:AllResults += @{ Sev = "High"; Line = $stripped }
        if (PassesFilter "High") {
            Write-Host (cc (HL $Line) "Red")
        }
        return
    }

    # Info hits (* Found)
    if ($stripped -match '^\[\*\]') {
        $script:AllResults += @{ Sev = "Info"; Line = $stripped }
        if (PassesFilter "Info") {
            Write-Host (cc (HL $Line) "Cyan")
        }
        return
    }

    # Nothing found
    if ($stripped -match '^\[!\]') {
        if (PassesFilter "None") {
            Write-Host (cc $Line "Green")
        }
        return
    }

    # Table/list data lines — apply keyword highlight + dim color
    if ($stripped -ne "" -and $stripped -ne "`r`n") {
        if (PassesFilter "Info") {
            Write-Host (HL $Line)
        }
        return
    }

    # Blank lines — pass through when not filtering
    if (PassesFilter "None") {
        Write-Host $Line
    }
}

# ===========================================================================
# SUMMARY
# ===========================================================================
function script:Write-Summary {
    $highs = ($script:AllResults | Where-Object { $_.Sev -eq "High" }).Count
    $infos = ($script:AllResults | Where-Object { $_.Sev -eq "Info" }).Count

    Write-Host ""
    Write-Host (cc $script:DIV2 "White" -B)
    Write-Host (cc "  SCAN COMPLETE — SUMMARY" "White" -B)
    Write-Host (cc $script:DIV2 "White" -B)
    Write-Host ""

    $line = @(
        (cc ("Actionable [+]: " + $highs) "Red" -B),
        (cc ("  Info [*]: " + $infos) "Cyan"),
        (cc "  Total: $($script:AllResults.Count)" "White")
    ) -join "   "
    Write-Host "  $line"
    Write-Host ""

    if ($highs -gt 0) {
        Write-Host (cc "  Actionable findings:" "Red" -B)
        Write-Host (cc ("  " + "-" * 58) "Gray")
        $script:AllResults | Where-Object { $_.Sev -eq "High" } | ForEach-Object {
            Write-Host (cc "  [+] " "Red" -B) -NoNewline
            Write-Host (HL $_.Line.TrimStart('[','+',']',' '))
        }
    } else {
        Write-Host (cc "  No actionable [+] findings." "Green")
    }

    Write-Host ""
    Write-Host (cc $script:DIV2 "Gray")
    Write-Host (cc "  Engine: PrivescCheck by @itm4n — https://github.com/itm4n/PrivescCheck" "DimGray")
    Write-Host ""
}

# ===========================================================================
# HEADER BANNER
# ===========================================================================
function script:Write-Header {
    if ($NoLogo) { return }
    Write-Host ""
    Write-Host (cc $script:DIV2 "Red" -B)
    Write-Host (cc "  PrivescCheck :: Color Edition  [STANDALONE / OFFLINE]" "White" -B)
    Write-Host (cc $script:DIV2 "Red" -B)
    Write-Host ""
    Write-Host (cc "  Engine  : PrivescCheck by @itm4n  (BSD 3-Clause)" "Gray")
    Write-Host (cc "  Source  : https://github.com/itm4n/PrivescCheck"  "Gray")
    Write-Host ""
    Write-Host (cc "  Legend:" "White")
    Write-Host "  $(cc '[+] finding' 'Red' -B)   Actionable — high/medium severity"
    Write-Host "  $(cc '[*] info'    'Cyan')   Enumeration data"
    Write-Host "  $(cc '[!] nothing' 'Green')   Check passed — nothing found"
    Write-Host "  $(cc 'keyword'     'Magenta')     Sensitive string highlighted inline"
    Write-Host ""
    if ($SeverityFilter -ne "None") {
        Write-Host (cc "  [!] Filter active — showing [$SeverityFilter] and above only" "Yellow" -B)
        Write-Host ""
    }
    Write-Host (cc $script:DIV2 "Gray")
    Write-Host ""
}


# ===========================================================================
# PRIVESCCHECK ENGINE (embedded verbatim)
# Original: https://github.com/itm4n/PrivescCheck  |  BSD 3-Clause  |  @itm4n
# This copy sourced from: https://github.com/JoelGMSec/AutoRDPwn (mirror)
# ===========================================================================


# ----------------------------------------------------------------
# Win32 stuff  
# ----------------------------------------------------------------
#region Win32
$CSharpSource = @'
private const Int32 ANYSIZE_ARRAY = 1;

[System.FlagsAttribute]
public enum ServiceAccessFlags : uint
{
    QueryConfig = 1,
    ChangeConfig = 2,
    QueryStatus = 4,
    EnumerateDependents = 8,
    Start = 16,
    Stop = 32,
    PauseContinue = 64,
    Interrogate = 128,
    UserDefinedControl = 256,
    Delete = 65536,
    ReadControl = 131072,
    WriteDac = 262144,
    WriteOwner = 524288,
    Synchronize = 1048576,
    AccessSystemSecurity = 16777216,
    GenericAll = 268435456,
    GenericExecute = 536870912,
    GenericWrite = 1073741824,
    GenericRead = 2147483648
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID {
   public UInt32 LowPart;
   public Int32 HighPart;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID_AND_ATTRIBUTES {
    public IntPtr Sid;
    public int Attributes;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct LUID_AND_ATTRIBUTES {
   public LUID Luid;
   public UInt32 Attributes;
}

public struct TOKEN_USER {
    public SID_AND_ATTRIBUTES User;
}

public struct TOKEN_PRIVILEGES {
    public int PrivilegeCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
    public LUID_AND_ATTRIBUTES [] Privileges;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPROW_OWNER_PID
{
    public uint state;
    public uint localAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint remoteAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] remotePort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDPROW_OWNER_PID
{
    public uint localAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCP6ROW_OWNER_PID
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] localAddr;
    public uint localScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] remoteAddr;
    public uint remoteScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] remotePort;
    public uint state;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDP6ROW_OWNER_PID
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] localAddr;
    public uint localScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPTABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_TCPROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDPTABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_UDPROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCP6TABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_TCP6ROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDP6TABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_UDP6ROW_OWNER_PID[] table;

}

[StructLayout(LayoutKind.Sequential)]
public struct FILETIME
{
    public uint dwLowDateTime;
    public uint dwHighDateTime;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CREDENTIAL
{
    public uint Flags;
    public uint Type;
    public string TargetName;
    public string Comment;
    public FILETIME LastWritten;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
   public ushort Length;
   public ushort MaximumLength;
   public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct VAULT_ITEM_7
{
    public Guid SchemaId;
    public string FriendlyName;
    public IntPtr Resource;
    public IntPtr Identity;
    public IntPtr Authenticator;
    public UInt64 LastWritten;
    public UInt32 Flags;
    public UInt32 PropertiesCount;
    public IntPtr Properties;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct VAULT_ITEM_8
{
    public Guid SchemaId;
    public string FriendlyName;
    public IntPtr Resource;
    public IntPtr Identity;
    public IntPtr Authenticator;
    public IntPtr PackageSid;
    public UInt64 LastWritten;
    public UInt32 Flags;
    public UInt32 PropertiesCount;
    public IntPtr Properties;
}

[StructLayout(LayoutKind.Sequential)]
public struct VAULT_ITEM_DATA_HEADER
{
    public UInt32 SchemaElementId;
    public UInt32 Unknown1;
    public UInt32 Type;
    public UInt32 Unknown2;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_INTERFACE_INFO
{
    public Guid InterfaceGuid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strInterfaceDescription;
    public uint isState; // WLAN_INTERFACE_STATE
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_PROFILE_INFO
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public uint dwFlags;
}

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool QueryServiceObjectSecurity(IntPtr serviceHandle, System.Security.AccessControl.SecurityInfos secInfo, byte[] lpSecDesrBuf, uint bufSize, out uint bufSizeNeeded);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CloseServiceHandle(IntPtr hSCObject);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetTokenInformation(IntPtr TokenHandle, UInt32 TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid, System.Text.StringBuilder lpName, ref uint cchName, System.Text.StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out int peUse);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName );

[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CredEnumerate(IntPtr Filter, UInt32 Flags, out UInt32 Count, out IntPtr Credentials);

[DllImport("advapi32.dll")]
public static extern void CredFree(IntPtr Buffer);

[DllImport("advapi32.dll", SetLastError=false)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsTextUnicode(IntPtr buf, UInt32 len, ref UInt32 opt);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetCurrentProcess();

[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CloseHandle(IntPtr hObject);

[DllImport("kernel32.dll")]
public static extern UInt64 GetTickCount64();

[DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern uint GetFirmwareEnvironmentVariable(string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetFirmwareType(ref uint FirmwareType);

[DllImport("iphlpapi.dll", SetLastError=true)]
public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, uint TableClass, uint Reserved);

[DllImport("iphlpapi.dll", SetLastError=true)]
public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, uint TableClass, uint Reserved);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultEnumerateVaults(uint dwFlags, out int VaultsCount, out IntPtr ppVaultGuids);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultOpenVault(IntPtr pVaultId, uint dwFlags, out IntPtr pVaultHandle);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultEnumerateItems(IntPtr pVaultHandle, uint dwFlags, out int ItemsCount, out IntPtr ppItems);

[DllImport("vaultcli.dll", SetLastError=false, EntryPoint="VaultGetItem")]
public static extern uint VaultGetItem7(IntPtr pVaultHandle, ref Guid guidSchemaId, IntPtr pResource, IntPtr pIdentity, IntPtr pUnknown, uint iUnknown, out IntPtr pItem);

[DllImport("vaultcli.dll", SetLastError=false, EntryPoint="VaultGetItem")]
public static extern uint VaultGetItem8(IntPtr pVaultHandle, ref Guid guidSchemaId, IntPtr pResource, IntPtr pIdentity, IntPtr pPackageSid, IntPtr pUnknown, uint iUnknown, out IntPtr pItem);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultFree(IntPtr pVaultItem);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultCloseVault(ref IntPtr pVaultHandle);

[DllImport("Wlanapi.dll")]
public static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr hClientHandle);

[DllImport("Wlanapi.dll")]
public static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

[DllImport("Wlanapi.dll")]
public static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, ref IntPtr ppInterfaceList);

[DllImport("Wlanapi.dll")]
public static extern void WlanFreeMemory(IntPtr pMemory);

[DllImport("Wlanapi.dll")]
public static extern uint WlanGetProfileList(IntPtr hClientHandle, [MarshalAs(UnmanagedType.LPStruct)]Guid interfaceGuid, IntPtr pReserved, out IntPtr ppProfileList);

[DllImport("Wlanapi.dll")]
public static extern uint WlanGetProfile(IntPtr clientHandle, [MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [MarshalAs(UnmanagedType.LPWStr)] string profileName, IntPtr pReserved, [MarshalAs(UnmanagedType.LPWStr)] out string profileXml, ref uint flags, out uint pdwGrantedAccess);
'@

try {
    # Is the Type already defined?
    [PrivescCheck.Win32] | Out-Null 
} catch {
    # If not, create it by compiling the C# code in memory 
    $CompilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
    $CompilerParameters.GenerateInMemory = $True
    $CompilerParameters.GenerateExecutable = $False 
    #$Compiler = New-Object -TypeName Microsoft.CSharp.CSharpCodeProvider
    #$Compiler.CompileAssemblyFromSource($CompilerParameters, $CSharpSource) 
    Add-Type -MemberDefinition $CSharpSource -Name 'Win32' -Namespace 'PrivescCheck' -Language CSharp -CompilerParameters $CompilerParameters
}
#endregion Win32


# ----------------------------------------------------------------
# Helpers 
# ----------------------------------------------------------------
#region Helpers 
$global:IgnoredPrograms = @("Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies")

$global:IgnoredServices = @("1394ohci", "3ware", "AarSvc", "ACPI", "AcpiDev", "acpiex", "acpipagr", "AcpiPmi", "acpitime", "Acx01000", "ADOVMPPackage", "ADP80XX", "adsi", "ADWS", "AeLookupSvc", "AFD", "afunix", "ahcache", "AJRouter", "ALG", "AllUserInstallAgent", "amdgpio2", "amdi2c", "AmdK8", "AmdPPM", "amdsata", "amdsbs", "amdxata", "AppID", "AppIDSvc", "Appinfo", "applockerfltr", "AppMgmt", "AppReadiness", "AppHostSvc", "AppVClient", "AppvStrm", "AppvVemgr", "AppvVfs", "AppXSvc", "arcsas", "aspnet_state", "AssignedAccessManagerSvc", "AsyncMac", "atapi", "AudioEndpointBuilder", "Audiosrv", "autotimesvc", "AxInstSV", "b06bdrv", "bam", "BasicDisplay", "BasicRender", "BattC", "BcastDVRUserService", "bcmfn2", "BDESVC", "Beep", "BFE", "bindflt", "BITS", "BluetoothUserService", "bowser", "BrokerInfrastructure", "Browser", "BTAGService", "BthA2dp", "BthAvctpSvc", "BthEnum", "BthHFEnum", "BthLEEnum", "BthMini", "BTHMODEM", "BthPan", "BTHPORT", "bthserv", "BTHUSB", "bttflt", "buttonconverter", "CAD", "camsvc", "CaptureService", "cbdhsvc", "cdfs", "CDPSvc", "CDPUserSvc", "cdrom", "CertPropSvc", "cht4iscsi", "cht4vbd", "CimFS", "circlass", "CldFlt", "CLFS", "ClipSVC", "CmBatt", "CNG", "cnghwassist", "CompositeBus", "COMSysApp", "condrv", "ConsentUxUserSvc", "CoreMessagingRegistrar", "CoreUI", "CredentialEnrollmentManagerUserSvc", "crypt32", "CryptSvc", "CSC", "CscService", "dam", "DCLocator", "DcomLaunch", "defragsvc", "DeviceAssociationBrokerSvc", "DeviceAssociationService", "DeviceInstall", "DevicePickerUserSvc", "DevicesFlowUserSvc", "DevQueryBroker", "Dfs", "Dfsc", "DFSR", "Dhcp", "diagnosticshub.standardcollector.service", "diagsvc", "DiagTrack", "disk", "DispBrokerDesktopSvc", "DisplayEnhancementService", "DmEnrollmentSvc", "dmvsc", "dmwappushservice", "DNS", "Dnscache", "DoSvc", "dot3svc", "DPS", "drmkaud", "DsmSvc", "DsRoleSvc", "DsSvc", "DusmSvc", "DXGKrnl", "e1i65x64", "Eaphost", "ebdrv", "EFS", "ehRecvr", "ehSched", "EhStorClass", "EhStorTcgDrv", "embeddedmode", "EntAppSvc", "ErrDev", "ESENT", "EventLog", "EventSystem", "exfat", "fastfat", "Fax", "fdc", "fdPHost", "FDResPub", "fhsvc", "FileCrypt", "FileInfo", "Filetrace", "flpydisk", "FltMgr", "FontCache", "FrameServer", "FsDepends", "Fs_Rec", "fvevol", "gencounter", "genericusbfn", "GPIOClx0101", "gpsvc", "GpuEnergyDrv", "GraphicsPerfSvc", "HdAudAddService", "HDAudBus", "HidBatt", "HidBth", "hidi2c", "hidinterrupt", "HidIr", "hidserv", "hidspi", "HidUsb", "hkmsvc", "HomeGroupListener", "HomeGroupProvider", "HpSAMD", "HTTP", "hvcrash", "HvHost", "hvservice", "HwNClx0101", "hwpolicy", "hyperkbd", "HyperVideo", "i8042prt", "iagpio", "iai2c", "iaStorAV", "iaStorAVC", "iaStorV", "ibbus", "icssvc", "idsvc", "IEEtwCollectorService", "IKEEXT", "IndirectKmd", "inetaccs", "InstallService", "intelide", "intelpep", "intelpmax", "intelppm", "iorate", "IPBusEnum", "IpFilterDriver", "iphlpsvc", "IPMIDRV", "IPNAT", "IPT", "IpxlatCfgSvc", "isapnp", "iScsiPrt", "IsmServ", "ItSas35i", "kbdclass", "kbdhid", "Kdc", "KdsSvc", "kdnic", "KeyIso", "KPSSVC", "KSecDD", "KSecPkg", "ksthunk", "KtmRm", "LanmanServer", "LanmanWorkstation", "ldap", "lfsvc", "LicenseManager", "lltdio", "lltdsvc", "lmhosts", "Lsa", "LSI_SAS", "LSI_SAS2i", "LSI_SAS3i", "LSI_SSS", "LSM", "luafv", "LxpSvc", "MapsBroker", "mausbhost", "mausbip", "MbbCx", "Mcx2Svc", "megasas", "megasas2i", "megasas35i", "megasr", "MessagingService", "Microsoft_Bluetooth_AvrcpTransport", "MixedRealityOpenXRSvc", "mlx4_bus", "MMCSS", "Modem", "monitor", "mouclass", "mouhid", "mountmgr", "mpsdrv", "mpssvc", "MRxDAV", "mrxsmb", "mrxsmb20", "MsBridge", "Msfs", "msgpiowin32", "mshidkmdf", "mshidumdf", "msisadrv", "MSiSCSI", "msiserver", "MSKSSRV", "MsLldp", "MSPCLOCK", "MSPQM", "MsQuic", "MsRPC", "MSSCNTRS", "MsSecFlt", "mssmbios", "MSTEE", "MTConfig", "Mup", "mvumis", "napagent", "NativeWifiP", "NaturalAuthentication", "NcaSvc", "NcbService", "NcdAutoSetup", "ndfltr", "NDIS", "NdisCap", "NdisImPlatform", "NdisTapi", "Ndisuio", "NdisVirtualBus", "NdisWan", "ndiswanlegacy", "NDKPing", "ndproxy", "Ndu", "NetAdapterCx", "NetBIOS", "NetbiosSmb", "NetBT", "NetMsmqActivator", "NetPipeActivator", "NetTcpActivator", "Netlogon", "Netman", "netprofm", "NetSetupSvc", "NetTcpPortSharing", "netvsc", "NgcCtnrSvc", "NgcSvc", "NlaSvc", "Npfs", "npsvctrig", "nsi", "nsiproxy", "NTDS", "Ntfs", "NtFrs", "Null", "nvdimm", "nvraid", "nvstor", "OneSyncSvc", "p2pimsvc", "p2psvc", "Parport", "partmgr", "PcaSvc", "pci", "pciide", "pcmcia", "pcw", "pdc", "PEAUTH", "PeerDistSvc", "PenService", "perceptionsimulation", "percsas2i", "percsas3i", "PerfDisk", "PerfHost", "PerfNet", "PerfOS", "PerfProc", "PhoneSvc", "PimIndexMaintenanceSvc", "PktMon", "pla", "PlugPlay", "pmem", "PNPMEM", "PNRPAutoReg", "PNRPsvc", "PolicyAgent", "portcfg", "PortProxy", "Power", "PptpMiniport", "PrintNotify", "PrintWorkflowUserSvc", "Processor", "ProfSvc", "ProtectedStorage", "Psched", "PushToInstall", "pvscsi", "QWAVE", "QWAVEdrv", "Ramdisk", "RasAcd", "RasAgileVpn", "RasAuto", "Rasl2tp", "RasMan", "RasPppoe", "RasSstp", "rdbss", "RDMANDK", "rdpbus", "RDPDR", "RDPNP", "RDPUDD", "RdpVideoMiniport", "rdyboost", "ReFS", "ReFSv1", "FCRegSvc", "RemoteAccess", "RemoteRegistry", "RetailDemo", "RFCOMM", "rhproxy", "RmSvc", "RpcEptMapper", "RpcLocator", "RpcSs", "RSoPProv", "rspndr", "s3cap", "sacsvr", "SamSs", "sbp2port", "SCardSvr", "ScDeviceEnum", "scfilter", "Schedule", "scmbus", "SCPolicySvc", "sdbus", "SDFRd", "SDRSVC", "sdstor", "seclogon", "SecurityHealthService", "SEMgrSvc", "SENS", "Sense", "SensorDataService", "SensorService", "SensrSvc", "SerCx", "SerCx2", "Serenum", "Serial", "sermouse", "SessionEnv", "sfloppy", "SgrmAgent", "SgrmBroker", "SharedAccess", "SharedRealitySvc", "ShellHWDetection", "shpamsvc", "SiSRaid2", "SiSRaid4", "SmartSAMD", "smbdirect", "smphost", "SmsRouter", "SMSvcHost 4.0.0.0", "SNMPTRAP", "spaceparser", "spaceport", "SpatialGraphFilter", "SpbCx", "spectrum", "Spooler", "sppsvc", "sppuinotify", "srv2", "srvnet", "SSDPSRV", "ssh-agent", "SstpSvc", "StateRepository", "stexstor", "stisvc", "storahci", "storflt", "stornvme", "storqosflt", "StorSvc", "storufs", "storvsc", "svsvc", "swenum", "swprv", "Synth3dVsc", "SysMain", "SystemEventsBroker", "TabletInputService", "TapiSrv", "Tcpip", "Tcpip6", "TCPIP6TUNNEL", "tcpipreg", "TCPIPTUNNEL", "tdx", "Telemetry", "terminpt", "TermService", "Themes", "TieringEngineService", "TimeBroker", "TimeBrokerSvc", "THREADORDER", "TokenBroker", "TPM", "TrkWks", "TroubleshootingSvc", "TrustedInstaller", "TSDDD", "TsUsbFlt", "TsUsbGD", "tsusbhub", "tunnel", "tzautoupdate", "UALSVC", "UASPStor", "UcmCx0101", "UcmTcpciCx0101", "UcmUcsiAcpiClient", "UcmUcsiCx0101", "Ucx01000", "UdeCx", "udfs", "UdkUserSvc", "UEFI", "UevAgentDriver", "UevAgentService", "Ufx01000", "UfxChipidea", "ufxsynopsys", "UGatherer", "UGTHRSVC", "UI0Detect", "umbus", "UmPass", "UmRdpService", "UnistoreSvc", "upnphost", "UrsChipidea", "UrsCx01000", "UrsSynopsys", "usbaudio", "usbaudio2", "usbccgp", "usbcir", "usbehci", "usbhub", "USBHUB3", "usbohci", "usbprint", "usbser", "USBSTOR", "usbuhci", "USBXHCI", "UserDataSvc", "UserManager", "UsoSvc", "UxSms", "VacSvc", "VaultSvc", "vdrvroot", "vds", "VerifierExt", "VGAuthService", "vhdmp", "vhf", "Vid", "VirtualRender", "vm3dmp", "vm3dmp-debug", "vm3dmp-stats", "vm3dmp_loader", "vmbus", "VMBusHID", "vmci", "vmgid", "vmhgfs", "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvmsession", "vmicvss", "VMMemCtl", "vmmouse", "vmrawdsk", "vmusbmouse", "vmvss", "vmwefifw", "vmxnet3ndis6", "volmgr", "volmgrx", "volsnap", "volume", "vpci", "vsmraid", "vsock", "VSS", "VSTXRAID", "vwifibus", "vwififlt", "W32Time", "w3logsvc", "W3SVC", "WaaSMedicSvc", "WAS", "WacomPen", "WalletService", "wanarp", "wanarpv6", "WarpJITSvc", "WatAdminSvc", "wbengine", "WbioSrvc", "wcifs", "Wcmsvc", "wcncsvc", "wcnfs", "WcsPlugInService", "WdBoot", "Wdf01000", "WdFilter", "WdiServiceHost", "WdiSystemHost", "wdiwifi", "WdmCompanionFilter", "WdNisDrv", "WdNisSvc", "WebClient", "Wecsvc", "WEPHOSTSVC", "wercplsupport", "WerSvc", "WFDSConMgrSvc", "WFPLWFS", "WiaRpc", "WIMMount", "WinDefend", "Windows Workflow Foundation 4.0.0.0", "WindowsTrustedRT", "WindowsTrustedRTProxy", "WinHttpAutoProxySvc", "WinMad", "Winmgmt", "WinNat", "WinRM", "Winsock", "WinSock2", "WINUSB", "WinVerbs", "wisvc", "WlanSvc", "wlidsvc", "WLMS", "wlpasvc", "WManSvc", "WmiAcpi", "WmiApRpl", "wmiApSrv", "WMPNetworkSvc", "Wof", "workerdd", "workfolderssvc", "WpcMonSvc", "WPCSvc", "WPDBusEnum", "WpdUpFltr", "WpnService", "WpnUserService", "ws2ifsl", "wscsvc", "WSearch", "WSearchIdxPi", "WSService", "wuauserv", "WudfPf", "WUDFRd", "wudfsvc", "WwanSvc", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc", "xinputhid", "xmlprov")

function Convert-DateToString {
    
    [CmdletBinding()] param(
        [System.DateTime]
        $Date
    )

    $OutString = ""
    $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
    #$OutString += " ($($Date.ToString('o')))" # ISO format
    $OutString
}

function Convert-ServiceTypeToString {
    
    [CmdletBinding()] param(
        [int]
        $ServiceType
    )

    $ServiceTypeEnum = @{
        "KernelDriver" =        "1";
        "FileSystemDriver" =    "2";
        "Adapter" =             "4";
        "RecognizerDriver" =    "8";
        "Win32OwnProcess" =     "16";
        "Win32ShareProcess" =   "32";
        "InteractiveProcess" =  "256";
    }

    $ServiceTypeEnum.GetEnumerator() | ForEach-Object { 
        if ( $_.value -band $ServiceType ) 
        {
            $_.name
        }
    }
}

function Convert-ServiceStartModeToString {
    
    [CmdletBinding()] param(
        [int]
        $StartMode
    )

    $StartModeEnum = @{
        "Boot" =        "0";
        "System" =      "1";
        "Automatic" =   "2";
        "Manual" =      "3";
        "Disabled" =    "4";
    }

    $StartModeEnum.GetEnumerator() | ForEach-Object { 
        if ( $_.Value -eq $StartMode ) 
        {
            $_.Name
        }
    }
}

function Test-IsKnownService {
    
    [CmdletBinding()] param(
        [string]
        $ServiceName
    )

    $KnownServices = @("AarSvc_*", "BcastDVRUserService_*", "BluetoothUserService_*", "CaptureService_*", "cbdhsvc_*", "CDPUserSvc_*", "clr_optimization_*", "ConsentUxUserSvc_*", "CredentialEnrollmentManagerUserSvc_*", "DeviceAssociationBrokerSvc_*", "DevicePickerUserSvc_*", "DevicesFlowUserSvc_*", "FontCache*", "iaLPSS*", "IpOverUsbSvc", "LxssManager*", "MessagingService_*", "MSDTC*", ".NET*", "OneSyncSvc_*", "PenService_*", "PimIndexMaintenanceSvc_*", "PrintWorkflowUserSvc_*", "UdkUserSvc_*", "UnistoreSvc_*", "UserDataSvc_*", "WpnUserService_*")

    if ($global:IgnoredServices -contains $ServiceName) {
        return $True 
    } else {
        ForEach ($KnownService in $KnownServices) {
            if ($ServiceName -like $KnownService) {
                return $True 
            }
        }
    }
    return $False 
}

function Get-UserPrivileges {
    
    [CmdletBinding()] param()

    function Get-PrivilegeDescription {
        [CmdletBinding()] param(
            [string]
            $Name
        )

        $PrivilegeDescriptions = @{
            "SeAssignPrimaryTokenPrivilege" =               "Replace a process-level token";
            "SeAuditPrivilege" =                            "Generate security audits";
            "SeBackupPrivilege" =                           "Back up files and directories";
            "SeChangeNotifyPrivilege" =                     "Bypass traverse checking";
            "SeCreateGlobalPrivilege" =                     "Create global objects";
            "SeCreatePagefilePrivilege" =                   "Create a pagefile";
            "SeCreatePermanentPrivilege" =                  "Create permanent shared objects";
            "SeCreateSymbolicLinkPrivilege" =               "Create symbolic links";
            "SeCreateTokenPrivilege" =                      "Create a token object";
            "SeDebugPrivilege" =                            "Debug programs";
            "SeDelegateSessionUserImpersonatePrivilege" =   "Impersonate other users";
            "SeEnableDelegationPrivilege" =                 "Enable computer and user accounts to be trusted for delegation";
            "SeImpersonatePrivilege" =                      "Impersonate a client after authentication";
            "SeIncreaseBasePriorityPrivilege" =             "Increase scheduling priority";
            "SeIncreaseQuotaPrivilege" =                    "Adjust memory quotas for a process";
            "SeIncreaseWorkingSetPrivilege" =               "Increase a process working set";
            "SeLoadDriverPrivilege" =                       "Load and unload device drivers";
            "SeLockMemoryPrivilege" =                       "Lock pages in memory";
            "SeMachineAccountPrivilege" =                   "Add workstations to domain";
            "SeManageVolumePrivilege" =                     "Manage the files on a volume";
            "SeProfileSingleProcessPrivilege" =             "Profile single process";
            "SeRelabelPrivilege" =                          "Modify an object label";
            "SeRemoteShutdownPrivilege" =                   "Force shutdown from a remote system";
            "SeRestorePrivilege" =                          "Restore files and directories";
            "SeSecurityPrivilege" =                         "Manage auditing and security log";
            "SeShutdownPrivilege" =                         "Shut down the system";
            "SeSyncAgentPrivilege" =                        "Synchronize directory service data";
            "SeSystemEnvironmentPrivilege" =                "Modify firmware environment values";
            "SeSystemProfilePrivilege" =                    "Profile system performance";
            "SeSystemtimePrivilege" =                       "Change the system time";
            "SeTakeOwnershipPrivilege" =                    "Take ownership of files or other objects";
            "SeTcbPrivilege" =                              "Act as part of the operating system";
            "SeTimeZonePrivilege" =                         "Change the time zone";
            "SeTrustedCredManAccessPrivilege" =             "Access Credential Manager as a trusted caller";
            "SeUndockPrivilege" =                           "Remove computer from docking station";
            "SeUnsolicitedInputPrivilege" =                 "N/A";
        }

        $PrivilegeDescriptions[$Name]

    }

    # Get a handle to a process the current user owns 
    $ProcessHandle = [PrivescCheck.Win32]::GetCurrentProcess()
    Write-Verbose "Current process handle: $ProcessHandle"

    # Get a handle to the token corresponding to this process 
    $TOKEN_QUERY= 0x0008
    [IntPtr]$TokenHandle = [IntPtr]::Zero
    $Success = [PrivescCheck.Win32]::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$TokenHandle);
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {


        # TOKEN_INFORMATION_CLASS - 3 = TokenPrivileges
        $TokenPrivilegesPtrSize = 0
        $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 3, 0, $Null, [ref]$TokenPrivilegesPtrSize)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if (-not ($TokenPrivilegesPtrSize -eq 0)) {


            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                # Convert the unmanaged memory at offset $TokenPrivilegesPtr to a TOKEN_PRIVILEGES managed type 
                $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] [PrivescCheck.Win32+TOKEN_PRIVILEGES])
                #$Offset = [System.IntPtr]::Add($TokenPrivilegesPtr, 4)
                # Properly Incrementing an IntPtr
                # https://docs.microsoft.com/en-us/archive/blogs/jaredpar/properly-incrementing-an-intptr
                $Offset = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
                

                For ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {

                    # Cast the unmanaged memory at offset 
                    $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+LUID_AND_ATTRIBUTES])
                    
                    # Copy LUID to unmanaged memory 
                    $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes.Luid)
                    [IntPtr]$LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LuidAndAttributes.Luid, $LuidPtr, $True)

                    # public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName );
                    [int]$Length = 0
                    $Success = [PrivescCheck.Win32]::LookupPrivilegeName($Null, $LuidPtr, $Null, [ref]$Length)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not ($Length -eq 0)) {


                        $Name = New-Object -TypeName System.Text.StringBuilder
                        $Name.EnsureCapacity($Length + 1) |Out-Null
                        $Success = [PrivescCheck.Win32]::LookupPrivilegeName($Null, $LuidPtr, $Name, [ref]$Length)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Success) {

                            $PrivilegeName = $Name.ToString()

                            # SE_PRIVILEGE_ENABLED = 0x00000002
                            $PrivilegeEnabled = ($LuidAndAttributes.Attributes -band 2) -eq 2


                            $PrivilegeObject = New-Object -TypeName PSObject 
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PrivilegeName
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($PrivilegeEnabled) { "Enabled" } else { "Disabled" })
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(Get-PrivilegeDescription -Name $PrivilegeName)
                            $PrivilegeObject

                        } else {
                        }

                    } else {
                    }

                    # Cleanup - Free unmanaged memory
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

                    # Update the offset to point to the next LUID_AND_ATTRIBUTES structure in the unmanaged buffer
                    #$Offset = [System.IntPtr]::Add($Offset, [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes))
                    # Properly Incrementing an IntPtr
                    # https://docs.microsoft.com/en-us/archive/blogs/jaredpar/properly-incrementing-an-intptr
                    $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes))
                }

            } else {
            }

            # Cleanup - Free unmanaged memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

        } else {
        }

        # Cleanup - Close Token handle 
        $Success = [PrivescCheck.Win32]::CloseHandle($TokenHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Token handle closed"
        } else {
        }

    } else {
    }
}

function Get-UserFromProcess() {
    
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [int]
        $ProcessId
    )

    function Get-SidTypeName {
        param(
            $SidType
        )

        $SidTypeEnum = @{
            "User" = "1";
            "Group" = "2";
            "Domain" = "3";
            "Alias" = "4";
            "WellKnownGroup" = "5";
            "DeletedAccount" = "6";
            "Invalid" = "7";
            "Unknown" = "8";
            "Computer" = "9";
            "Label" = "10";
            "LogonSession" = "11";
        }

        $SidTypeEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.value -eq $SidType ) 
            {
                $_.name
            }
        }
    }

    # PROCESS_QUERY_INFORMATION = 0x0400
    $AccessFlags = 0x0400
    $ProcessHandle = [PrivescCheck.Win32]::OpenProcess($AccessFlags, $False, $ProcessId)
    #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if (-not ($Null -eq $ProcessHandle)) {


        $TOKEN_QUERY= 0x0008
        [IntPtr]$TokenHandle = [IntPtr]::Zero
        $Success = [PrivescCheck.Win32]::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$TokenHandle);
        #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Success) {


            # TOKEN_INFORMATION_CLASS - 1 = TokenUser
            $TokenUserPtrSize = 0
            $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 1, 0, $Null, [ref]$TokenUserPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if (($TokenUserPtrSize -gt 0) -and ($LastError -eq 122)) {


                [IntPtr]$TokenUserPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenUserPtrSize)

                $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 1, $TokenUserPtr, $TokenUserPtrSize, [ref]$TokenUserPtrSize)
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() 

                if ($Success) {


                    # Cast unmanaged memory to managed TOKEN_USER struct 
                    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] [PrivescCheck.Win32+TOKEN_USER])

                    $SidType = 0

                    $UserNameSize = 256
                    $UserName = New-Object -TypeName System.Text.StringBuilder
                    $UserName.EnsureCapacity(256) | Out-Null

                    $UserDomainSize = 256
                    $UserDomain = New-Object -TypeName System.Text.StringBuilder
                    $UserDomain.EnsureCapacity(256) | Out-Null

                    $Success = [PrivescCheck.Win32]::LookupAccountSid($Null, $TokenUser.User.Sid, $UserName, [ref]$UserNameSize, $UserDomain, [ref]$UserDomainSize, [ref]$SidType)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Success) {

                        $UserObject = New-Object -TypeName PSObject 
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $UserDomain.ToString()
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $UserName.ToString()
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($UserDomain.ToString())\$($UserName.ToString())"
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Get-SidTypeName $SidType)
                        $UserObject
                        
                    } else {
                    }
                } else {
                }

                # Cleanup - Free unmanaged memory 
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
            }

            # Cleanup - Close token handle 
            $Success = [PrivescCheck.Win32]::CloseHandle($TokenHandle)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Write-Verbose "Token handle closed"
            } else {
            }
        } else {
            Write-Verbose "Can't open token for process with PID $ProcessId"
        }

        # Cleanup - Close process handle 
        $Success = [PrivescCheck.Win32]::CloseHandle($ProcessHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Process handle closed"
        } else {
        }
    } else {
        Write-Verbose "Can't open process with PID $ProcessId"
    }
}

function Get-NetworkEndpoints {

    [CmdletBinding()] param(
        [switch]
        $IPv6 = $False, # IPv4 by default 
        [switch]
        $UDP = $False # TCP by default 
    )

    $AF_INET6 = 23
    $AF_INET = 2
    
    if ($IPv6) { 
        $IpVersion = $AF_INET6
    } else {
        $IpVersion = $AF_INET
    }

    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [int]$BufSize = 0
        $Result = [PrivescCheck.Win32]::GetExtendedUdpTable([IntPtr]::Zero, [ref]$BufSize, $True, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [int]$BufSize = 0
        $Result = [PrivescCheck.Win32]::GetExtendedTcpTable([IntPtr]::Zero, [ref]$BufSize, $True, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {


        [IntPtr]$TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = [PrivescCheck.Win32]::GetExtendedUdpTable($TablePtr, [ref]$BufSize, $True, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        } else {
            $Result = [PrivescCheck.Win32]::GetExtendedTcpTable($TablePtr, [ref]$BufSize, $True, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_UDPTABLE_OWNER_PID])
                } elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_UDP6TABLE_OWNER_PID])
                }
            } else {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_TCPTABLE_OWNER_PID])
                } elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_TCP6TABLE_OWNER_PID])
                }
            }
            
            $NumEntries = $Table.dwNumEntries


            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_UDPROW_OWNER_PID])
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr)).IPAddressToString
                    } elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_UDP6ROW_OWNER_PID])
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr, $TableEntry.localScopeId)
                    }
                } else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_TCPROW_OWNER_PID])
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr)).IPAddressToString
                    } elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_TCP6ROW_OWNER_PID])
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr, $TableEntry.localScopeId)
                    }
                }

                $LocalPort = $TableEntry.localPort[0] * 0x100 + $TableEntry.localPort[1]
                $ProcessId = $TableEntry.owningPid

                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                } elseif ($IpVersion -eq $AF_INET6) {
                    $LocalAddress = "[$($LocalAddr)]:$($LocalPort)"
                }

                $ListenerObject = New-Object -TypeName PSObject 
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId).ProcessName
                $ListenerObject

                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }

        } else {
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)

    } else {
    }
}

function Get-InstalledPrograms {
    
    [CmdletBinding()] param(
        [switch]
        $Filtered = $False
    )

    $InstalledProgramsResult = New-Object System.Collections.ArrayList

    $InstalledPrograms = New-Object System.Collections.ArrayList

    $PathProgram32 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)"
    $PathProgram64 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files" 

    $Items = Get-ChildItem -Path $PathProgram32,$PathProgram64 -ErrorAction SilentlyContinue
    if ($Items) {
        [void]$InstalledPrograms.AddRange($Items)
    }
    
    $RegInstalledPrograms = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 
    $RegInstalledPrograms6432 = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    if ($RegInstalledPrograms6432) { $RegInstalledPrograms += $RegInstalledPrograms6432 }
    ForEach ($InstalledProgram in $RegInstalledPrograms) {
        $InstallLocation = [System.Environment]::ExpandEnvironmentVariables($InstalledProgram.GetValue("InstallLocation"))
        if ($InstallLocation) {
            if (Test-Path -Path $InstallLocation -ErrorAction SilentlyContinue) {
                if ($InstallLocation[$InstallLocation.Length - 1] -eq "\") {
                    $InstallLocation = $InstallLocation.SubString(0, $InstallLocation.Length - 1)
                }
                $FileObject = Get-Item -Path $InstallLocation -ErrorAction SilentlyContinue -ErrorVariable GetItemError 
                if ($GetItemError) {
                    continue 
                }
                if ($FileObject -is [System.IO.DirectoryInfo]) {
                    continue
                }
                [void]$InstalledPrograms.Add([object]$FileObject)
            }
        }
    }

    $PathListResult = New-Object System.Collections.ArrayList
    ForEach ($InstalledProgram in $InstalledPrograms) {
        if (-not ($PathListResult -contains $InstalledProgram.FullName)) {
            [void]$InstalledProgramsResult.Add($InstalledProgram)
            [void]$PathListResult.Add($InstalledProgram.FullName)
        }
    }

    if ($Filtered) {
        $InstalledProgramsResultFiltered = New-Object -TypeName System.Collections.ArrayList
        ForEach ($InstalledProgram in $InstalledProgramsResult) {
            if (-Not ($global:IgnoredPrograms -contains $InstalledProgram.Name)) {
                [void]$InstalledProgramsResultFiltered.Add($InstalledProgram)
            }
        }
        $InstalledProgramsResultFiltered
    } else {
        $InstalledProgramsResult
    }
}

function Get-ServiceFromRegistry {

    [CmdletBinding()] param(
        [string]$Name
    )

    $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services" 
    $ServiceRegPath = Join-Path -Path $ServicesRegPath -ChildPath $Name

    $ServiceProperties = Get-ItemProperty -Path "Registry::$ServiceRegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $DisplayName = [System.Environment]::ExpandEnvironmentVariables($ServiceProperties.DisplayName)

        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ServiceProperties.PSChildName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ServiceProperties.ObjectName 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $ServiceProperties.ImagePath 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $(Convert-ServiceStartModeToString -StartMode $ServiceProperties.Start)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Convert-ServiceTypeToString -ServiceType $Properties.Type)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $ServiceProperties.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $ServiceProperties.PSPath
        $ServiceItem
    }
}

function Get-ServiceList {
    
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1,2,3)]
        [int]
        $FilterLevel
    )

    $ServicesRegPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" 
    $RegAllServices = Get-ChildItem -Path $ServicesRegPath

    ForEach ($RegService in $RegAllServices) {

        $Properties = Get-ItemProperty -Path $RegService.PSPath -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
        if ($GetItemPropertyError) {
            # If an error occurred, skip the current item 
            continue 
        } 

        $DisplayName = [System.Environment]::ExpandEnvironmentVariables($Properties.DisplayName)

        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Properties.PSChildName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Properties.ObjectName 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Properties.ImagePath 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $(Convert-ServiceStartModeToString -StartMode $Properties.Start)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Convert-ServiceTypeToString -ServiceType $Properties.Type)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $RegService.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $RegService.PSPath 

        # FilterLevel = 0 - Add the service to the list and go to the next one 
        if ($FilterLevel -eq 0) {
            $ServiceItem
            continue 
        }

        if ($Properties.ImagePath -and (-not ($Properties.ImagePath.trim() -eq ''))) {
            # FilterLevel = 1 - Add the service to the list of its ImagePath is not empty
            if ($FilterLevel -le 1) {
                $ServiceItem
                continue 
            }

            if ($Properties.Type -gt 8) {
                # FilterLevel = 2 - Add the service to the list if it's not a driver 
                if ($FilterLevel -le 2) {
                    $ServiceItem
                    continue
                }

                if (-not (Test-IsKnownService -ServiceName $Properties.PSChildName)) {
                    # FilterLevel = 3 - Add the service if it's not a built-in Windows service 
                    if ($FilterLevel -le 3) {
                        $ServiceItem
                        continue
                    }
                }
            }
        } 
    }
}

function Get-ModifiablePath {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Switch]
        $LiteralPaths
    )

    BEGIN {
        # # false positives ?
        # $Excludes = @("MsMpEng.exe", "NisSrv.exe")

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if($PSBoundParameters['LiteralPaths']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    try {
                        $ParentPath = Split-Path $TempPath -Parent
                        if($ParentPath -and (Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                        }
                    }
                    catch {
                        # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if(($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            # if the path is actually an option like '/svc', skip it 
                            # it will prevent a lot of false positives but it might also skip vulnerable paths in some particular cases 
                            # though, it's more common to see options like '/svc' than file paths like '/ProgramData/something' in Windows 
                            if (-not ($TempPath -Like "/*")) { 

                                if($TempPath -and ($TempPath -ne '')) {
                                    if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                        # if the path exists, resolve it and add it to the candidate list
                                        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                    }
                                    else {
                                        # if the path doesn't exist, check if the parent folder allows for modification
                                        try {
                                            $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                            if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                                                $CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
                                            }
                                        }
                                        catch {
                                            # trap because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {

                $CandidatePath = $_

                try {
                
                    Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                        $FileSystemRights = $_.FileSystemRights.value__

                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }

                        # the set of permission types that allow for modification
                        $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                        if($Comparison) {
                            if ($_.IdentityReference -notmatch '^S-1-5.*' -and $_.IdentityReference -notmatch '^S-1-15-.*') {
                                if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                    # translate the IdentityReference if it's a username and not a SID
                                    $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                    $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                }
                                $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                            }
                            else {
                                $IdentitySID = $_.IdentityReference
                            }

                            if($CurrentUserSids -contains $IdentitySID) {
                                New-Object -TypeName PSObject -Property @{
                                    ModifiablePath = $CandidatePath
                                    IdentityReference = $_.IdentityReference
                                    Permissions = $Permissions
                                }
                            }
                        }
                    }
                } catch {
                    # trap because Get-Acl doesn't handle -ErrorAction SilentlyContinue nicely
                }
            }
        }
    }
}

function Get-ModifiableRegistryPath {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [String[]]
        $Path
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {
        $KeyAcl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
        if (-not $GetAclError) {
            $KeyAcl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                $RegistryRights = $_.RegistryRights.value__

                $Permissions = $AccessMask.Keys | Where-Object { $RegistryRights -band $_ } | ForEach-Object { $accessMask[$_] }

                # the set of permission types that allow for modification
                $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                if($Comparison) {
                    if ($_.IdentityReference -notmatch '^S-1-5.*') {
                        if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                            # translate the IdentityReference if it's a username and not a SID
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                            $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                    }
                    else {
                        $IdentitySID = $_.IdentityReference
                    }

                    if($CurrentUserSids -contains $IdentitySID) {
                        New-Object -TypeName PSObject -Property @{
                            ModifiablePath = $Path
                            IdentityReference = $_.IdentityReference
                            Permissions = $Permissions
                        }
                    }
                }
            }
        }
    } 
}

function Add-ServiceDacl {

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )
            Add-Type -AssemblyName System.ServiceProcess # ServiceProcess is not loaded by default  
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -ErrorVariable GetServiceError
            if (-not $GetServiceError) {

                try {
                    $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
                }
                catch {
                    $ServiceHandle = $Null
                }

                if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                    $SizeNeeded = 0

                    $Result = [PrivescCheck.Win32]::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    # 122 == The data area passed to a system call is too small
                    if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                        $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                        $Result = [PrivescCheck.Win32]::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result) {
                            
                            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0

                            $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                                Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value $([PrivescCheck.Win32+ServiceAccessFlags] $_.AccessMask) -PassThru
                            }

                            Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                        }
                    }

                    $Null = [PrivescCheck.Win32]::CloseServiceHandle($ServiceHandle)
                }
            }
        }
    }
}

function Get-UEFIStatus {

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [int]$FirmwareType = 0
        $Result = [PrivescCheck.Win32]::GetFirmwareType([ref]$FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                # FirmwareTypeBios = 1
                $Status = $False 
                $Description = "BIOS mode is Legacy"
            } elseif ($FirmwareType -eq 2) {
                # FirmwareTypeUefi = 2
                $Status = $True 
                $Description = "BIOS mode is UEFI"
            } else {
                $Description = "BIOS mode is unknown"
            }
        } else {
        }

    # Windows = 7/2008 R2
    } elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        [PrivescCheck.Win32]::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0) | Out-Null 
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        $ERROR_INVALID_FUNCTION = 1
        if ($LastError -eq $ERROR_INVALID_FUNCTION) {
            $Status = $False 
            $Description = "BIOS mode is Legacy"
        } else {
            $Status = $True 
            $Description = "BIOS mode is UEFI"
        }
        
    } else {
        $Description = "Cannot check BIOS mode"
    }

    $BiosMode = New-Object -TypeName PSObject
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "UEFI"
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $BiosMode
}

function Get-SecureBootStatus {
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 

    if (-not $GetItemPropertyError) {

        if (-not ($Null -eq $Result.UEFISecureBootEnabled)) {

            if ($Result.UEFISecureBootEnabled -eq 1) {
                $Status = $True
                $Description = "Secure Boot is enabled"
            } else {
                $Status = $False
                $Description = "Secure Boot is disabled"
            }
        } else {
            $Status = $False
            $Description = "Secure Boot is not supported"
        }
    } else {
        $Status = $False
        $Description = "Secure Boot is not supported"
    }

    $SecureBootStatus = New-Object -TypeName PSObject
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $SecureBootStatus
}

function Get-CredentialGuardStatus {
    
    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -ge 10) {

        $RegPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA"
        $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    
        if (-not $GetItemPropertyError) {
    
            if (-not ($Null -eq $Result.LsaCfgFlags)) {
    
                if ($Result.LsaCfgFlags -eq 0) {
                    $Status = $False 
                    $Description = "Credential Guard is disabled"
                } elseif ($Result.LsaCfgFlags -eq 1) {
                    $Status = $True 
                    $Description = "Credential Guard is enabled with UEFI lock"
                } elseif ($Result.LsaCfgFlags -eq 2) {
                    $Status = $True
                    $Description = "Credential Guard is enabled without UEFI lock"
                } 
            } else {
                $Status = $False 
                $Description = "Credential Guard is not configured"
            }
        }
    } else {
        $Status = $False
        $Description = "Credential Guard is not supported on this OS"
    }

    $CredentialGuardStatus = New-Object -TypeName PSObject
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Credential Guard"
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $CredentialGuardStatus
}

function Get-LsaRunAsPPLStatus {
    

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # if Windows >= 8.1 / 2012 R2
    if ($OsVersion.Major -eq 10 -or ( ($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3) )) {

        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        $Result = Get-ItemProperty -Path "REgistry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError

        if (-not $GetItemPropertyError) {

            if (-not ($Null -eq $Result.RunAsPPL)) {

                if ($Result.RunAsPPL -eq 1) {
                    $Status = $True 
                    $Description = "RunAsPPL is enabled"
                } else {
                    $Status = $False 
                    $Description = "RunAsPPL is disabled"
                } 
            } else {
                $Status = $False 
                $Description = "RunAsPPL is not configured"
            }
        }

    } else {
        # RunAsPPL not supported 
        $Status = $False 
        $Description = "RunAsPPL is not supported on this OS"
    }

    $LsaRunAsPplStatus = New-Object -TypeName PSObject
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "RunAsPPL"
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $LsaRunAsPplStatus

}

function Get-UnattendSensitiveData {

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$True)]
        [string]$Path
    )

    function Get-DecodedPassword {

        [CmdletBinding()]Param(
            [object]$XmlNode
        )

        if ($XmlNode.GetType().Name -eq "string") {
            $XmlNode
        } else {
            if ($XmlNode) {
                if ($XmlNode.PlainText -eq "false") {
                    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($XmlNode.Value))
                } else {
                    $XmlNode.Value
                }
            }
        }
    }

    [xml] $Xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError

    if (-not $GetContentError) {

        $Xml.GetElementsByTagName("Credentials") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    
        $Xml.GetElementsByTagName("LocalAccount") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password
    
            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    
        $Xml.GetElementsByTagName("AutoLogon") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }

        $Xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    }
}
#endregion Helpers 


# ----------------------------------------------------------------
# Checks  
# ----------------------------------------------------------------
#region Checks 

# ----------------------------------------------------------------
# BEGIN REGISTRY SETTINGS   
# ----------------------------------------------------------------
function Invoke-UacCheck {
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {
        $UacResult = New-Object -TypeName PSObject
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "EnableLUA" -Value $Item.EnableLUA
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.EnableLUA -eq 1)
        $UacResult
    } else {
        Write-Verbose -Message "Error while querying '$RegPath'"
    }
}

function Invoke-LapsCheck {
    
    [CmdletBinding()]Param()
    
    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        $LapsResult = New-Object -TypeName PSObject 
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "AdmPwdEnabled" -Value $Item.AdmPwdEnabled
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.AdmPwdEnabled -eq 1)
        $LapsResult
    }
}

function Invoke-PowershellTranscriptionCheck {
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        # PowerShell Transcription is configured 
        $PowershellTranscriptionResult = New-Object -TypeName PSObject 
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $Item.EnableTranscripting
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $Item.EnableInvocationHeader
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $Item.OutputDirectory
        $PowershellTranscriptionResult
    } 
}

function Invoke-RegistryAlwaysInstallElevatedCheck {
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer"

    if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {

        $HKLMval = Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $RegistryAlwaysInstallElevatedItem = New-Object -TypeName PSObject 
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "AlwaysInstallElevated" -Value $HKLMval.AlwaysInstallElevated 
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $True
            $RegistryAlwaysInstallElevatedItem
        } 
    } 

    $RegPath = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer"

    if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {
        $HKCUval = (Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
            $RegistryAlwaysInstallElevatedItem = New-Object -TypeName PSObject
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "AlwaysInstallElevated" -Value $HKLMval.AlwaysInstallElevated 
            $RegistryAlwaysInstallElevatedItem | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $True
            $RegistryAlwaysInstallElevatedItem
        }
    }   
}

function Invoke-LsaProtectionsCheck {
    
    [CmdletBinding()]Param()

    Get-LsaRunAsPPLStatus
    Get-UEFIStatus
    Get-SecureBootStatus
    Get-CredentialGuardStatus

}

function Invoke-WsusConfigCheck {

    $WindowsUpdateRegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAURegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

    $WsusKeyServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateRegPath)" -Name WUServer -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
    if (-not $ErrorGetItemProperty) {

        $WusUrl = $WsusKeyServerValue.WUServer

        $UseWUServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateAURegPath)" -Name UseWUServer -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
        if (-not $ErrorGetItemProperty) {

            $WusEnabled = $UseWUServerValue.UseWUServer
            
            if ($WusUrl -Like "http://*" -and $WusEnabled -eq 1) {
                $IsVulnerable = $True
            } else {
                $IsVulnerable = $False
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "WUServer" -Value $WusUrl
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWUServer" -Value $WusEnabled
            $Result | Add-Member -MemberType "NoteProperty" -Name "IsVulnerable" -Value $IsVulnerable
            $Result
        }        
    }
}
# ----------------------------------------------------------------
# END REGISTRY SETTINGS   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN NETWORK 
# ----------------------------------------------------------------
function Get-RpcRange {

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$True)]
        [int[]]
        $Ports
    )

    function Get-Stats {
        [CmdletBinding()]Param(
            [int[]]$Ports,
            [int]$MinPort,
            [int]$MaxPort,
            [int]$Span
        )

        $Stats = @() 
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            ForEach ($Port in $Ports) {
                if (($Port -ge $i) -and ($Port -lt ($i + $Span))) {
                    $Counter += 1
                }
            }
            $RangeStats = New-Object -TypeName PSObject 
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $i
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value ($i + $Span)
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "PortsInRange" -Value $Counter
            $Stats += $RangeStats 
        }
        $Stats
    }

    # We split the range 49152-65536 into blocks of size 32 and then, we take the block which has 
    # greater number of ports in it. 
    $Stats = Get-Stats -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32

    $MaxStat = $Null
    ForEach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    } 

    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = Get-Stats -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            } elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            } else {
                break 
            }
        }
    }

    $RpcRange = New-Object -TypeName PSObject 
    $RpcRange | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $RpcRange | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $RpcRange
}

function Invoke-TcpEndpointsCheck {

    [CmdletBinding()]Param(
        [switch]$Filtered
    )

    $IgnoredPorts = @(135, 139, 445)

    $Endpoints = Get-NetworkEndpoints
    $Endpoints += Get-NetworkEndpoints -IPv6

    if ($Filtered) {
        $FilteredEndpoints = @()
        $AllPorts = @()
        $Endpoints | ForEach-Object { $AllPorts += $_.LocalPort }
        $AllPorts = $AllPorts | Sort-Object -Unique
        
        $RpcRange = Get-RpcRange -Ports $AllPorts
        Write-Verbose "Excluding port range: $($RpcRange.MinPort)-$($RpcRange.MaxPort)"
    
        $Endpoints | ForEach-Object {

            if (-not ($IgnoredPorts -contains $_.LocalPort)) {

                if ($RpcRange) {

                    if (($_.LocalPort -lt $RpcRange.MinPort) -or ($_.LocalPort -ge $RpcRange.MaxPort)) {
                        
                        $FilteredEndpoints += $_
                    }
                }
            }
        }
        $Endpoints = $FilteredEndpoints
    } 

    $Endpoints | ForEach-Object {
        $TcpEndpoint = New-Object -TypeName PSObject
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
        $TcpEndpoint
    }
}

function Invoke-UdpEndpointsCheck {
    
    [CmdletBinding()]Param(
        [switch]$Filtered
    )

    # https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows
    $IgnoredPorts = @(53, 67, 123, 137, 138, 139, 500, 1701, 2535, 4500, 445, 1900, 5050, 5353, 5355)
    
    $Endpoints = Get-NetworkEndpoints -UDP 
    $Endpoints += Get-NetworkEndpoints -UDP -IPv6

    if ($Filtered) {
        $FilteredEndpoints = @()
        $Endpoints | ForEach-Object {
            if (-not ($IgnoredPorts -contains $_.LocalPort)) {
                $FilteredEndpoints += $_
            }
        }
        $Endpoints = $FilteredEndpoints
    }

    $Endpoints | ForEach-Object {
        if (-not ($_.Name -eq "dns")) {
            $UdpEndpoint = New-Object -TypeName PSObject 
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
            $UdpEndpoint
        }
    }
}

function Invoke-WlanProfilesCheck {

    [CmdletBinding()] param()

    function Convert-ProfileXmlToObject {

        [CmdletBinding()] param(
            [string]$ProfileXml
        )

        $Xml = [xml] $ProfileXml

        $Name = $Xml.WLANProfile.name
        $Ssid = $Xml.WLANProfile.SSIDConfig.SSID.name 
        $Authentication = $Xml.WLANProfile.MSM.security.authEncryption.authentication
        $PassPhrase = $Xml.WLANProfile.MSM.security.sharedKey.keyMaterial

        $Profile = New-Object -TypeName PSObject
        $Profile | Add-Member -MemberType "NoteProperty" -Name "Profile" -Value $Name
        $Profile | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $Ssid
        $Profile | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $Authentication
        $Profile | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $PassPhrase
        $Profile
    }

    $ERROR_SUCCESS = 0

    try {
        [IntPtr]$ClientHandle = [IntPtr]::Zero
        $NegotiatedVersion = 0
        $Result = [PrivescCheck.Win32]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$NegotiatedVersion, [ref]$ClientHandle)
        if ($Result -eq $ERROR_SUCCESS) {
    
    
            [IntPtr]$InterfaceListPtr = [IntPtr]::Zero
            $Result = [PrivescCheck.Win32]::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref]$InterfaceListPtr)
            if ($Result -eq $ERROR_SUCCESS) {
    
    
                $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
                Write-Verbose "Number of Wlan interfaces: $($NumberOfInterfaces)"
    
                # Calculate the pointer to the first WLAN_INTERFACE_INFO structure 
                $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {
    
                    $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type] [PrivescCheck.Win32+WLAN_INTERFACE_INFO])
    
                    Write-Verbose "Wlan interface: $($WlanInterfaceInfo.strInterfaceDescription)"
    
                    [IntPtr]$ProfileListPtr = [IntPtr]::Zero
                    $Result = [PrivescCheck.Win32]::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref]$ProfileListPtr)
                    if ($Result -eq $ERROR_SUCCESS) {
    
    
                        $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                        Write-Verbose "Number of profiles: $($NumberOfProfiles)"
    
                        # Calculate the pointer to the first WLAN_PROFILE_INFO structure 
                        $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                        for ($j = 0; $j -lt $NumberOfProfiles; $j++) {
    
                            $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] [PrivescCheck.Win32+WLAN_PROFILE_INFO])
    
                            Write-Verbose "Wlan profile: $($WlanProfileInfo.strProfileName)"
    
                            [string]$ProfileXml = ""
                            [UInt32]$WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                            [UInt32]$WlanProfileAccessFlags = 0
                            $Result = [PrivescCheck.Win32]::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.strProfileName, [IntPtr]::Zero, [ref]$ProfileXml, [ref]$WlanProfileFlags, [ref]$WlanProfileAccessFlags)
                            if ($Result -eq $ERROR_SUCCESS) {
    
    
                                $Item = Convert-ProfileXmlToObject -ProfileXml $ProfileXml
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Interface" -Value $WlanInterfaceInfo.strInterfaceDescription
                                $Item
    
                            } else {
                            }
    
                            # Calculate the pointer to the next WLAN_PROFILE_INFO structure 
                            $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                        }
    
                        # cleanup
                        [PrivescCheck.Win32]::WlanFreeMemory($ProfileListPtr)
    
                    } else {
                    }
    
                    # Calculate the pointer to the next WLAN_INTERFACE_INFO structure 
                    $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
                }
    
                # cleanup
                [PrivescCheck.Win32]::WlanFreeMemory($InterfaceListPtr)
    
            } else {
            }
    
            # cleanup
            $Result = [PrivescCheck.Win32]::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            if ($Result -eq $ERROR_SUCCESS) {
            } else {
            }
    
        } else {
        }
    } catch {
        # Do nothing
        # Wlan API doesn't exist on this machine probably 
    }
}
# ----------------------------------------------------------------
# END NETWORK    
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN MISC   
# ----------------------------------------------------------------
function Invoke-SystemInfoCheck {
    
    [CmdletBinding()] param()

    $OsName = ""
    $OsVersion = [System.Environment]::OSVersion.Version

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $OsName = $Item.ProductName

        if ($OsVersion -like "10.*") {
            # Windows >= 10/2016
            $OsVersion = "$($Item.CurrentMajorVersionNumber).$($Item.CurrentMinorVersionNumber).$($Item.CurrentBuild) Version $($Item.ReleaseId) ($($Item.CurrentBuild).$($Item.UBR))"
        } 

        $SystemInfoResult = New-Object -TypeName PSObject
        $SystemInfoResult | Add-Member -MemberType NoteProperty -Name "Name" -Value $OsName
        $SystemInfoResult | Add-Member -MemberType NoteProperty -Name "Version" -Value $OsVersion
        $SystemInfoResult

    } else {
        Write-Verbose $GetItemPropertyError
    }
}

function Invoke-SystemStartupHistoryCheck {
    
    [CmdletBinding()] param(
        [int]
        $TimeSpanInDays = 31
    )

    try {
        $SystemStartupHistoryResult = New-Object -TypeName System.Collections.ArrayList

        $StartDate = (Get-Date).AddDays(-$TimeSpanInDays)
        $EndDate = Get-Date

        $StartupEvents = Get-EventLog -LogName "System" -EntryType "Information" -After $StartDate -Before $EndDate | Where-Object {$_.EventID -eq 6005}

        $EventNumber = 1

        ForEach ($Event in $StartupEvents) {
            $SystemStartupHistoryItem = New-Object -TypeName PSObject 
            $SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $EventNumber
            $SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $Event.TimeGenerated)"
            #$SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Message" -Value "$($Event.Message)"
            [void]$SystemStartupHistoryResult.Add($SystemStartupHistoryItem)
            $EventNumber += 1
        }

        $SystemStartupHistoryResult
    } catch {
        # We might get an "acces denied"
        Write-Verbose "Error while querying the Event Log."
    }
}

function Invoke-SystemStartupCheck {
    
    [CmdletBinding()] param() 

    try {
        $TickcountMilliseconds = [PrivescCheck.Win32]::GetTickCount64()

        $StartupDate = (Get-Date).AddMilliseconds(-$TickcountMilliseconds)

        $SystemStartupResult = New-Object -TypeName PSObject
        $SystemStartupResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $StartupDate)"
        $SystemStartupResult
    
    } catch {
        # We are dealing with the Windows API so let's silently catch any exception, just in case...
    }
}

function Invoke-SystemDrivesCheck {
    
    [CmdletBinding()] param()

    $SystemDrivesResult = New-Object -TypeName System.Collections.ArrayList

    $Drives = Get-PSDrive -PSProvider "FileSystem"

    ForEach ($Drive in $Drives) {
        $DriveItem = New-Object -TypeName PSObject
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "Root" -Value "$($Drive.Root)"
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "DisplayRoot" -Value "$($Drive.DisplayRoot)"
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($Drive.Description)"
        [void]$SystemDrivesResult.Add([object]$DriveItem)
    }

    $SystemDrivesResult
}

function Invoke-LocalAdminGroupCheck {

    [CmdletBinding()] param()

    function Get-UserFlags {
        param(
            $UserFlags
        )

        $UserFlagsEnum = @{
            "ADS_UF_SCRIPT" = "1";
            "ADS_UF_ACCOUNTDISABLE" = "2";
            "ADS_UF_HOMEDIR_REQUIRED" = "8";
            "ADS_UF_LOCKOUT" = "16";
            "ADS_UF_PASSWD_NOTREQD" = "32";
            "ADS_UF_PASSWD_CANT_CHANGE" = "64";
            "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" = "128";
            "ADS_UF_TEMP_DUPLICATE_ACCOUNT" = "256";
            "ADS_UF_NORMAL_ACCOUNT" = "512";
            "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT" = "2048";
            "ADS_UF_WORKSTATION_TRUST_ACCOUNT" = "4096";
            "ADS_UF_SERVER_TRUST_ACCOUNT" = "8192";
            "ADS_UF_DONT_EXPIRE_PASSWD" = "65536";
            "ADS_UF_MNS_LOGON_ACCOUNT" = "131072";
            "ADS_UF_SMARTCARD_REQUIRED" = "262144";
            "ADS_UF_TRUSTED_FOR_DELEGATION" = "524288";
            "ADS_UF_NOT_DELEGATED" = "1048576";
            "ADS_UF_USE_DES_KEY_ONLY" = "2097152";
            "ADS_UF_DONT_REQUIRE_PREAUTH" = "4194304";
            "ADS_UF_PASSWORD_EXPIRED" = "8388608";
            "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" = "16777216";
        }

        $UserFlagsEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.value -band $UserFlags ) 
            {
                $_.name
            }
        }
    }

    function Get-GroupFlags {
        param(
            $GroupFlags
        )
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55
        $GroupFlagsEnum = @{
            "ADS_GROUP_TYPE_BUILTIN_LOCAL_GROUP" = "1"; # Specifies a group that is created by the system.
            "ADS_GROUP_TYPE_ACCOUNT_GROUP" = "2"; # Specifies a global group.
            "ADS_GROUP_TYPE_RESOURCE_GROUP" = "4"; # Specifies a domain local group.
            "ADS_GROUP_TYPE_UNIVERSAL_GROUP" = "8"; # Specifies a universal group.
            "ADS_GROUP_TYPE_APP_BASIC_GROUP" = "16";
            "ADS_GROUP_TYPE_APP_QUERY_GROUP" = "32";
            "ADS_GROUP_TYPE_SECURITY_ENABLED" = "2147483648"; # Specifies a security-enabled group.
        }

        $GroupFlagsEnum.GetEnumerator() | ForEach-Object { 
            if ($_.value -band $GroupFlags) 
            {
                $_.name
            }
        }
    }

    $LocalAdminGroupSid = "S-1-5-32-544" # Local admin group SID 
    $LocalAdminGroupFullname = ([Security.Principal.SecurityIdentifier]$LocalAdminGroupSid).Translate([Security.Principal.NTAccount]).Value
    $LocalAdminGroupName = $LocalAdminGroupFullname.Split('\')[1]

    $Computer = $env:COMPUTERNAME
    $AdsiComputer = [ADSI]("WinNT://$Computer,computer") 

    try {
        $LocalAdminGroup = $AdsiComputer.psbase.children.find($LocalAdminGroupName, "Group") 

        if ($LocalAdminGroup) {
            $LocalAdminGroup.psbase.invoke("members") | ForEach-Object {
                # For each member of the local admin group 
                
                $MemberName = $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
                $Member = $Null

                # Is it a local user?
                $AdsiComputer.Children | Where-Object { $_.SchemaClassName -eq "User" } | ForEach-Object {
                    if ($_.Name -eq $MemberName) {
                        Write-Verbose "Found user: $MemberName"
                        $Member = $_
                    } 
                }

                # if it's not a local user, is it a local grop ?
                if (-not $IsLocal) {
                    $AdsiComputer.Children | Where-Object { $_.SchemaClassName -eq "Group" } | ForEach-Object {
                        if ($_.Name -eq $MemberName) {
                            Write-Verbose "Found group: $MemberName"
                            $Member = $_
                        }
                    }
                }

                if ($Member) {
                    if ($Member.SchemaClassName -eq "User") {
                        $UserFlags = $Member.UserFlags.value
                        $Flags = Get-UserFlags $UserFlags 
                        $MemberType = "User"
                        $MemberIsLocal = $True
                        $MemberIsEnabled = $(-not ($Flags -contains "ADS_UF_ACCOUNTDISABLE"))
                    } elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.groupType.value
                        $Flags = Get-GroupFlags $GroupType
                        $MemberType = "Group"
                        $MemberIsLocal = $($Flags -contains "ADS_GROUP_TYPE_RESOURCE_GROUP")
                        $MemberIsEnabled = $True 
                    }
                } else {
                    $MemberType = ""
                    $MemberIsLocal = $False
                    $MemberIsEnabled = $Null 
                }

                $LocalAdminGroupResultItem = New-Object -TypeName PSObject 
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $MemberName
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $MemberType
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "IsLocal" -Value $MemberIsLocal  
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "IsEnabled" -Value $MemberIsEnabled 
                $LocalAdminGroupResultItem
            }
        } 
    } catch {
        Write-Verbose $_.Exception
    }
}

function Invoke-UsersHomeFolderCheck {

    [CmdletBinding()] param()
    
    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users

    Get-ChildItem -Path $UsersHomeFolder | ForEach-Object {

        $FolderPath = $_.FullName
        $ReadAccess = $False
        $WriteAccess = $False

        $Null = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem 
        if (-not $ErrorGetChildItem) {

            $ReadAccess = $True 

            $ModifiablePaths = $FolderPath | Get-ModifiablePath -LiteralPaths
            if (([object[]]$ModifiablePaths).Length -gt 0) {
                $WriteAccess = $True
            }
        }

        $UserHomFolderResultItem = New-Object -TypeName PSObject 
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "Write" -Value $WriteAccess
        $UserHomFolderResultItem
    }
}

function Invoke-MachineRoleCheck {
    
    [CmdletBinding()] param()

    $MachineRoleResult = New-Object -TypeName PSObject 

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    
    $FriendlyNames = @{
        "WinNT" = "WorkStation";
        "LanmanNT" = "Domain Controller";
        "ServerNT" = "Server";
    }

    if (-not $GetItemPropertyError){
        try {
            $MachineRoleResult = New-Object -TypeName PSObject
            $MachineRoleResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Item.ProductType
            $MachineRoleResult | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $FriendlyNames[$Item.ProductType]
            $MachineRoleResult 
        } catch {
            Write-Verbose "Hashtable error."
        }
    }
}

function Invoke-WindowsUpdateCheck {
    
    [CmdletBinding()] param()

    try {
        $WindowsUpdate = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Results

        if ($WindowsUpdate.LastInstallationSuccessDate) {
            $WindowsUpdateResult = New-Object -TypeName PSObject 
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value $(Convert-DateToString -Date $WindowsUpdate.LastInstallationSuccessDate)
            $WindowsUpdateResult
        } 
    } catch {
        # We migh get an access denied when querying this COM object
        Write-Verbose "Error while requesting COM object Microsoft.Update.AutoUpdate."
    }
}

# ----------------------------------------------------------------
# END MISC   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN CURRENT USER   
# ----------------------------------------------------------------
function Invoke-UserCheck {
    
    [CmdletBinding()] param()
    
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $UserResult = New-Object -TypeName PSObject 
    $UserResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $CurrentUser.Name 
    $UserResult | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $CurrentUser.User 
    $UserResult
}

function Invoke-UserGroupsCheck {
    
    [CmdletBinding()] param()

    $IgnoredGroupSids = @(
        "S-1-0",            # Null Authority
        "S-1-0-0",          # Nobody
        "S-1-1",            # World Authority
        "S-1-1-0",          # Everyone
        "S-1-2",            # Local Authority
        "S-1-2-0",          # Local
        "S-1-2-1",          # CONSOLE_LOGON
        "S-1-3",            # Creator Authority
        "S-1-3-0",          # Creator Owner
        "S-1-3-1",          # Creator Group
        "S-1-3-2",          # OWNER_SERVER
        "S-1-3-3",          # GROUP_SERVER
        "S-1-3-4",          # Owner Rights
        "S-1-5-80-0",       # NT Services\All Services
        "S-1-5",            # NT Authority
        "S-1-5-1",          # Dialup
        "S-1-5-2",          # Network
        "S-1-5-3",          # Batch
        "S-1-5-4",          # Interactive
        "S-1-5-6",          # Service
        "S-1-5-7",          # Anonymous
        "S-1-5-8",          # PROXY
        "S-1-5-10",         # Principal Self
        "S-1-5-11",         # Authenticated Users
        "S-1-5-12",         # Restricted Code
        "S-1-5-15",         # THIS_ORGANIZATION
        "S-1-5-17",         # This Organization
        "S-1-5-18",         # Local System 
        "S-1-5-19",         # Local Service
        "S-1-5-20",         # Network Service
        "S-1-5-32-545",     # Users
        "S-1-5-32-546",     # Guests
        "S-1-5-32-554",     # Builtin\Pre-Windows 2000 Compatible Access
        "S-1-5-80-0",       # NT Services\All Services
        "S-1-5-83-0",       # NT Virtual Machine\Virtual Machines
        "S-1-5-113",        # LOCAL_ACCOUNT
        "S-1-5-1000",       # OTHER_ORGANIZATION
        "S-1-15-2-1"        # ALL_APP_PACKAGES
    ) 

    $IgnoredGroupSidPatterns = @(
        "S-1-5-21-*-513",   # Domain Users
        "S-1-5-21-*-514",   # Domain Guests
        "S-1-5-21-*-515",   # Domain Computers
        "S-1-5-21-*-516",   # Domain Controllers
        "S-1-5-21-*-545",   # Users
        "S-1-5-21-*-546",   # Guests
        "S-1-5-64-*",       # NTLM / SChannel / Digest Authentication
        "S-1-16-*",         # Integrity levels 
        "S-1-15-3-*",       # Capabilities ("Active Directory does not resolve capability SIDs to names. This behavior is by design.")
        "S-1-18-*"          # Identities
    )
    
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Groups = $CurrentUser.Groups 

    ForEach ($Group in $Groups) {

        $GroupSid = $Group.Value 

        if (-not ($IgnoredGroupSids -contains $GroupSid)) {

            $KnownSid = $False 
            ForEach ($Pattern in $IgnoredGroupSidPatterns) {
                if ($GroupSid -like $Pattern) {
                    Write-Verbose "Known SID pattern: $GroupSid"
                    $KnownSid = $true
                    break   
                }
            }

            if (-not $KnownSid) {

                if ($GroupSid -notmatch '^S-1-5.*') {
                    $GroupName = ($Group.Translate([System.Security.Principal.NTAccount])).Value
                } else {
                    $GroupName = "N/A"
                }

                $UserGroups = New-Object -TypeName PSObject 
                $UserGroups | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $GroupName 
                $UserGroups | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $GroupSid
                $UserGroups
            }
        } else {
            Write-Verbose "Known SID: $GroupSid"
        }
    }
}

function Invoke-UserPrivilegesCheck {

    [CmdletBinding()] param()    

    $HighPotentialPrivileges = "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeShutdownPrivilege"

    $CurrentPrivileges = Get-UserPrivileges

    ForEach ($Privilege in $CurrentPrivileges) {

        if ($HighPotentialPrivileges -contains $Privilege.Name) {

            $Privilege
        }
    }
}

function Invoke-UserEnvCheck {

    [CmdletBinding()] param() 

    [string[]] $Keywords = "key", "passw", "secret", "pwd", "creds", "credential", "api"

    Get-ChildItem -Path env: | ForEach-Object {

        $EntryName = $_.Name
        $EntryValue = $_.Value 
        $CheckVal = "$($_.Name) $($_.Value)"
        
        ForEach ($Keyword in $Keywords) {

            if ($CheckVal -Like "*$($Keyword)*") {

                $EnvItem = New-Object -TypeName PSObject 
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $EntryValue
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value $Keyword
                $EnvItem
            }
        }
    }
}
# ----------------------------------------------------------------
# END CURRENT USER    
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN CREDENTIALS     
# ----------------------------------------------------------------
function Invoke-WinlogonCheck {

    [CmdletBinding()] param()

    $RegPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    $Item = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError

    if (-not $GetItemPropertyError) {

        if ($Item.DefaultPassword) {
            $WinlogonItem = New-Object -TypeName PSObject 
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Item.DefaultDomainName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $Item.DefaultUserName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Item.DefaultPassword
            $WinlogonItem
        } 
    
        if ($Item.AltDefaultPassword) {
            $WinlogonItem = New-Object -TypeName PSObject 
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Item.AltDefaultDomainName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $Item.AltDefaultUserName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Item.AltDefaultPassword
            $WinlogonItem
        }

    } else {
        Write-Verbose "Error while querying '$RegPath'"
    }
}

function Invoke-CredentialFilesCheck {
    
    [CmdletBinding()] param()

    $CredentialsFound = $False

    $Paths = New-Object -TypeName System.Collections.ArrayList
    [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Credentials"))
    [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Credentials"))

    ForEach ($Path in [string[]]$Paths) {

        Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {

            $Result = New-Object -TypeName PSObject 
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
            $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
            $Result

            if (-not $CredentialsFound) { $CredentialsFound = $True }
        }
    }

    if ($CredentialsFound) {

        $CurrentUser = Invoke-UserCheck

        if ($CurrentUser -and $CurrentUser.SID) {
    
            $Paths = New-Object -TypeName System.Collections.ArrayList
            [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
            [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
    
            ForEach ($Path in [string[]]$Paths) {
    
                Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | Where-Object {$_.Name.Length -eq 36 } | ForEach-Object {
        
                    $Result = New-Object -TypeName PSObject 
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Protect"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
                    $Result
                }
            }
        } 
    } 
}

function Invoke-VaultCredCheck {
    
    [CmdletBinding()] param()

    function Convert-TypeToString {
        [CmdletBinding()] param(
            [Uint32]$Type 
        )

        $TypeEnum = @{
            "GENERIC"                   = "1";
            "DOMAIN_PASSWORD"           = "2";
            "DOMAIN_CERTIFICATE"        = "3";
            "DOMAIN_VISIBLE_PASSWORD"   = "4"; #  This value is no longer supported. 
            "GENERIC_CERTIFICATE"       = "5"; #  This value is no longer supported.
            "DOMAIN_EXTENDED"           = "6"; #  This value is no longer supported.
            "MAXIMUM"                   = "7"; #  This value is no longer supported.
            "TYPE_MAXIMUM_EX"           = "8"; #  This value is no longer supported.
        }
    
        $TypeEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.Value -eq $Type ) 
            {
                $_.Name
            }
        }
    }

    function Convert-PersistToString {
        [CmdletBinding()] param(
            [Uint32]$Persist 
        )

        $PersistEnum = @{
            "SESSION" = "1";
            "LOCAL_MACHINE" = "2";
            "ENTERPRISE" = "3";
        }

        $PersistEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.Value -eq $Persist ) 
            {
                $_.Name
            }
        }
    }

    function Get-Credential {
        [CmdletBinding()] param(
            [PrivescCheck.Win32+CREDENTIAL]$RawObject
        )

        if (-not ($RawObject.CredentialBlobSize -eq 0)) {

            $UnicodeString = New-Object -TypeName "PrivescCheck.Win32+UNICODE_STRING"
            $UnicodeString.Length = $RawObject.CredentialBlobSize
            $UnicodeString.MaximumLength = $RawObject.CredentialBlobSize
            $UnicodeString.Buffer = $RawObject.CredentialBlob

            $TestFlags = 2 # IS_TEXT_UNICODE_STATISTICS
            $IsUnicode = [PrivescCheck.Win32]::IsTextUnicode($UnicodeString.Buffer, $UnicodeString.Length, [ref]$TestFlags)
            
            if ($IsUnicode) {
                $Result = [Runtime.InteropServices.Marshal]::PtrToStringUni($UnicodeString.Buffer, $UnicodeString.Length / 2)
            } else {
                for ($i = 0; $i -lt $UnicodeString.Length; $i++) {
                    $BytePtr = [IntPtr] ($UnicodeString.Buffer.ToInt64() + $i)
                    $Byte = [Runtime.InteropServices.Marshal]::ReadByte($BytePtr)
                    $Result += "{0:X2} " -f $Byte
                }
            }

            $Result
        }
    }

    # CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
    $Count = 0;
    [IntPtr]$CredentialsPtr = [IntPtr]::Zero
    $Success = [PrivescCheck.Win32]::CredEnumerate([IntPtr]::Zero, 1, [ref]$Count, [ref]$CredentialsPtr)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {


        # CredEnumerate() returns an array of $Count PCREDENTIAL pointers, so we need to iterate
        # this array in order to get each PCREDENTIAL pointer. Then we can use this pointer to 
        # convert a blob of unmanaged memory to a PrivescCheck.Win32+CREDENTIAL object.

        for ($i = 0; $i -lt $Count; $i++) {

            $CredentialPtrOffset = [IntPtr] ($CredentialsPtr.ToInt64() + [IntPtr]::Size * $i)
            $CredentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($CredentialPtrOffset) 
            $Credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CredentialPtr, [type] [PrivescCheck.Win32+CREDENTIAL])
            $CredentialStr = Get-Credential -RawObject $Credential

            if (-not [String]::IsNullOrEmpty($CredentialStr)) {
                $CredentialObject = New-Object -TypeName PSObject 
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $Credential.TargetName
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $Credential.UserName
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Comment" -Value $Credential.Comment
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "$($Credential.Type) - $(Convert-TypeToString -Type $Credential.Type)"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Persist" -Value "$($Credential.Persist) - $(Convert-PersistToString -Persist $Credential.Persist)"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value "0x$($Credential.Flags.ToString('X8'))"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $CredentialStr
                $CredentialObject
            }
        }

        [PrivescCheck.Win32]::CredFree($CredentialsPtr) 

    } else {
        # If there is no saved credentials, CredEnumerate sets the last error to ERROR_NOT_FOUND 
        # but this doesn't mean that the function really failed. The same thing applies for 
        # the error code ERROR_NO_SUCH_LOGON_SESSION.
    }
}

function Invoke-VaultListCheck {
    

    [CmdletBinding()] param()

    function Get-VaultNameFromGuid {
        [CmdletBinding()] param(
            [Guid] $VaultGuid
        )

        $VaultSchemaEnum = @{
            ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
            ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
            ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
            ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
            ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
            ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
            ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
            ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        }

        $VaultSchemaEnum[$VaultGuid]
    }

    # Highly inspired from "Get-VaultCredential.ps1", credit goes to Matthew Graeber (@mattifestation)
    # https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Get-VaultCredential.ps1
    function Get-VaultItemElementValue {
        [CmdletBinding()] param(
            [IntPtr] $VaultItemElementPtr
        )

        if ($VaultItemElementPtr -eq [IntPtr]::Zero) {
            return
        }

        $VaultItemDataHeader = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemElementPtr, [type] [PrivescCheck.Win32+VAULT_ITEM_DATA_HEADER])
        $VaultItemDataValuePtr = [IntPtr] ($VaultItemElementPtr.ToInt64() + 16)

        switch ($VaultItemDataHeader.Type) {

            # ElementType_Boolean
            0x00 {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte($VaultItemDataValuePtr)
            }

            # ElementType_Short
            0x01 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedShort
            0x02 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_Integer
            0x03 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedInteger
            0x04 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_Double
            0x05 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Double])
            }

            # ElementType_Guid
            0x06 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Guid])
            }

            # ElementType_String
            0x07 { 
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni($StringPtr)
            }

            # ElementType_ByteArray
            0x08 {

            }

            # ElementType_TimeStamp
            0x09 {

            }

            # ElementType_ProtectedArray
            0x0a {

            }

            # ElementType_Attribute
            0x0b {

            }

            # ElementType_Sid
            0x0c {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                $SidObject = [Security.Principal.SecurityIdentifier] ($SidPtr)
                $SidObject.Value
            }

            # ElementType_Max
            0x0d {
                
            }
        }
    }

    $VaultsCount = 0
    $VaultGuids = [IntPtr]::Zero 
    $Result = [PrivescCheck.Win32]::VaultEnumerateVaults(0, [ref]$VaultsCount, [ref]$VaultGuids)

    if ($Result -eq 0) {


        for ($i = 0; $i -lt $VaultsCount; $i++) {

            $VaultGuidPtr = [IntPtr] ($VaultGuids.ToInt64() + ($i * [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid])))
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultGuidPtr, [type] [Guid])
            $VaultName = Get-VaultNameFromGuid -VaultGuid $VaultGuid

            Write-Verbose "Vault: $($VaultGuid) - $($VaultName)"

            $VaultHandle = [IntPtr]::Zero 
            $Result = [PrivescCheck.Win32]::VaultOpenVault($VaultGuidPtr, 0, [ref]$VaultHandle)

            if ($Result -eq 0) {


                $VaultItemsCount = 0
                $ItemsPtr = [IntPtr]::Zero 
                $Result = [PrivescCheck.Win32]::VaultEnumerateItems($VaultHandle, 0x0200, [ref]$VaultItemsCount, [ref]$ItemsPtr)

                $VaultItemPtr = $ItemsPtr

                if ($Result -eq 0) {


                    $OSVersion = [Environment]::OSVersion.Version

                    try {

                        for ($j = 0; $j -lt $VaultItemsCount; $j++) {

                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $VaultItemType = [type] [PrivescCheck.Win32+VAULT_ITEM_7]
                            } else {
                                # Windows 8+
                                $VaultItemType = [type] [PrivescCheck.Win32+VAULT_ITEM_8]
                            }
    
                            $VaultItem = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemPtr, [type] $VaultItemType)
    
                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = [PrivescCheck.Win32]::VaultGetItem7($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            } else {
                                # Windows 8+
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = [PrivescCheck.Win32]::VaultGetItem8($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, $VaultItem.PackageSid, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
    
                            if ($Result -eq 0) {

                                $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordItemPtr, [Type] $VaultItemType)
                                $Password = Get-VaultItemElementValue -VaultItemElementPtr $PasswordItem.Authenticator
                                [PrivescCheck.Win32]::VaultFree($PasswordItemPtr) | Out-Null 

                            } else {
                            }
    
                            if (-not [String]::IsNullOrEmpty($Password)) {
                                $Item = New-Object -TypeName PSObject
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $VaultName
                                $Item | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Resource)
                                $Item | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Identity)
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $Password
                                $Item | Add-Member -MemberType "NoteProperty" -Name "LastWritten" -Value $([DateTime]::FromFileTimeUtc($VaultItem.LastWritten))
                                $Item
                            }

                            $VaultItemPtr = [IntPtr] ($VaultItemPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VaultItemType))
                        }

                    } catch [Exception] {
                        Write-Verbose $_.Exception.Message 
                    }

                } else {
                }

                [PrivescCheck.Win32]::VaultCloseVault([ref]$VaultHandle) | Out-Null 

            } else {
            }
        }

    } else {
    }
}

function Invoke-GPPPasswordCheck {

    [CmdletBinding()] param(
        [switch]$Remote
    )

    try {
        Add-Type -Assembly System.Security
        Add-Type -Assembly System.Core
    } catch {
        # do nothing
    }

    function Get-DecryptedPassword {
        [CmdletBinding()] param(
            [string] $Cpassword 
        )

        if (-not [String]::IsNullOrEmpty($Cpassword)) {

            $Mod = $Cpassword.Length % 4
            if ($Mod -gt 0) {
                $Cpassword += "=" * (4 - $Mod)
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            try {

                $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

                $AesIV = New-Object Byte[]($AesObject.IV.Length) 
                $AesObject.IV = $AesIV
                $AesObject.Key = $AesKey
                $DecryptorObject = $AesObject.CreateDecryptor() 
                [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

                [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)

            } catch [Exception] {
                Write-Verbose $_.Exception.Message
            }
        }
    }

    if ($Remote) {
        $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
    } else {
        $GppPath = $Env:ALLUSERSPROFILE
        if ($GppPath -notmatch "ProgramData") {
            $GppPath = Join-Path -Path $GppPath -ChildPath "Application Data"
        } else {
            $GppPath = Join-Path -Path $GppPath -ChildPath "Microsoft\Group Policy"
        }
    }
    
    if (Test-Path -Path $GppPath -ErrorAction SilentlyContinue) {

        $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Drives.xml','Printers.xml' -Force -ErrorAction SilentlyContinue

        foreach ($File in $CachedGPPFiles) {
            
            $FileFullPath = $File.FullName 
            Write-Verbose $FileFullPath

            try {
                [xml]$XmlFile = Get-Content -Path $FileFullPath -ErrorAction SilentlyContinue
            } catch [Exception] {
                Write-Verbose $_.Exception.Message 
            }

            if ($Null -eq $XmlFile) {
                continue
            }

            $XmlFile.GetElementsByTagName("Properties") | ForEach-Object {

                $Properties = $_ 
                $Cpassword = ""

                switch ($File.BaseName) {

                    Groups {
                        $Type = "User/Group"
                        $UserName = $Properties.userName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Description: $($Properties.description)"
                    }
    
                    Scheduledtasks {
                        $Type = "Scheduled Task"
                        $UserName = $Properties.runAs 
                        $Cpassword = $Properties.cpassword 
                        $Content = "App: $($Properties.appName) $($Properties.args)"
                    }
    
                    DataSources {
                        $Type = "Data Source"
                        $UserName = $Properties.username 
                        $Cpassword = $Properties.cpassword 
                        $Content = "DSN: $($Properties.dsn)"
                    }
    
                    Drives {
                        $Type = "Mapped Drive"
                        $UserName = $Properties.userName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Path: $($Properties.path)"
                    }
    
                    Services {
                        $Type = "Service"
                        $UserName = $Properties.accountName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Name: $($Properties.serviceName)"
                    }

                    Printers {
                        $Type = "Printer"
                        $UserName = $Properties.username 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Path: $($Properties.path)"
                    }
                }

                if (-not [String]::IsNullOrEmpty($Cpassword)) {
                    $Item = New-Object -TypeName PSObject
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                    $Item | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $(Get-DecryptedPassword -Cpassword $Cpassword)
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Content" -Value $Content
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Changed" -Value $Properties.ParentNode.changed
                    $Item | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $FileFullPath
                    $Item
                }
            }
        }
    }
}
# ----------------------------------------------------------------
# END CREDENTIALS     
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN SENSITIVE FILES 
# ----------------------------------------------------------------
function Invoke-SamBackupFilesCheck {
    
    [CmdletBinding()] param()

    $ArrayOfPaths = New-Object System.Collections.ArrayList 
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\system"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SYSTEM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\system"))

    ForEach ($Path in [string[]]$ArrayOfPaths) {

        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) { 

            Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError | Out-Null 

            if (-not $GetContentError) {
                $SamBackupFile = New-Object -TypeName PSObject 
                $SamBackupFile | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path 
                $SamBackupFile
            } 
        }
    }
}

function Invoke-UnattendFilesCheck {

    [CmdletBinding()] param()

    $ArrayOfPaths = New-Object System.Collections.ArrayList 
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattended.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattended.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Panther\Unattend.xml"))

    ForEach ($Path in [string[]]$ArrayOfPaths) {

        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) { 

            Write-Verbose "Found file: $Path"

            $Result = Get-UnattendSensitiveData -Path $Path 
            if ($Result) {
                $Result | Add-Member -MemberType "NoteProperty" -Name "File" -Value $Path 
                $Result
            }
        }
    }
}
# ----------------------------------------------------------------
# END SENSITIVE FILES 
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN INSTALLED PROGRAMS   
# ----------------------------------------------------------------
function Invoke-InstalledProgramsCheck {
    
    [CmdletBinding()] param()

    $InstalledProgramsResult = New-Object System.Collections.ArrayList 

    $Items = Get-InstalledPrograms -Filtered

    ForEach ($Item in $Items) {
        $CurrentFileName = $Item.Name 
        $CurrentFileFullname = $Item.FullName
        $AppItem = New-Object -TypeName PSObject 
        $AppItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $CurrentFileName
        $AppItem | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $CurrentFileFullname
        [void]$InstalledProgramsResult.Add($AppItem)
    }
    
    $InstalledProgramsResult
}

function Invoke-ModifiableProgramsCheck {
    
    [CmdletBinding()] param()

    $Items = Get-InstalledPrograms -Filtered

    ForEach ($Item in $Items) {
        
        $SearchPath = New-Object -TypeName System.Collections.ArrayList
        [void]$SearchPath.Add([string]$(Join-Path -Path $Item.FullName -ChildPath "\*")) # Do this to avoid the use of -Depth which is PSH5+
        [void]$SearchPath.Add([string]$(Join-Path -Path $Item.FullName -ChildPath "\*\*")) # Do this to avoid the use of -Depth which is PSH5+
        
        $ChildItems = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue -ErrorVariable GetChildItemError 
        #$ChildItems = $Item | Get-ChildItem -Recurse -Depth 2 -ErrorAction SilentlyContinue -ErrorVariable GetChildItemError 
        
        if (-not $GetChildItemError) {

            $ChildItems | ForEach-Object {

                if ($_ -is [System.IO.DirectoryInfo]) {
                    $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths
                } else {
                    # Check only .exe and .dll ???
                    # TODO: maybe consider other extensions 
                    if ($_.FullName -Like "*.exe" -or $_.FullName -Like "*.dll") {
                        $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths 
                    }
                }

                if ($ModifiablePaths) {
                    ForEach ($Path in $ModifiablePaths) {
                        if ($Path.ModifiablePath -eq $_.FullName) {
                            $Path
                        }
                    }
                }
            }
        }
    }
}

function Invoke-ApplicationsOnStartupCheck {

    [CmdletBinding()] param()

    # Is it relevant to check HKCU entries???
    #[string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    [string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"

    $RegistryPaths | ForEach-Object {

        $RegKeyPath = $_

        $Item = Get-Item -Path "Registry::$($RegKeyPath)" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
        if (-not $ErrorGetItem) {

            $Item | Select-Object -ExpandProperty Property | ForEach-Object {

                $RegKeyValueName = $_
                $RegKeyValueData = $Item.GetValue($RegKeyValueName, "", "DoNotExpandEnvironmentNames")
                
                $ModifiablePaths = $RegKeyValueData | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')}
                if (([object[]]$ModifiablePaths).Length -gt 0) {
                    $IsModifiable = $True 
                } else {
                    $IsModifiable = $False 
                }

                $ResultItem = New-Object -TypeName PSObject 
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegKeyValueName
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($RegKeyPath)\$($RegKeyValueName)"
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegKeyValueData
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                $ResultItem 
            }
        }
    }

    $Root = (Get-Item -Path $env:windir).PSDrive.Root
    
    [string[]]$FileSystemPaths = "\Users\All Users\Start Menu\Programs\Startup", "\Users\$env:USERNAME\Start Menu\Programs\Startup"

    $FileSystemPaths | ForEach-Object {

        $StartupFolderPath = Join-Path -Path $Root -ChildPath $_ 

        Get-ChildItem -Path $StartupFolderPath -ErrorAction SilentlyContinue | ForEach-Object {
            $EntryName = $_.Name
            $EntryPath = $_.FullName

            if ($EntryPath -Like "*.lnk") {

                try {

                    $Wsh = New-Object -ComObject WScript.Shell
                    $Shortcut = $Wsh.CreateShortcut((Resolve-Path -Path $EntryPath))

                    $ModifiablePaths = $Shortcut.TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')}
                    if (([object[]]$ModifiablePaths).Length -gt 0) {
                        $IsModifiable = $True
                    } else {
                        $IsModifiable = $False
                    }

                    $ResultItem = New-Object -TypeName PSObject 
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                    $ResultItem 

                } catch {
                    # do nothing
                }
            }
        }
    }
}

function Invoke-ScheduledTasksCheck {

    [CmdletBinding()] param(
        [switch]$Filtered
    )

    function Get-ScheduledTasks {

        param (
            [object]$Service,
            [string]$TaskPath
        )

        ($CurrentFolder = $Service.GetFolder($TaskPath)).GetTasks(0)
        $CurrentFolder.GetFolders(0) | ForEach-Object {
            Get-ScheduledTasks -Service $Service -TaskPath $(Join-Path -Path $TaskPath -ChildPath $_.Name )
        }
    }

    function Convert-SidToName {

        param (
            [string]$Sid
        )

        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate( [System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }

    try {

        $ScheduleService = New-Object -ComObject("Schedule.Service")
        $ScheduleService.Connect()

        Get-ScheduledTasks -Service $ScheduleService -TaskPath "\" | ForEach-Object {

            if ($_.Enabled) {

                $TaskName = $_.Name
                $TaskPath = $_.Path
                $TaskFile = Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $TaskPath

                [xml]$TaskXml = $_.Xml
                $TaskExec = $TaskXml.GetElementsByTagName("Exec")
                $TaskCommandLine = "$($TaskExec.Command) $($TaskExec.Arguments)"
                $Principal = $TaskXml.GetElementsByTagName("Principal")

                if ($Principal.UserId) {
                    $PrincipalName = Convert-SidToName -Sid $Principal.UserId
                } elseif ($Principal.GroupId) {
                    $PrincipalName = Convert-SidToName -Sid $Principal.GroupId
                }

                if ($TaskExec.Command.Length -gt 0) {

                    if ($Filtered) {

                        $TaskCommandLine | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | ForEach-Object {

                            $ResultItem = New-Object -TypeName PSObject 
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                            $ResultItem
                        }
                    } else {

                        $ResultItem = New-Object -TypeName PSObject 
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                        $ResultItem
                    }

                } else {
                    Write-Verbose "Task '$($_.Name)' has an empty cmd line"
                }
            } else {
                Write-Verbose "Task '$($_.Name)' is disabled"
            }
        }
    } catch {
        Write-Verbose $_
    }
}

function Invoke-RunningProcessCheck {
    
    [CmdletBinding()] param(
        [switch]
        $Self = $False
    )

    $CurrentUser = $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 

    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", 
    "csrss", # Client/Server Runtime Subsystem
    "dwm", # Desktop Window Manager
    "msdtc", # Microsoft Distributed Transaction Coordinator
    "smss", # Session Manager Subsystem
    "svchost" # Service Host
    )

    $AllProcess = Get-Process 

    ForEach ($Process in $AllProcess) {

        if (-not ($IgnoredProcessNames -contains $Process.Name )) {

            $ProcessUser = (Get-UserFromProcess -ProcessId $Process.Id).DisplayName

            $ReturnProcess = $False

            if ($Self) {
                if ($ProcessUser -eq $CurrentUser) {
                    $ReturnProcess = $True 
                }
            } else {
                if (-not ($ProcessUser -eq $CurrentUser)) {

                    # Here, I check whether 'C:\Windows\System32\<PROC_NAME>.exe' exists
                    # Not ideal but it's a quick way to check whether it's a built-in binary.
                    # There might be some issues because of the FileSystem Redirector if the script is 
                    # run from a 32-bits instance of powershell.exe (-> SysWow64 instead of System32).
                    $PotentialImagePath = Join-Path -Path $env:SystemRoot -ChildPath "System32"
                    $PotentialImagePath = Join-Path -Path $PotentialImagePath -ChildPath "$($Process.name).exe"

                    # If we can't find it in System32, add it to the list 
                    if (-not (Test-Path -Path $PotentialImagePath)) {
                        $ReturnProcess = $True 
                    }
                    $ReturnProcess = $True 
                }
            }

            if ($ReturnProcess) {
                $RunningProcess = New-Object -TypeName PSObject 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Process.Name 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $Process.Id 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "User" -Value $(if ($ProcessUser) { $ProcessUser } else { "N/A" })
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Process.Path 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "SessionId" -Value $Process.SessionId
                $RunningProcess
            }

        } else {
            Write-Verbose "Ignored: $($Process.Name)"
        }
    }
}
# ----------------------------------------------------------------
# END INSTALLED PROGRAMS   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN SERVICES   
# ----------------------------------------------------------------
function Test-ServiceDaclPermission {
    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }
        
        $CheckAllPermissionsInSet = $False

        if($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            # We might not be able to access the Service at all so we must check whether Add-ServiceDacl returned something.
            if ($TargetService -and $TargetService.Dacl) { 

                # Enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                # Check all the Dacl objects of the current service 
                ForEach($ServiceDacl in $TargetService.Dacl) {

                    $MatchingDaclFound = $False

                    # A Dacl object contains two properties we want to check: a SID and a list of AccessRights 
                    # First, we want to check if the current Dacl SID is in the list of SIDs of the current user 
                    if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if($CheckAllPermissionsInSet) {

                            # If a Permission Set was specified, we want to make sure that we have all the necessary access rights
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if($AllMatched) {
                                $TargetService
                                $MatchingDaclFound = $True 
                            }
                        } else {

                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' permission for $IndividualService"
                                    $TargetService
                                    $MatchingDaclFound = $True 
                                    break
                                }
                            }
                        }
                    }

                    if ($MatchingDaclFound) {
                        # As soon as we find a matching Dacl, we can stop searching 
                        break
                    }
                }
            } else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}

function Invoke-InstalledServicesCheck {
    
    [CmdletBinding()] param()

    $InstalledServicesResult = New-Object -TypeName System.Collections.ArrayList

    # Get only third-party services 
    $FilteredServices = Get-ServiceList -FilterLevel 3

    ForEach ($Service in $FilteredServices) {
        # Make a simplified version of the Service object, we only basic information for ths check.
        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $Service.DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $Service.StartMode
        #$ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Service.Type
        [void]$InstalledServicesResult.Add($ServiceItem)
    }

    $InstalledServicesResult
}

function Invoke-ServicesPermissionsRegistryCheck {
    
    [CmdletBinding()] param()
    
    # Get all services except the ones with an empty ImagePath or Drivers 
    $AllServices = Get-ServiceList -FilterLevel 2 

    ForEach ($Service in $AllServices) {

        Get-ModifiableRegistryPath -Path $Service.RegistryPath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {

            $Status = "Unknown"
            # Can we restart the service?
            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
    
            # Can we start the service?
            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}

function Invoke-ServicesUnquotedPathCheck {
    
    [CmdletBinding()] param()

    # Get all services which have a non-empty ImagePath
    $Services = Get-ServiceList -FilterLevel 1
    
    $PermissionsAddFile = @("WriteData/AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    $PermissionsAddFolder = @("AppendData/AddSubdirectory", "DeleteChild", "WriteDAC", "WriteOwner")

    ForEach ($Service in $Services) {
        $ImagePath = $Service.ImagePath.trim()

        # If the ImagePath doesn't start with a " or a ' 
        if (-not ($ImagePath.StartsWith("`"") -or $ImagePath.StartsWith("'"))) {
            
            # Extract the binpath from the ImagePath
            $BinPath = $ImagePath.SubString(0, $ImagePath.ToLower().IndexOf(".exe") + 4)

            # If the binpath contains spaces 
            If ($BinPath -match ".* .*") {
                $ModifiableFiles = $BinPath.split(' ') | Get-ModifiablePath

                $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                     
                    $TempPath = $([System.Environment]::ExpandEnvironmentVariables($BinPath))
                    $TempPath = Split-Path -Path $TempPath -Parent 
                    while ($TempPath) 
                    {
                        try {
                            $ParentPath = Split-Path -Path $TempPath -Parent 
                            if ($ParentPath -eq $_.ModifiablePath) {
                                $PermissionsSet = $Null 
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # If the current folder exists, can we create files in it?
                                    #"Folder $($TempPath) exists, can we create files in $($ParentPath)???"
                                    $PermissionsSet = $PermissionsAddFile
                                } else {
                                    # The current folder doesn't exist, can we create it? 
                                    #"Folder $($TempPath) doesn't exist, can we create the folder $($ParentPath)???"
                                    $PermissionsSet = $PermissionsAddFolder 
                                }
                                ForEach ($Permission in $_.Permissions) {
                                    if ($PermissionsSet -contains $Permission) {

                                        $Status = "Unknown"
                                        # Can we restart the service?
                                        $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
                                        if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
                                
                                        # Can we start the service?
                                        $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                                        if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

                                        $ServiceItem = New-Object -TypeName PSObject 
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
                                        $ServiceItem

                                        break
                                    }
                                }
                                # We found the path returned by Get-ModifiablePath so we can exit the while loop 
                                break
                            }
                        } catch {
                            # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                            # exit safely to avoid an infinite loop 
                            break 
                        }
                        $TempPath = $ParentPath
                    }
                }
            }
        }
    }
}

function Invoke-ServicesImagePermissionsCheck {
    
    [CmdletBinding()] param()
    
    $Services = Get-ServiceList -FilterLevel 1

    ForEach ($Service in $Services) {

        $Service.ImagePath | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
            
            $Status = "Unknown"
            # Can we restart the service?
            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
    
            # Can we start the service?
            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}

function Invoke-ServicesPermissionsCheck {
    
    [CmdletBinding()] param()

    # Get-ServiceList returns a list of custom Service objects 
    # The properties of a custom Service object are: Name, DisplayName, User, ImagePath, StartMode, Type, RegsitryKey, RegistryPath 
    # We also apply the FilterLevel 1 to filter out services which have an empty ImagePath 
    $Services = Get-ServiceList -FilterLevel 1

    # For each custom Service object in the list 
    ForEach ($Service in $Services) {

        # Get a 'real' Service object and the associated DACL, based on its name 
        $TargetService = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'ChangeConfig'

        if ($TargetService) {

            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True } else { $UserCanRestart = $False }

            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject  
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $TargetService.Status 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}
# ----------------------------------------------------------------
# END SERVICES   
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN DLL HIJACKING   
# ----------------------------------------------------------------
function Invoke-DllHijackingCheck {
    
    [CmdletBinding()] param()
    
    $SystemPath = (Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path 
    $Paths = $SystemPath.Split(';')

    ForEach ($Path in $Paths) {
        if ($Path -and $Path -ne '') {
            $Path | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $_
            }
        }
    }
}

function Invoke-HijackableDllsCheck {

    [CmdletBinding()] param()

    function Test-DllExists {

        [CmdletBinding()] param (
            [string]$Name
        )

        $WindowsDirectories = New-Object System.Collections.ArrayList
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System32"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "SysNative"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System"))
        [void]$WindowsDirectories.Add($env:windir)

        ForEach ($WindowsDirectory in [string[]]$WindowsDirectories) {
            $Path = Join-Path -Path $WindowsDirectory -ChildPath $Name 
            $Null = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem 
            if (-not $ErrorGetItem) {
                return $True
            }
        }
        return $False
    }

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -eq 10) {
        #$Service = Get-Service -Name "CDPSvc" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        $Service = Get-ServiceFromRegistry -Name "CDPSvc"
        if ($Service -and ($Service.StartMode -ne "Disabled")) {
            $DllName = "cdpsgshims.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by CDPSvc upon service startup"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\LOCAL SERVICE"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $True 
                $ServiceItem
            }
        }
    }

    # Windows 7, 8, 8.1
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {
        #$Service = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        $Service = Get-ServiceFromRegistry -Name "DiagTrack"
        if ($Service -and ($Service.StartMode -ne "Disabled")) {
            $DllName = "windowsperformancerecordercontrol.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by DiagTrack upon service startup or shutdown"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\SYSTEM"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $True 
                $ServiceItem
            }

            $DllName = "diagtrack_win.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by DiagTrack upon service startup"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\SYSTEM"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $True 
                $ServiceItem
            }
        }
    }

    # Windows Vista, 7, 8
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {
        #$Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        $Service = Get-ServiceFromRegistry -Name "IKEEXT"
        if ($Service -and ($Service.StartMode -ne "Disabled")) {

            $RebootRequired = $True
            $Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
            if ((-not $ErrorGetService) -and ($Service.Status -eq "Stopped")) {
                $RebootRequired = $False
            }

            $DllName = "wlbsctrl.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by IKEEXT upon service startup"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\SYSTEM"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $RebootRequired 
                $ServiceItem
            }
        }
    }

    # Windows 7
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        #$Service = Get-Service -Name "NetMan" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        $Service = Get-ServiceFromRegistry -Name "NetMan"
        if ($Service -and ($Service.StartMode -ne "Disabled")) {
            $DllName = "wlanhlp.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by NetMan when listing network interfaces"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\SYSTEM"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $False 
                $ServiceItem
            } 
        }
    }

    # Windows 8, 8.1, 10
    if (($OsVersion.Major -eq 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {
        # $Service = Get-Service -Name "NetMan" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        $Service = Get-ServiceFromRegistry -Name "NetMan"
        if ($Service -and ($Service.StartMode -ne "Disabled")) {
            $DllName = "wlanapi.dll"
            if (-not (Test-DllExists -Name $DllName)) {
                $ServiceItem = New-Object -TypeName PSObject
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Loaded by NetMan when listing network interfaces"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value "NT AUTHORITY\SYSTEM"
                $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $False 
                $ServiceItem
            }
        }
    }
}
# ----------------------------------------------------------------
# END DLL HIJACKING   
# ----------------------------------------------------------------
#endregion Checks

# ----------------------------------------------------------------
# Main  
# ----------------------------------------------------------------
#region Main
function Write-Banner {
    [CmdletBinding()] param(
        [string]$Category,
        [string]$Name,
        [ValidateSet("Info", "Conf", "Vuln")]$Type,
        [string]$Note
    )

    function Split-Note {
        param([string]$Note)
        $NoteSplit = New-Object System.Collections.ArrayList
        $Temp = $Note 
        do {
            if ($Temp.Length -gt 53) {
                [void]$NoteSplit.Add([string]$Temp.Substring(0, 53))
                $Temp = $Temp.Substring(53)
            } else {
                [void]$NoteSplit.Add([string]$Temp)
                break
            }
        } while ($Temp.Length -gt 0)
        $NoteSplit
    }

    $Title = "$($Category.ToUpper()) > $($Name)"
    if ($Title.Length -gt 46) {
        throw "Input title is too long."
    }

    $Result = ""
    $Result += "+------+------------------------------------------------+------+`r`n"
    $Result += "| TEST | $Title$(' '*(46 - $Title.Length)) | $($Type.ToUpper()) |`r`n"
    $Result += "+------+------------------------------------------------+------+`r`n"
    Split-Note -Note $Note | ForEach-Object {
        $Result += "| $(if ($Flag) { '    ' } else { 'DESC'; $Flag = $True }) | $($_)$(' '*(53 - ([string]$_).Length)) |`r`n"
    }
    $Result += "+------+-------------------------------------------------------+"
    $Result
}

function Invoke-PrivescCheck {

    [CmdletBinding()] param()

    ### This check was taken from PowerUp.ps1
    # https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if($IsAdmin){
        "[+] Current user already has local administrative privileges! Safely exiting."
        Write-Host
        # We don't want to continue, otherwise the script will identify almost everything as 
        # exploitable and thus generate a loooot of output. 
        return
    }

    Write-Banner -Category "user" -Name "whoami" -Type Info -Note "What's my username / SID?"
    $Results = Invoke-UserCheck
    if ($Results) {
        "[*] Found some info:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "whoami /groups" -Type Conf -Note "Do I belong to any interesting group(s)? Additional groups give you additional privileges. Default groups are filtered out."
    $Results = Invoke-UserGroupsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) non-default group(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "whoami /priv" -Type Conf -Note "Do I have any interesting privilege(s)? Privileges such as SeImpersonate or SeAssignPrimaryToken might allow you to run code as SYSTEM."
    $Results = Invoke-UserPrivilegesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) potentially interesting privilege(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "Environment Variables" -Type Conf -Note "Environment variables may contain some sensitive information."
    $Results = Invoke-UserEnvCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) potentially interesting result(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Non-default Services" -Type Info -Note "Is there any non-default / third-party service?"
    $Results = Invoke-InstalledServicesCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] Found $(([object[]]$Results).Length) service(s)."
        $Results | Select-Object -Property Name,DisplayName | Format-Table
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Service Permissions" -Type Vuln -Note "Can we modify the configuration of any service through the Service Control Manager? (sc.exe config VulnService binpath= C:\Temp\evil.exe)"
    $Results = Invoke-ServicesPermissionsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) vulnerable service(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Service Permissions (Registry)" -Type Vuln -Note "Can we modify the configuration of any service in the Registry? (reg.exe add HKLM\[...]\Services\VulnService /v ImagePath /d C:\Temp\evil.exe /f)"
    $Results = Invoke-ServicesPermissionsRegistryCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"
    
    Write-Banner -Category "services" -Name "Service Binary Permissions" -Type Vuln -Note "Can we modify the executable itself or can we somehow control one of its arguments? (copy C:\Temp\evil.exe C:\APPS\MyCustomApp\service.exe)"
    $Results = Invoke-ServicesImagePermissionsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Unquoted Paths" -Type Vuln -Note "Can we hijack any service by planting a binary in one of the executable parent folders? (C:\APPS\Foo Bar\service.exe -> copy C:\Temp\evil.exe C:\APPS\Foo.exe)"
    $Results = Invoke-ServicesUnquotedPathCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "DLL Hijacking" -Name "System's %PATH%" -Type Vuln -Note "Do we have write permissions in at least one of the system's %PATH% folders?"
    $Results = Invoke-DllHijackingCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "DLL Hijacking" -Name "Hijackable DLLs" -Type Info -Note "Which known DLLs can we potentially hijack on this version Windows?"
    $Results = Invoke-HijackableDllsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Non-default Applications" -Type Info -Note "Is there any non-default / third-party software we could exploit?"
    $Results = Invoke-InstalledProgramsCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) non-default application(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"
    
    Write-Banner -Category "Applications" -Name "Modifiable Applications" -Type Vuln -Note "Do we have write permissions in non-default application folders? If so, we may compromise other user accounts by planting a malicious EXE or DLL."
    $Results = Invoke-ModifiableProgramsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) file(s)."
        $Results | Format-Table
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Programs Run on Startup" -Type Info -Note "Which applications run automatically on startup?"
    $Results = Invoke-ApplicationsOnStartupCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) application(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Scheduled Tasks" -Type Vuln -Note "Can we modify the executable used by a scheduled task? If you want to list all the scheduled tasks, use the command 'Invoke-ScheduledTasksCheck' whith no args."
    $Results = Invoke-ScheduledTasksCheck -Filtered
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Running Processes" -Type Info -Note "Among the processes that are not owned by the current user, is there anything interesting? In this check, typical windows processes such as 'svchost.exe' are filtered out."
    $Results = Invoke-RunningProcessCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) process(es)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "SAM/SYSTEM Backup Files" -Type Vuln -Note "Is there any backup of the SAM/SYSTEM hives we can read?"
    $Results = Invoke-SamBackupFilesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) readable file(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Unattended Files" -Type Vuln -Note "Is there any Unattend file? Do they contain cleartext credentials?"
    $Results = Invoke-UnattendFilesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) password(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "WinLogon" -Type Vuln -Note "Does the Winlogon registry key contain any cleartext password? Entries with an empty password field are filtered out."
    $Results = Invoke-WinlogonCheck
    if ($Results) {
        "[*] Found some info:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Files" -Type Info -Note "Does the current user have any saved credentials?"
    $Results = Invoke-CredentialFilesCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) file(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Manager" -Type Info -Note "Is there any credentials saved in the Credential Manager? vault::cred"
    $Results = Invoke-VaultCredCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Manager (web)" -Type Info -Note "Is there any web credentials saved in the Credential Manager? vault::list"
    $Results = Invoke-VaultListCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "GPP Passwords" -Type Vuln -Note "Is there any cached GPP containing a 'cpassword'?"
    $Results = Invoke-GPPPasswordCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) credential(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Registry" -Name "UAC Settings" -Type Conf -Note "Is User Access Control enabled?"
    $Results = Invoke-UacCheck
    if ($Results) {
        "[*] UAC status:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "LSA RunAsPPL" -Type Conf -Note "Is lsass running as a Protected Process?"
    $Results = Invoke-LsaProtectionsCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Registry" -Name "LAPS Settings" -Type Conf -Note "Is the `"Local Administrator Password Solution`" enabled?"
    $Results = Invoke-LapsCheck
    if ($Results) {
        "[*] LAPS status:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "PowerShell Transcription" -Type Conf -Note "Is PowerShell Transcription enabled or even configured?"
    $Results = Invoke-PowershellTranscriptionCheck
    if ($Results) {
        "[*] PowerShell Transcription is configured (and enabled?)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "AlwaysInstallElevated" -Type Conf -Note "Is the 'AlwaysInstallElevated' registry key enabled?"
    $Results = Invoke-RegistryAlwaysInstallElevatedCheck
    if ($Results) {
        "[+] AlwaysInstallElevated is enabled."
        $Result | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "WSUS Configuration" -Type Conf -Note "Is WSUS configured/enabled? If so, check whether it's vulnerable to the 'Wsuxploit' MITM attack (https://github.com/pimps/wsuxploit)."
    $Results = Invoke-WsusConfigCheck
    if ($Results) {
        "[*] Found some info."
        $Result | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Network" -Name "TCP Endpoints" -Type Info -Note "Is there any interesting/unusual service? Default ports such as 445 are filtered out."    
    $Results = Invoke-TcpEndpointsCheck #$Results = Invoke-TcpEndpointsCheck -Filtered
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) TCP endpoints."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Network" -Name "UDP Endpoints" -Type Info -Note "Is there any interesting/unusual service? Showing all listening UDP endpoints (except DNS)."
    $Results = Invoke-UdpEndpointsCheck #$Results = Invoke-UdpEndpointsCheck -Filtered
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) UDP endpoints."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Network" -Name "Saved Wifi Profiles" -Type Info -Note "Can we extract any saved WEP key or PSK passphrase?"
    $Results = Invoke-WlanProfilesCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) saved Wifi profiles."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Last Windows Update Date" -Type Info -Note "Has the OS been updated lately? If the last update is more than 1 month old, we might be able to use some public exploits."
    $Results = Invoke-WindowsUpdateCheck 
    if ($Results) {
        "[*] Last update time:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "OS Version" -Type Info -Note "What is the exact version number of the system? If we can't get the last system update date and time, this can be useful."
    $Results = Invoke-SystemInfoCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Local Admin Group" -Type Info -Note "Who is a member of the local administator group? It might be useful to know which user account we could try to compromise next."
    $Results = Invoke-LocalAdminGroupCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] The default local admin group has $(([object[]]$Results).Length) member(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Misc" -Name "User Home Folders" -Type Conf -Note "Do we have R/W access to any other home folder?"
    $Results = Invoke-UsersHomeFolderCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found"
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Machine Role" -Type Info -Note "Is it a Workstation / Server / Domain Controller?"
    $Results = Invoke-MachineRoleCheck 
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found"
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "System Startup History" -Type Info -Note "Can we extract the startup history from the Event Log?"
    $Results = Invoke-SystemStartupHistoryCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] Found $(([object[]]$Results).Length) startup event(s) in the last 31 days."
        "[*] Last startup time was: $(([object[]]$Results)[0].Time)"
        $Results | Select-Object -First 10 | Format-Table
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Last System Startup" -Type Info -Note "Can we calculate the last system startup date based on the current tick count? /!\ This might be unreliable."
    $Results = Invoke-SystemStartupCheck
    if ($Results) {
        "[*] Last startup event time:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Filesystem Drives" -Type Info -Note "Is there any other partition or mapped share?"
    $Results = Invoke-SystemDrivesCheck
    "[*] Found $(([object[]]$Results).Length) drive(s)."
    $Results | Format-Table -AutoSize

    "`r`n"
}
#endregion Main

# ===========================================================================
# RUNNER — Invoke-PrivescCheckColor
# Calls the embedded Invoke-PrivescCheck engine and re-emits every output
# line with ANSI severity coloring.
# ===========================================================================

function Invoke-PrivescCheckColor {
    [CmdletBinding()]
    param(
        [switch]$Extended,
        [switch]$Audit,
        [switch]$Experimental,
        [switch]$Risky,
        [switch]$Force,
        [string]$Report         = "",
        [string]$Format         = "",
        [switch]$NoColor,
        [switch]$NoLogo,
        [ValidateSet("High","Medium","Low","Info","None")]
        [string]$SeverityFilter = "None"
    )

    # Allow overrides at call-time
    if ($NoColor) { $script:ColorEnabled = $false }
    if ($PSBoundParameters.ContainsKey("SeverityFilter")) {
        $script:FilterRank = $script:SevMap[$SeverityFilter].Rank
        if ($null -eq $script:FilterRank) { $script:FilterRank = 0 }
    }

    Write-Header

    $script:AllResults = @()

    # Capture ALL output from Invoke-PrivescCheck (pipeline + Write-Host via redirect)
    # Strategy: redirect 4>&1 (Information stream) + capture pipeline output
    # Write-Banner is already overridden in GLOBAL scope above.
    # For the output lines ([+]/[*]/[!] + table rows) we capture the pipeline.

    $ip = @{}
    if ($Extended)     { $ip["Extended"]     = $true }
    if ($Audit)        { $ip["Audit"]        = $true }
    if ($Experimental) { $ip["Experimental"] = $true }
    if ($Risky)        { $ip["Risky"]        = $true }
    if ($Force)        { $ip["Force"]        = $true }

    # PrivescCheck writes via both pipeline (strings) and Write-Host.
    # We capture pipeline; Write-Banner/Header are already overridden.
    # Pipe all output through our colorizer line by line.
    try {
        Invoke-PrivescCheck @ip | ForEach-Object {
            $line = "$_"
            ColorLine -Line $line
        }
    } catch {
        cw "  [!] Scan error: $_" "Red"
    }

    Write-Summary
}

# ===========================================================================
# AUTO-RUN when executed directly (not dot-sourced)
# ===========================================================================
$_myInv = $MyInvocation.InvocationName
if ($_myInv -ne "." -and $MyInvocation.Line -notmatch "^\s*\.[\s]") {
    $p = @{}
    if ($Extended)                          { $p["Extended"]       = $true }
    if ($Audit)                             { $p["Audit"]          = $true }
    if ($Experimental)                      { $p["Experimental"]   = $true }
    if ($Risky)                             { $p["Risky"]          = $true }
    if ($Force)                             { $p["Force"]          = $true }
    if ($Report -ne "")                     { $p["Report"]         = $Report }
    if ($Format -ne "")                     { $p["Format"]         = $Format }
    if ($NoColor)                           { $p["NoColor"]        = $true }
    if ($NoLogo)                            { $p["NoLogo"]         = $true }
    if ($SeverityFilter -ne "None")         { $p["SeverityFilter"] = $SeverityFilter }
    Invoke-PrivescCheckColor @p
}
