#Requires -Version 5.1
<#
.SYNOPSIS
    Manages the pool of secondary IPv4 addresses that give DNS Load Forge many
    distinct source IPs, so a DNS filtering appliance sees ~N real clients
    instead of one.

.DESCRIPTION
    A DNS filtering appliance identifies a client by source IP. Testing one with
    a single host therefore only ever exercises policy for one client, no matter
    how much traffic you throw at it. This script adds a block of secondary IPv4
    addresses to a dedicated lab interface; the Python load engine then binds its
    sockets to those addresses so each simulated "office worker" presents a
    different source IP on the wire.

    Every address is added with -SkipAsSource $true. That flag is the whole
    reason this works: it marks the address as never-selected for outbound
    connections, so Windows will not use these addresses as the source for the
    host's normal traffic or re-elect a default source address while the pool is
    in place. A socket only uses one if it explicitly binds to it.

    The script is idempotent and reversible: re-running it skips addresses that
    already exist, and -Remove deletes exactly the addresses inside the computed
    range and nothing else.

    DELIBERATELY OUT OF SCOPE: this script never touches DNS servers, the
    default gateway, the interface metric, or any interface other than the one
    named in -InterfaceAlias. Adding a gateway or resolver change here would
    risk cutting the host off, which is not something a traffic generator should
    ever be able to do.

.PARAMETER InterfaceAlias
    Name of the target interface, exactly as shown by Get-NetAdapter. Must be a
    dedicated lab segment. Wi-Fi and down interfaces are refused unless -Force.

.PARAMETER Start
    First address of the inclusive range, e.g. 10.1.50.10.

.PARAMETER End
    Last address of the inclusive range, e.g. 10.1.50.250.

.PARAMETER PrefixLength
    Prefix length applied to each address. Default 24, which must match the lab
    segment or the addresses will not be on-link.

.PARAMETER Remove
    Removes the addresses in the range instead of adding them.

.PARAMETER Max
    Safety ceiling on how many addresses one invocation may manage. Default
    1024.

.PARAMETER OutputFile
    Writes the managed addresses, one per line in ascending order, to this file.
    This is what the Python engine consumes via --source-ips-file.

.PARAMETER Force
    Permits operating on a Wi-Fi interface or an interface that is not Up.
    Required for wireless, because adding hundreds of addresses to a wireless
    NIC will typically break the host's connectivity.

.INPUTS
    None.

.OUTPUTS
    System.Management.Automation.PSCustomObject. A summary object with the
    counts of requested, added, removed, skipped and failed addresses, so the
    script is usable in a pipeline.

.EXAMPLE
    .\New-LabSourceIPs.ps1 -InterfaceAlias 'Ethernet 2' -Start 10.1.50.10 -End 10.1.50.250 -OutputFile .\sources.txt

    Adds 241 addresses to the lab interface and writes the list for the engine.

.EXAMPLE
    .\New-LabSourceIPs.ps1 -InterfaceAlias 'Ethernet 2' -Start 10.1.50.10 -End 10.1.50.250 -Remove -WhatIf

    Shows what the teardown would remove without changing anything.

.NOTES
    Author:      Zach Snow
    Part of:     DNS Load Forge (see ..\README.md)
    License:     MIT
    Requires:    Local administrator, NetTCPIP module, Windows 8 / Server 2012 or later.

.RESTRICTIONS
    - Modifies host network configuration.
    - Requires elevation; never run unattended against a production segment
    - Only ever targets the interface named in -InterfaceAlias
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$InterfaceAlias,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($_, [ref]$parsed)) {
            throw "'$_' is not a valid IP address."
        }
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "'$_' is not an IPv4 address. Only IPv4 pools are supported."
        }
        $true
    })]
    [string]$Start,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($_, [ref]$parsed)) {
            throw "'$_' is not a valid IP address."
        }
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "'$_' is not an IPv4 address. Only IPv4 pools are supported."
        }
        $true
    })]
    [string]$End,

    [ValidateRange(1, 32)]
    [int]$PrefixLength = 24,

    [switch]$Remove,

    [ValidateRange(1, 8192)]
    [int]$Max = 1024,

    [string]$OutputFile,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# LOGGING: $env:ProgramData\DnsLoadForge\Logs\<ScriptName>\<ScriptName>_<stamp>.log
# Logging is best-effort: on a locked-down or non-administrator session we fall
# back to console output rather than failing the run over a log file.
# ---------------------------------------------------------------------------
$script:LogFile = $null

function Initialize-LogFile {
    [CmdletBinding()]
    param()

    $scriptName = if ($PSCommandPath) {
        [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    } else {
        'New-LabSourceIPs'
    }

    try {
        $folder = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath 'DnsLoadForge\Logs') -ChildPath $scriptName
        if (-not (Test-Path -LiteralPath $folder)) {
            New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $script:LogFile = Join-Path -Path $folder -ChildPath ('{0}_{1}.log' -f $scriptName, $stamp)
    } catch {
        $script:LogFile = $null
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        } catch {
            # Console output already happened; losing a log line is not fatal.
        }
    }
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
function Test-IsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-IPv4UInt32 {
    <#
        IPv4 <-> UInt32, used to enumerate a range. GetAddressBytes returns a
        fresh array, so reversing it here cannot corrupt the IPAddress object.
    #>
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]$Address
    )

    $bytes = $Address.GetAddressBytes()
    [array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-IPv4UInt32 {
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Value
    )

    $bytes = [System.BitConverter]::GetBytes($Value)
    [array]::Reverse($bytes)
    return [System.Net.IPAddress]::new($bytes)
}

# ---------------------------------------------------------------------------
# PREFLIGHT
# ---------------------------------------------------------------------------
Initialize-LogFile

Write-Log -Message ('{0} - started. User: {1} Host: {2}' -f $PSCommandPath, ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name), $env:COMPUTERNAME)
Write-Log -Message ('Action: {0}  Interface: {1}  Range: {2} - {3}  PrefixLength: {4}' -f $(if ($Remove) { 'Remove' } else { 'Add' }), $InterfaceAlias, $Start, $End, $PrefixLength)

if (-not (Test-IsElevated)) {
    $message = @(
        'This script must run elevated: adding or removing IP addresses requires administrator rights.'
        'Close this window and relaunch an elevated session, e.g.:'
        "    Start-Process pwsh -Verb RunAs -ArgumentList '-NoExit', '-File', '$PSCommandPath'"
    ) -join [Environment]::NewLine
    throw $message
}

foreach ($requiredCommand in @('Get-NetAdapter', 'Get-NetIPAddress', 'New-NetIPAddress', 'Remove-NetIPAddress')) {
    if (-not (Get-Command -Name $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "Required cmdlet '$requiredCommand' was not found. The NetTCPIP module is required; this script only runs on Windows."
    }
}

# Confirm the interface exists and is safe to touch.
try {
    $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} catch {
    $available = (Get-NetAdapter | Select-Object -ExpandProperty Name) -join ', '
    throw "Interface '$InterfaceAlias' was not found. Available interfaces: $available"
}

if ($adapter.Status -ne 'Up' -and -not $Force) {
    throw "Interface '$InterfaceAlias' is in state '$($adapter.Status)', not 'Up'. Bring it up first, or pass -Force to override."
}

if ($adapter.Name -match '(?i)wi-?fi|wlan|wireless') {
    if (-not $Force) {
        throw @(
            "Refusing to add a source-IP pool to wireless interface '$($adapter.Name)'."
            'Adding hundreds of secondary addresses to a wireless NIC disrupts the host: the driver and'
            'the access point cannot handle the extra ARP/ND entries reliably and connectivity usually drops.'
            'Use a dedicated wired or virtual adapter on the lab segment, or pass -Force if you accept the risk.'
        ) -join ' '
    }
    Write-Log -Level WARNING -Message "Proceeding on wireless interface '$($adapter.Name)' because -Force was specified. Expect connectivity disruption."
}

# ---------------------------------------------------------------------------
# BUILD THE ADDRESS RANGE
# ---------------------------------------------------------------------------
$startUint = ConvertTo-IPv4UInt32 -Address ([System.Net.IPAddress]::Parse($Start))
$endUint = ConvertTo-IPv4UInt32 -Address ([System.Net.IPAddress]::Parse($End))

if ($endUint -lt $startUint) {
    throw "-Start ($Start) is greater than -End ($End). The range must be ascending."
}

$rangeSize = [int]($endUint - $startUint + 1)

if ($rangeSize -gt $Max) {
    throw @(
        "Range $Start-$End contains $rangeSize addresses, which exceeds the -Max ceiling of $Max."
        'That ceiling exists on purpose. A real 10,000-seat office is simulated as 10,000 logical personas'
        'sharing a much smaller pool of source IPs: the persona model provides the traffic mix and per-client'
        'behaviour, while the appliance only ever needs enough distinct addresses to exercise its per-client'
        'policy paths. Pushing tens of thousands of secondary addresses onto one Windows NIC is slow to apply,'
        'bloats the ARP/neighbour table and degrades the host, with no extra test value. Raise -Max explicitly'
        'if you have measured a reason to go further.'
    ) -join ' '
}

# Reject ranges that can never carry a usable source-IP pool. A typo here is
# otherwise only caught one failing address at a time, after the NIC has already
# been touched. 0.0.0.0/8 is "this network", 127/8 is loopback, 169.254/16 is
# the APIPA block a host with no DHCP already owns, and 224/4 upward is
# multicast and broadcast.
$reservedBlocks = @(
    @{ Name = '0.0.0.0/8'; Network = '0.0.0.0'; Mask = '255.0.0.0' },
    @{ Name = '127.0.0.0/8'; Network = '127.0.0.0'; Mask = '255.0.0.0' },
    @{ Name = '169.254.0.0/16'; Network = '169.254.0.0'; Mask = '255.255.0.0' },
    @{ Name = '224.0.0.0/4'; Network = '224.0.0.0'; Mask = '240.0.0.0' }
)

foreach ($block in $reservedBlocks) {
    $networkUint = ConvertTo-IPv4UInt32 -Address ([System.Net.IPAddress]::Parse($block.Network))
    $maskUint = ConvertTo-IPv4UInt32 -Address ([System.Net.IPAddress]::Parse($block.Mask))
    if ((($startUint -band $maskUint) -eq $networkUint) -or (($endUint -band $maskUint) -eq $networkUint)) {
        throw "Range $Start-$End overlaps the reserved block $($block.Name), which cannot be used as a source-IP pool."
    }
}

$addresses = [System.Collections.Generic.List[string]]::new()
for ($value = $startUint; $value -le $endUint; $value++) {
    $addresses.Add((ConvertFrom-IPv4UInt32 -Value ([uint32]$value)).ToString())
}

Write-Verbose "Range expands to $($addresses.Count) address(es)."

# ---------------------------------------------------------------------------
# SNAPSHOT EXISTING ADDRESSES (one query, compared in memory -- not per address)
# ---------------------------------------------------------------------------
$existingAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$currentOnInterface = @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
foreach ($current in $currentOnInterface) {
    [void]$existingAddresses.Add([string]$current.IPAddress)
}

Write-Verbose "Interface '$InterfaceAlias' currently holds $($existingAddresses.Count) IPv4 address(es)."

# ---------------------------------------------------------------------------
# APPLY
# ---------------------------------------------------------------------------
$added = [System.Collections.Generic.List[string]]::new()
$removed = [System.Collections.Generic.List[string]]::new()
$skipped = [System.Collections.Generic.List[string]]::new()
$failed = [System.Collections.Generic.List[object]]::new()

foreach ($address in $addresses) {
    $present = $existingAddresses.Contains($address)

    if ($Remove) {
        if (-not $present) {
            $skipped.Add($address)
            continue
        }

        if ($PSCmdlet.ShouldProcess("$InterfaceAlias : $address", 'Remove IP address')) {
            try {
                Remove-NetIPAddress -IPAddress $address -InterfaceAlias $InterfaceAlias -Confirm:$false -ErrorAction Stop
                $removed.Add($address)
            } catch {
                $failed.Add([pscustomobject]@{ Address = $address; Error = $_.Exception.Message })
            }
        }
        continue
    }

    if ($present) {
        $skipped.Add($address)
        continue
    }

    if ($PSCmdlet.ShouldProcess("$InterfaceAlias : $address", 'Add IP address (SkipAsSource)')) {
        try {
            # -SkipAsSource marks the address as never-collected for outbound
            # source selection. Without it, Windows may re-elect a default source
            # address and the host's own traffic would start leaving from a pool
            # address. No -DefaultGateway is ever passed: the pool must not alter
            # routing.
            New-NetIPAddress -InterfaceAlias $InterfaceAlias `
                -IPAddress $address `
                -PrefixLength $PrefixLength `
                -SkipAsSource $true `
                -ErrorAction Stop | Out-Null
            $added.Add($address)
        } catch {
            $failed.Add([pscustomobject]@{ Address = $address; Error = $_.Exception.Message })
        }
    }
}

# ---------------------------------------------------------------------------
# VERIFY
# ---------------------------------------------------------------------------
$verifySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($after in @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    [void]$verifySet.Add([string]$after.IPAddress)
}

$verified = [System.Collections.Generic.List[string]]::new()
foreach ($address in $addresses) {
    if ($verifySet.Contains($address)) {
        $verified.Add($address)
    }
}

# ---------------------------------------------------------------------------
# OUTPUT FILE
# ---------------------------------------------------------------------------
$resolvedOutputFile = $null
if ($OutputFile) {
    $resolvedOutputFile = $OutputFile
    if (-not [System.IO.Path]::IsPathRooted($resolvedOutputFile)) {
        $resolvedOutputFile = Join-Path -Path (Get-Location).ProviderPath -ChildPath $resolvedOutputFile
    }

    # The engine wants the addresses it should bind, so write what is actually
    # present on the interface in this range rather than what we attempted.
    $toWrite = @()
    if ($Remove) {
        $toWrite = @($addresses | Where-Object { $verifySet.Contains($_) })
    } else {
        $toWrite = @($verified)
    }

    $parentFolder = Split-Path -Path $resolvedOutputFile -Parent
    if ($parentFolder -and -not (Test-Path -LiteralPath $parentFolder)) {
        New-Item -Path $parentFolder -ItemType Directory -Force | Out-Null
    }

    Set-Content -LiteralPath $resolvedOutputFile -Value $toWrite -Encoding ASCII
    Write-Log -Message "Wrote $($toWrite.Count) address(es) to $resolvedOutputFile"
}

# A pool is only useful if the addresses really are contiguous on one segment.
# Catching a typo'd range here is far cheaper than debugging odd resolver
# behaviour later, when half the pool is off-link.
$firstOctet = ([System.Net.IPAddress]::Parse($Start)).GetAddressBytes()[0]
$crossesBoundary = @($addresses | Where-Object {
        ([System.Net.IPAddress]::Parse($_)).GetAddressBytes()[0] -ne $firstOctet
    })
if ($crossesBoundary.Count -gt 0) {
    Write-Log -Level WARNING -Message "$($crossesBoundary.Count) address(es) in this range cross a /8 boundary from $Start. Verify the range is the intended lab segment."
}

Write-Log -Message ('Summary: requested {0}, added {1}, removed {2}, skipped {3}, failed {4}' -f $rangeSize, $added.Count, $removed.Count, $skipped.Count, $failed.Count)

if ($failed.Count -gt 0) {
    foreach ($failure in $failed) {
        Write-Log -Level ERROR -Message ('  FAILED {0}: {1}' -f $failure.Address, $failure.Error)
    }
    Write-Log -Level WARNING -Message 'Some addresses failed. Check the log for details; the summary object reports the count.'
}

Write-Log -Level SUCCESS -Message 'New-LabSourceIPs.ps1 - completed.'

# ---------------------------------------------------------------------------
# SUMMARY OBJECT (pipeline-friendly)
# ---------------------------------------------------------------------------
[pscustomobject]@{
    InterfaceAlias = $InterfaceAlias
    Action         = if ($Remove) { 'Remove' } else { 'Add' }
    PrefixLength   = $PrefixLength
    FirstAddress   = $Start
    LastAddress    = $End
    Requested      = $rangeSize
    Added          = $added.Count
    Removed        = $removed.Count
    Skipped        = $skipped.Count
    Failed         = $failed.Count
    PresentOnNIC   = $verified.Count
    OutputFile     = $resolvedOutputFile
    Failures       = $failed
    LogFile        = $script:LogFile
}
