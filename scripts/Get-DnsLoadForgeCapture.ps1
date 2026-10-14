#Requires -Version 5.1
<#
.SYNOPSIS
    Wire-side verification for DNS Load Forge using the built-in pktmon tool.

.DESCRIPTION
    The load engine already knows what it *tried* to send. That is not the same
    as what actually left the NIC: a saturated socket buffer, a backed-up send
    queue or a driver dropping frames will quietly reduce the offered load, and
    the generator's own statistics cannot see any of it. This script captures
    port 53 traffic at the NIC with pktmon, converts it to pcapng, and compares
    the queries really seen on the wire against the engine's sender log.

    pktmon is used deliberately: it ships with Windows and needs no third-party
    driver. Npcap is NOT installed on this host, and installing a capture driver
    on a machine used for filtering-appliance testing is an unnecessary risk.
    tshark is used only if it happens to be present; the packet counting here is
    done by parsing the pcapng directly, so no Wireshark install is required.

    IMPORTANT -- pktmon runs on ETW and adds measurable per-packet overhead. Use
    it for spot-check runs at a modest query rate to validate the generator, not
    for a full 10,000-persona soak test, where the capture itself becomes the
    bottleneck and distorts the very numbers you are trying to verify.

    The capture is filtered to the DNS port. On Windows the filter is applied to
    the whole NIC, so if other hosts share this segment their port 53 traffic is
    captured too -- the reconciliation step compares counts, so run the capture
    on an isolated lab segment or interpret the delta accordingly.

.PARAMETER Server
    The DNS filtering appliance under test, by IP or hostname. Used to label the
    capture and to attempt an address-scoped filter.

.PARAMETER Port
    DNS port to capture. Default 53. Both UDP and TCP are filtered, because a
    truncated UDP answer is retried over TCP and that path often behaves
    differently on a filtering appliance.

.PARAMETER Action
    Start     - clear stale filters, install DNS filters, begin capturing.
    Stop      - stop the capture, convert to pcapng, report the packet count.
    Convert   - convert an existing .etl in $OutputDirectory to pcapng.
    Status    - show installed filters, running state, and existing captures.
    Reconcile - compare captured queries against the engine's sender log.

.PARAMETER OutputDirectory
    Where .etl and .pcapng files are written. Defaults to .\captures beside this
    script.

.PARAMETER DurationSeconds
    When greater than zero, Start captures for this long and then stops and
    converts automatically. Zero captures until Stop is called.

.PARAMETER SenderLog
    The engine's exported CSV (recorded with --export) for Reconcile.

.PARAMETER CaptureFile
    Explicit .etl or .pcapng to use for Convert and Reconcile. Defaults to the
    newest matching file in $OutputDirectory.

.PARAMETER Force
    Overrides the guard that refuses to start a second capture while one is
    already running.

.INPUTS
    None.

.OUTPUTS
    System.Management.Automation.PSCustomObject. A summary object describing the
    action taken and, for Reconcile, the compared counts.

.EXAMPLE
    .\Get-DnsLoadForgeCapture.ps1 -Server 10.1.106.5 -Action Start -DurationSeconds 60

    Captures 60 seconds of DNS traffic to and from the appliance, then stops and
    converts automatically.

.EXAMPLE
    .\Get-DnsLoadForgeCapture.ps1 -Server 10.1.106.5 -Action Reconcile -SenderLog .\run1.csv

    Compares the on-wire query count against the generator's log and explains any
    shortfall.

.NOTES
    Author:      Zach Snow
    Part of:     DNS Load Forge (see ..\README.md)
    License:     MIT
    Requires:    Local administrator for Start/Stop/Convert/Status. Reconcile
                 needs no privilege because it only reads a file.

.RESTRICTIONS
    - Captures and parses live network traffic. Only run it on networks you own
      or are authorised to monitor.
    - Capture files contain internal hostnames, IP addresses and queried domains.
      They must not be committed to source control or shared publicly.
      DnsLoadForge\.gitignore already excludes the captures directory; keep it
      that way.
    - Never leave a capture running: always finish with -Action Stop.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [ValidateRange(1, 65535)]
    [int]$Port = 53,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Stop', 'Convert', 'Status', 'Reconcile')]
    [string]$Action,

    [string]$OutputDirectory,

    [ValidateRange(0, 86400)]
    [int]$DurationSeconds = 0,

    [string]$SenderLog,

    [string]$CaptureFile,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# LOGGING: $env:ProgramData\DnsLoadForge\Logs\<ScriptName>\<ScriptName>_<stamp>.log
# ---------------------------------------------------------------------------
$script:LogFile = $null

function Initialize-LogFile {
    [CmdletBinding()]
    param()

    $scriptName = if ($PSCommandPath) {
        [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    } else {
        'Get-DnsLoadForgeCapture'
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

        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'DEBUG' { Write-Verbose $line }
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

function Test-IsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# PKTMON WRAPPER
# ---------------------------------------------------------------------------
function Resolve-PktMonPath {
    <#
        pktmon.exe is in %SystemRoot%\System32 on Windows 10 1809+ / Server 2019+.
        If it is missing, the host is too old or the component has been removed -
        both are worth a clear error rather than a cryptic one.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $command = Get-Command -Name 'pktmon.exe' -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $fallback = Join-Path -Path $env:SystemRoot -ChildPath 'System32\PktMon.exe'
    if (Test-Path -LiteralPath $fallback) {
        return $fallback
    }

    throw @(
        'pktmon.exe was not found. It ships with Windows 10 1809 / Server 2019 and later.'
        'Check that this host meets that baseline, or use a Wireshark/npcap-based capture instead.'
    ) -join ' '
}

function Invoke-PktMon {
    <#
        Runs pktmon with an argument array (never a joined string, so paths with
        spaces cannot be mis-parsed) and returns the exit code plus all output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    $commandLine = 'pktmon ' + ($ArgumentList -join ' ')
    Write-Verbose $commandLine

    $output = & $script:PktMonPath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE

    return [pscustomobject]@{
        CommandLine = $commandLine
        ExitCode    = $exitCode
        Succeeded   = ($exitCode -eq 0)
        Output      = @($output)
    }
}

function Test-PktMonRunning {
    <#
        pktmon keeps a process alive for the duration of a capture, which is the
        most reliable "is a capture running" signal available without a
        privileged query.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $process = Get-Process -Name 'PktMon' -ErrorAction SilentlyContinue
    return ($null -ne $process)
}

function Remove-PktMonFilters {
    <#
        `pktmon filter remove` with no argument clears every filter on the
        system. That is intentional here -- we always install our own filter set
        immediately afterwards -- but it does mean this script will not coexist
        with another capture-filter author on the same host.
    #>
    [CmdletBinding()]
    param()

    $result = Invoke-PktMon -ArgumentList @('filter', 'remove')
    if (-not $result.Succeeded) {
        Write-Verbose ('filter remove returned {0}: {1}' -f $result.ExitCode, ($result.Output -join ' '))
    }
    return $result
}

function Add-PktMonDnsFilters {
    <#
        Installs the capture filters: UDP and TCP on the DNS port.

        A note on syntax, because it cost real debugging time: pktmon's filter
        switches have varied between builds, and a wrong flag fails silently
        enough to be confusing. Every invocation below is checked, and on failure
        the real output is surfaced with a pointer to `pktmon filter add --help`
        instead of pretending the filter was installed.
    #>
    [CmdletBinding()]
    param()

    $installed = [System.Collections.Generic.List[string]]::new()

    $udpFilter = Invoke-PktMon -ArgumentList @('filter', 'add', 'DnsLoadForge-UDP', '-t', 'UDP', '-p', "$Port")
    if ($udpFilter.Succeeded) {
        $installed.Add('DnsLoadForge-UDP (UDP/$Port)')
    } else {
        Write-Log -Level ERROR -Message ('Failed to add UDP filter: {0}' -f ($udpFilter.Output -join ' '))
        Write-Log -Level WARNING -Message 'Run `pktmon filter add --help` on this host to confirm the flag syntax for this build of pktmon.'
    }

    # The server-scoped filter narrows the capture to the appliance. A pktmon
    # address filter needs a literal IP, so resolve a hostname first.
    $serverAddress = $null
    $parsedServer = $null
    if ([System.Net.IPAddress]::TryParse($Server, [ref]$parsedServer)) {
        $serverAddress = $parsedServer.ToString()
    } else {
        try {
            $serverAddress = [System.Net.Dns]::GetHostAddresses($Server) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -First 1 -ExpandProperty IPAddressToString
        } catch {
            Write-Log -Level WARNING -Message "Could not resolve '$Server' to an IPv4 address; the capture will not be scoped to the appliance."
        }
    }

    # If this build of pktmon rejects the address flag, the port-only filters
    # above still make the capture useful, so a failure here is not fatal.
    if ($serverAddress) {
        $serverFilter = Invoke-PktMon -ArgumentList @('filter', 'add', 'DnsLoadForge-Appliance', '-t', 'UDP', '-p', "$Port", '-i', $serverAddress)
        if ($serverFilter.Succeeded) {
            $installed.Add("DnsLoadForge-Appliance (UDP/$Port to or from $serverAddress)")
        } else {
            Write-Verbose ('Address-scoped filter not applied: {0}' -f ($serverFilter.Output -join ' '))
            Write-Log -Level WARNING -Message "Could not scope the capture to $serverAddress; falling back to all DNS traffic on this interface."
        }
    }

    $tcpFilter = Invoke-PktMon -ArgumentList @('filter', 'add', 'DnsLoadForge-TCP', '-t', 'TCP', '-p', "$Port")
    if ($tcpFilter.Succeeded) {
        $installed.Add('DnsLoadForge-TCP (TCP/' + $Port + ')')
    } else {
        Write-Log -Level WARNING -Message ('Failed to add TCP filter: {0}' -f ($tcpFilter.Output -join ' '))
    }

    return $installed
}

# ---------------------------------------------------------------------------
# PCAPNG PARSING
# ---------------------------------------------------------------------------
function Read-ChunkUInt32 {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [bool]$LittleEndian
    )

    [byte[]]$slice = @($Buffer[$Offset], $Buffer[$Offset + 1], $Buffer[$Offset + 2], $Buffer[$Offset + 3])
    if (-not $LittleEndian) {
        [array]::Reverse($slice)
    }
    return [System.BitConverter]::ToUInt32($slice, 0)
}

function Read-ChunkUInt16 {
    [CmdletBinding()]
    [OutputType([uint16])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [bool]$LittleEndian
    )

    if ($LittleEndian) {
        return [System.BitConverter]::ToUInt16($Buffer, $Offset)
    }
    [byte[]]$slice = @($Buffer[$Offset], $Buffer[$Offset + 1])
    [array]::Reverse($slice)
    return [System.BitConverter]::ToUInt16($slice, 0)
}

function Get-DnsInfoFromFrame {
    <#
        Walks one captured frame down to the DNS header and reports whether it is
        a query or a response, plus the transaction ID. Only the link types
        pktmon's pcapng converter actually emits are handled; anything else is
        reported as unsupported rather than silently ignored.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [int]$Length,

        [Parameter(Mandatory = $true)]
        [int]$LinkType
    )

    $none = [pscustomobject]@{ IsDns = $false; IsQuery = $false; TransactionId = [uint32]0 }

    $available = [Math]::Min($Length, $Buffer.Length - $Offset)
    if ($available -lt 20) { return $none }

    $ipOffset = -1
    $isIpv6 = $false

    switch ($LinkType) {
        1 {
            # LINKTYPE_ETHERNET
            if ($available -lt 14) { return $none }
            $etherType = [uint16](([uint16]$Buffer[$Offset + 12] -shl 8) -bor $Buffer[$Offset + 13])
            $ipOffset = $Offset + 14
            if ($etherType -eq 0x8100) {
                # 802.1Q VLAN tag: 4 more bytes, then the real ethertype.
                if ($available -lt 18) { return $none }
                $etherType = [uint16](([uint16]$Buffer[$Offset + 16] -shl 8) -bor $Buffer[$Offset + 17])
                $ipOffset = $Offset + 18
            }
            switch ($etherType) {
                0x0800 { $isIpv6 = $false }
                0x86DD { $isIpv6 = $true }
                default { return $none }
            }
        }
        228 { $isIpv6 = $false; $ipOffset = $Offset }
        101 {
            if (([uint16]$Buffer[$Offset] -shr 4) -eq 6) { $isIpv6 = $true } else { $isIpv6 = $false }
            $ipOffset = $Offset
        }
        0 {
            # LINKTYPE_NULL: a 4-byte host-order address family, then the IP header.
            if ($available -lt 24) { return $none }
            $family = Read-ChunkUInt32 -Buffer $Buffer -Offset $Offset -LittleEndian $true
            $ipOffset = $Offset + 4
            if ($family -eq 2) { $isIpv6 = $false }
            elseif ($family -eq 24 -or $family -eq 28 -or $family -eq 30) { $isIpv6 = $true }
            else { return $none }
        }
        default { return $none }
    }

    $transport = 0
    $transportOffset = -1

    if ($isIpv6) {
        if ($available -lt ($ipOffset - $Offset) + 40) { return $none }
        if (([uint16]$Buffer[$ipOffset] -shr 4) -ne 6) { return $none }
        $transport = $Buffer[$ipOffset + 6]
        $transportOffset = $ipOffset + 40
    } else {
        if (($ipOffset - $Offset) + 20 -gt $available) { return $none }
        if (([uint16]$Buffer[$ipOffset] -shr 4) -ne 4) { return $none }
        $headerLength = ([int]($Buffer[$ipOffset] -band 0x0F)) * 4
        if ($headerLength -lt 20) { return $none }
        $transport = $Buffer[$ipOffset + 9]
        $transportOffset = $ipOffset + $headerLength
    }

    $dnsOffset = -1
    switch ($transport) {
        17 {
            if (($transportOffset - $Offset) + 8 -gt $available) { return $none }
            $sourcePort = [uint16](([uint16]$Buffer[$transportOffset] -shl 8) -bor $Buffer[$transportOffset + 1])
            $destPort = [uint16](([uint16]$Buffer[$transportOffset + 2] -shl 8) -bor $Buffer[$transportOffset + 3])
            if ($sourcePort -ne $Port -and $destPort -ne $Port) { return $none }
            $dnsOffset = $transportOffset + 8
        }
        6 {
            if (($transportOffset - $Offset) + 20 -gt $available) { return $none }
            $sourcePort = [uint16](([uint16]$Buffer[$transportOffset] -shl 8) -bor $Buffer[$transportOffset + 1])
            $destPort = [uint16](([uint16]$Buffer[$transportOffset + 2] -shl 8) -bor $Buffer[$transportOffset + 3])
            if ($sourcePort -ne $Port -and $destPort -ne $Port) { return $none }
            $tcpHeaderLength = ([int]($Buffer[$transportOffset + 12] -shr 4)) * 4
            if ($tcpHeaderLength -lt 20) { return $none }
            # DNS over TCP is length-prefixed with a 2-byte big-endian length.
            $dnsOffset = $transportOffset + $tcpHeaderLength + 2
        }
        default { return $none }
    }

    if (($dnsOffset - $Offset) + 12 -gt $available) { return $none }

    $transactionId = [uint32](([uint32]$Buffer[$dnsOffset] -shl 8) -bor $Buffer[$dnsOffset + 1])
    $dnsFlags = [uint16](([uint16]$Buffer[$dnsOffset + 2] -shl 8) -bor $Buffer[$dnsOffset + 3])
    $isResponse = ($dnsFlags -band 0x8000) -ne 0

    return [pscustomobject]@{
        IsDns         = $true
        IsQuery       = (-not $isResponse)
        TransactionId = $transactionId
    }
}

function Get-PcapngDnsStats {
    <#
        Streams a pcapng file and counts DNS queries and responses on the wire.

        This exists so the wire-side check does not depend on tshark being
        installed. It parses the pcapng block structure, the link-layer header,
        IPv4/IPv6 and UDP/TCP, then reads the DNS header -- enough to classify
        each packet as a query or a response and to collect transaction IDs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stats = [pscustomobject]@{
        Path              = $Path
        FileBytes         = 0
        TotalBlocks       = 0
        TotalPackets      = 0
        DnsPackets        = 0
        DnsQueries        = 0
        DnsResponses      = 0
        UniqueQueryIds    = 0
        FirstTimestamp    = $null
        LastTimestamp     = $null
        CaptureSeconds    = 0.0
        LinkType          = -1
        UnsupportedFrames = 0
        ParseError        = $null
    }

    $stats.FileBytes = (Get-Item -LiteralPath $Path).Length

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $littleEndian = $true
            $linkType = -1
            $timestampScale = 0.000001   # pcapng default resolution: microseconds
            $queryIds = [System.Collections.Generic.HashSet[uint32]]::new()
            $firstTimestamp = $null
            $lastTimestamp = $null

            while (($stream.Length - $stream.Position) -ge 12) {
                $blockStart = $stream.Position

                $typeBytes = $reader.ReadBytes(4)
                if ($typeBytes.Length -lt 4) { break }
                $lengthBytes = $reader.ReadBytes(4)
                if ($lengthBytes.Length -lt 4) { break }

                # The Section Header Block's type bytes are identical in either
                # byte order, so read its byte-order magic before interpreting
                # any length. Everything after that uses the section's order.
                $isSectionHeader = ($typeBytes[0] -eq 0x0A -and $typeBytes[1] -eq 0x0D -and $typeBytes[2] -eq 0x0D -and $typeBytes[3] -eq 0x0A)
                if ($isSectionHeader) {
                    $magic = $reader.ReadBytes(4)
                    if ($magic.Length -lt 4) { break }
                    if ($magic[0] -eq 0x4D -and $magic[1] -eq 0x3C -and $magic[2] -eq 0x2B -and $magic[3] -eq 0x1A) {
                        $littleEndian = $true
                    } elseif ($magic[0] -eq 0x1A -and $magic[1] -eq 0x2B -and $magic[2] -eq 0x3C -and $magic[3] -eq 0x4D) {
                        $littleEndian = $false
                    } else {
                        $stats.ParseError = 'Not a pcapng file: Section Header Block byte-order magic not found.'
                        break
                    }
                }

                $totalLength = Read-ChunkUInt32 -Buffer $lengthBytes -Offset 0 -LittleEndian $littleEndian
                if ($totalLength -lt 12) {
                    $stats.ParseError = "Truncated or corrupt block at offset $blockStart (length $totalLength)."
                    break
                }
                if (($blockStart + $totalLength) -gt $stream.Length) {
                    $stats.ParseError = "Block at offset $blockStart claims $totalLength bytes but the file ends early."
                    break
                }

                $stats.TotalBlocks++

                # Body length excludes the 4-byte type, 4-byte length and the
                # trailing repeated 4-byte length.
                $bodyLength = [int]$totalLength - 12
                $body = $null
                if ($bodyLength -gt 0) {
                    $body = $reader.ReadBytes($bodyLength)
                }

                # Block Type is written in the section's byte order, so decode it
                # with the order detected above instead of shifting raw bytes.
                $blockType = Read-ChunkUInt32 -Buffer $typeBytes -Offset 0 -LittleEndian $littleEndian
                switch ($blockType) {
                    1 {
                        if ($body -and $body.Length -ge 8) {
                            # Interface Description Block: LinkType (u16), Reserved (u16),
                            # SnapLen (u32), then options.
                            $linkType = [int](Read-ChunkUInt16 -Buffer $body -Offset 0 -LittleEndian $littleEndian)
                            $optionOffset = 8
                            while ($optionOffset + 4 -le $body.Length) {
                                $optionCode = [int](Read-ChunkUInt16 -Buffer $body -Offset $optionOffset -LittleEndian $littleEndian)
                                if ($optionCode -eq 0) { break }
                                $optionLength = [int](Read-ChunkUInt16 -Buffer $body -Offset ($optionOffset + 2) -LittleEndian $littleEndian)
                                $valueOffset = $optionOffset + 4
                                if ($valueOffset + $optionLength -gt $body.Length) { break }
                                if ($optionCode -eq 9 -and $optionLength -ge 1) {
                                    $raw = $body[$valueOffset]
                                    if (($raw -band 0x80) -ne 0) {
                                        $timestampScale = [Math]::Pow(10, -1 * ($raw -band 0x7F))
                                    } else {
                                        $timestampScale = [Math]::Pow(10, -1 * $raw)
                                    }
                                }
                                $optionOffset = $valueOffset + $optionLength
                                if (($optionLength % 4) -ne 0) { $optionOffset += 4 - ($optionLength % 4) }
                            }
                        }
                    }
                    6 {
                        if ($body -and $body.Length -ge 20) {
                            $timestampHigh = Read-ChunkUInt32 -Buffer $body -Offset 4 -LittleEndian $littleEndian
                            $timestampLow = Read-ChunkUInt32 -Buffer $body -Offset 8 -LittleEndian $littleEndian
                            $capturedLength = Read-ChunkUInt32 -Buffer $body -Offset 12 -LittleEndian $littleEndian
                            $packetOffset = 20

                            $stats.TotalPackets++
                            if (($packetOffset + $capturedLength) -le $body.Length) {
                                $info = Get-DnsInfoFromFrame -Buffer $body -Offset $packetOffset -Length $capturedLength -LinkType $linkType
                                if ($info.IsDns) {
                                    $stats.DnsPackets++
                                    if ($info.IsQuery) {
                                        $stats.DnsQueries++
                                        if ($queryIds.Count -lt 2000000) {
                                            [void]$queryIds.Add($info.TransactionId)
                                        }
                                    } else {
                                        $stats.DnsResponses++
                                    }

                                    $timestamp = ([double]$timestampHigh * 4294967296.0 + [double]$timestampLow) * $timestampScale
                                    if ($null -eq $firstTimestamp -or $timestamp -lt $firstTimestamp) { $firstTimestamp = $timestamp }
                                    if ($null -eq $lastTimestamp -or $timestamp -gt $lastTimestamp) { $lastTimestamp = $timestamp }
                                } elseif ($linkType -notin @(1, 0, 101, 228)) {
                                    $stats.UnsupportedFrames++
                                }
                            }
                        }
                    }
                    3 {
                        if ($body -and $body.Length -ge 4) {
                            $stats.TotalPackets++
                            $originalLength = Read-ChunkUInt32 -Buffer $body -Offset 0 -LittleEndian $littleEndian
                            $info = Get-DnsInfoFromFrame -Buffer $body -Offset 4 -Length ([int]$originalLength) -LinkType $linkType
                            if ($info.IsDns) {
                                $stats.DnsPackets++
                                if ($info.IsQuery) { $stats.DnsQueries++ } else { $stats.DnsResponses++ }
                            }
                        }
                    }
                }

                # The trailing block-length field repeats the length; skip it and
                # rely on the stated length to stay in sync with padding.
                $stream.Position = $blockStart + $totalLength
            }

            $stats.LinkType = $linkType
            $stats.UniqueQueryIds = $queryIds.Count
            $stats.FirstTimestamp = $firstTimestamp
            $stats.LastTimestamp = $lastTimestamp
            if ($null -ne $firstTimestamp -and $null -ne $lastTimestamp) {
                $stats.CaptureSeconds = [Math]::Round($lastTimestamp - $firstTimestamp, 3)
            }
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }

    return $stats
}

function Get-SenderLogStats {
    <#
        Reads the engine's CSV export. Falls back to a line count if the file is
        not parseable as CSV, so a partially written log still gives a usable
        number rather than an exception.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stats = [pscustomobject]@{
        Path        = $Path
        TotalRows   = 0
        TimeoutRows = 0
        ErrorRows   = 0
        ParseMode   = 'lines'
    }

    try {
        $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
        $stats.TotalRows = $rows.Count
        $stats.ParseMode = 'csv'
        $stats.TimeoutRows = @($rows | Where-Object { $_.PSObject.Properties.Name -contains 'outcome' -and $_.outcome -eq 'timeout' }).Count
        $stats.ErrorRows = @($rows | Where-Object { $_.PSObject.Properties.Name -contains 'outcome' -and $_.outcome -eq 'error' }).Count
    } catch {
        Write-Verbose ('Falling back to line counting for {0}: {1}' -f $Path, $_.Exception.Message)
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        # Drop the header row if the engine wrote one.
        if ($lines.Count -gt 0 -and $lines[0] -match '^ts[,;]') {
            $lines = @($lines | Select-Object -Skip 1)
        }
        $stats.TotalRows = $lines.Count
    }

    return $stats
}

function Resolve-CapturePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [string]$ExplicitPath,

        [ValidateSet('etl', 'pcapng', 'newest')]
        [string]$Preference = 'newest'
    )

    if ($ExplicitPath) {
        $resolved = $ExplicitPath
        if (-not [System.IO.Path]::IsPathRooted($resolved)) {
            $resolved = Join-Path -Path (Get-Location).ProviderPath -ChildPath $resolved
        }
        if (-not (Test-Path -LiteralPath $resolved)) {
            throw "Capture file '$resolved' was not found."
        }
        return $resolved
    }

    if (-not (Test-Path -LiteralPath $Directory)) {
        throw "No capture directory at '$Directory'. Run -Action Start first."
    }

    $pattern = switch ($Preference) {
        'etl' { '*.etl' }
        'pcapng' { '*.pcapng' }
        default { '*.*' }
    }

    $candidate = Get-ChildItem -LiteralPath $Directory -Filter $pattern -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.etl', '.pcapng') } |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $candidate) {
        throw "No capture files found in '$Directory'. Run -Action Start, or pass -CaptureFile."
    }

    return $candidate.FullName
}

function Convert-PktMonEtl {
    <#
        Converts an ETL capture to pcapng. pktmon renamed this subcommand at some
        point (`etl2pcap` became `pcapng`), and which one a given build accepts
        depends on its version, so both are attempted and both command lines are
        reported if neither works. A missing/empty output file counts as failure
        even when the exit code claims success.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EtlPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )

    if (-not (Test-Path -LiteralPath $EtlPath)) {
        throw "ETL file '$EtlPath' was not found."
    }
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $pcapngPath = [System.IO.Path]::ChangeExtension($EtlPath, '.pcapng')

    $attempts = @(
        @('pcapng', $EtlPath, '-o', $pcapngPath),
        @('etl2pcap', $EtlPath, '-o', $pcapngPath)
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($attempt in $attempts) {
        $result = Invoke-PktMon -ArgumentList $attempt
        if ($result.Succeeded -and (Test-Path -LiteralPath $pcapngPath) -and (Get-Item -LiteralPath $pcapngPath).Length -gt 0) {
            Write-Verbose ('Converted using: ' + $result.CommandLine)
            return $pcapngPath
        }
        $errors.Add(('{0} -> exit {1}: {2}' -f $result.CommandLine, $result.ExitCode, ($result.Output -join ' ')))
    }

    throw ('Could not convert {0} to pcapng. Attempts: {1}' -f $EtlPath, ($errors -join ' | '))
}

function Stop-PktMonCapture {
    <#
        Stops the capture, converts the ETL to pcapng, and clears the filters.
        Filter cleanup is not optional: pktmon filters persist beyond the capture
        and beyond a reboot, and a forgotten filter silently reshapes the next
        capture someone takes on this host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [string]$EtlPath
    )

    if (-not (Test-PktMonRunning)) {
        Write-Log -Level WARNING -Message 'No pktmon capture appears to be running. Continuing teardown so any leftover filters are cleaned up.'
    }

    $stopResult = Invoke-PktMon -ArgumentList @('stop')
    if (-not $stopResult.Succeeded) {
        Write-Log -Level ERROR -Message ('pktmon stop returned {0}: {1}' -f $stopResult.ExitCode, ($stopResult.Output -join ' '))
    } else {
        Write-Log -Message 'Capture stopped.'
    }

    Remove-PktMonFilters | Out-Null
    Write-Log -Message 'Capture filters cleared.'

    if (-not $EtlPath -and (Test-Path -LiteralPath $OutputDirectory)) {
        $newest = Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.etl' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1
        if ($newest) {
            $EtlPath = $newest.FullName
        }
    }

    $pcapngPath = $null
    $summary = 'unavailable'

    if ($EtlPath -and (Test-Path -LiteralPath $EtlPath)) {
        $pcapngPath = Convert-PktMonEtl -EtlPath $EtlPath -OutputDirectory $OutputDirectory
        $stats = Get-PcapngDnsStats -Path $pcapngPath
        $summary = '{0:N0} packets, {1:N0} DNS queries, {2:N0} DNS responses, {3:N0} unique IDs' -f `
            $stats.TotalPackets, $stats.DnsQueries, $stats.DnsResponses, $stats.UniqueQueryIds
        Write-Log -Level SUCCESS -Message ('Capture written: {0} ({1:N0} bytes) - {2}' -f $pcapngPath, $stats.FileBytes, $summary)
        if ($stats.ParseError) {
            Write-Log -Level WARNING -Message "Capture parse note: $($stats.ParseError)"
        }
    } else {
        Write-Log -Level WARNING -Message "No .etl file was found in $OutputDirectory, so there was nothing to convert."
    }

    return [pscustomobject]@{
        Action     = 'Stop'
        EtlFile    = $EtlPath
        PcapngFile = $pcapngPath
        Summary    = $summary
        LogFile    = $script:LogFile
    }
}

# ---------------------------------------------------------------------------
# PREFLIGHT
# ---------------------------------------------------------------------------
Initialize-LogFile

if (-not $OutputDirectory) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).ProviderPath }
    $OutputDirectory = Join-Path -Path $scriptRoot -ChildPath 'captures'
}
if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path -Path (Get-Location).ProviderPath -ChildPath $OutputDirectory
}

Write-Log -Message ('{0} - started. Action: {1}  Server: {2}:{3}  User: {4}' -f $PSCommandPath, $Action, $Server, $Port, ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))

# Reconcile only reads an existing file, so it is the one action that does not
# need elevation.
if ($Action -ne 'Reconcile' -and -not (Test-IsElevated)) {
    throw @(
        "Action '$Action' requires administrator rights: pktmon uses an elevated ETW session and cannot capture otherwise."
        "Relaunch an elevated session, for example:  Start-Process pwsh -Verb RunAs -ArgumentList '-NoExit', '-File', '$PSCommandPath'"
    ) -join ' '
}

$script:PktMonPath = $null
if ($Action -ne 'Reconcile') {
    $script:PktMonPath = Resolve-PktMonPath
}

switch ($Action) {
    'Start' {
        if ((Test-PktMonRunning) -and -not $Force) {
            throw 'A pktmon capture appears to be running already (PktMon process found). Stop it with -Action Stop, or pass -Force to override.'
        }

        if ($PSCmdlet.ShouldProcess("${Server}:$Port", 'Start DNS capture with pktmon')) {
            if (-not (Test-Path -LiteralPath $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            }

            # Clear any stale filters left behind by an aborted run. Filters
            # persist across reboots and a forgotten one silently reshapes every
            # later capture, which is a nasty way to waste an afternoon.
            Remove-PktMonFilters | Out-Null

            $installedFilters = Add-PktMonDnsFilters
            foreach ($filter in $installedFilters) {
                Write-Log -Message "Filter installed: $filter"
            }
            if ($installedFilters.Count -eq 0) {
                throw 'No capture filters could be installed; refusing to start an unfiltered capture (it would capture all traffic on every interface).'
            }

            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $etlPath = Join-Path -Path $OutputDirectory -ChildPath ("DnsLoadForge_{0}.etl" -f $stamp)

            # --pkt-size 0 captures whole packets (no truncation), which is what
            # makes the DNS payload parseable. --comp nics captures at the
            # network interface, i.e. what really left the wire.
            $startArguments = @('start', '--capture', '--comp', 'nics', '--pkt-size', '0', '--file-name', $etlPath)

            Write-Log -Message ('Starting capture with: {0}' -f ('pktmon ' + ($startArguments -join ' ')))

            $startResult = Invoke-PktMon -ArgumentList $startArguments
            foreach ($line in $startResult.Output) {
                Write-Verbose ([string]$line)
            }

            if (-not $startResult.Succeeded) {
                throw ('pktmon failed to start (exit code {0}): {1}' -f $startResult.ExitCode, ($startResult.Output -join ' '))
            }

            Write-Log -Level SUCCESS -Message "Capture started. ETL file: $etlPath"

            if ($DurationSeconds -gt 0) {
                Write-Log -Message "Capturing for $DurationSeconds second(s). pktmon adds per-packet overhead, so keep spot-check runs short."
                Start-Sleep -Seconds $DurationSeconds
                Write-Log -Message 'Duration elapsed; stopping capture.'
                Stop-PktMonCapture -OutputDirectory $OutputDirectory -EtlPath $etlPath
            } else {
                Write-Log -Message 'Capture running. Use -Action Stop when finished; never leave a capture running.'
            }
        }
    }

    'Stop' {
        if ($PSCmdlet.ShouldProcess("${Server}:$Port", 'Stop DNS capture and convert to pcapng')) {
            Stop-PktMonCapture -OutputDirectory $OutputDirectory
        }
    }

    'Convert' {
        $etl = Resolve-CapturePath -Directory $OutputDirectory -ExplicitPath $CaptureFile -Preference 'etl'
        if ([System.IO.Path]::GetExtension($etl) -ne '.etl') {
            throw "Convert expects an .etl file but was given '$etl'. Use -Action Reconcile to analyse a .pcapng directly."
        }

        if ($PSCmdlet.ShouldProcess($etl, 'Convert ETL to pcapng')) {
            $pcapng = Convert-PktMonEtl -EtlPath $etl -OutputDirectory $OutputDirectory
            $stats = Get-PcapngDnsStats -Path $pcapng
            Write-Log -Level SUCCESS -Message ("Converted {0} -> {1} ({2:N0} bytes, {3:N0} packets, {4:N0} DNS queries)" -f $etl, $pcapng, $stats.FileBytes, $stats.TotalPackets, $stats.DnsQueries)
        }
    }

    'Status' {
        $filters = Invoke-PktMon -ArgumentList @('filter', 'list')
        Write-Host ''
        Write-Host 'Installed pktmon filters:' -ForegroundColor Cyan
        foreach ($line in $filters.Output) { Write-Host "  $line" }

        $running = Test-PktMonRunning
        Write-Host ''
        Write-Log -Message ('Capture state: {0}' -f $(if ($running) { 'RUNNING (a PktMon process is active)' } else { 'idle' }))

        if (Test-Path -LiteralPath $OutputDirectory) {
            $captures = @(Get-ChildItem -LiteralPath $OutputDirectory -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in @('.etl', '.pcapng') } |
                    Sort-Object -Property LastWriteTime -Descending)
            Write-Host ''
            if ($captures.Count -gt 0) {
                Write-Host "Captures in $OutputDirectory (newest first):" -ForegroundColor Cyan
                $captures | Select-Object -First 10 Name, @{ Name = 'SizeMB'; Expression = { [Math]::Round($_.Length / 1MB, 2) } }, LastWriteTime | Format-Table -AutoSize
            } else {
                Write-Host "No capture files in $OutputDirectory." -ForegroundColor Yellow
            }
        } else {
            Write-Log -Level WARNING -Message "Capture directory does not exist yet: $OutputDirectory"
        }

        if ($running) {
            Write-Log -Level WARNING -Message 'A capture is still running. Finish it with -Action Stop so filters and the ETW session are cleaned up.'
        }
    }

    'Reconcile' {
        $capture = Resolve-CapturePath -Directory $OutputDirectory -ExplicitPath $CaptureFile -Preference 'newest'

        # An ETL cannot be parsed directly; convert it first if the operator has
        # not already done so.
        if ([System.IO.Path]::GetExtension($capture) -eq '.etl') {
            if (-not (Test-IsElevated)) {
                throw 'Reconcile was given an .etl file, which must be converted to .pcapng first, and conversion needs administrator rights. Run -Action Convert elevated, then reconcile against the .pcapng file.'
            }
            $capture = Convert-PktMonEtl -EtlPath $capture -OutputDirectory $OutputDirectory
        }

        $wireStats = Get-PcapngDnsStats -Path $capture
        if ($wireStats.ParseError) {
            Write-Log -Level WARNING -Message "Capture parse note: $($wireStats.ParseError)"
        }

        Write-Log -Message ("Wire capture: {0} ({1:N0} blocks, {2:N0} packets, {3:N0} DNS queries, {4:N0} DNS responses, {5} unique transaction IDs)" -f `
                $capture, $wireStats.TotalBlocks, $wireStats.TotalPackets, $wireStats.DnsQueries, $wireStats.DnsResponses, $wireStats.UniqueQueryIds)

        if ($wireStats.LinkType -notin @(1, 0, 101, 228)) {
            Write-Log -Level WARNING -Message "Unsupported pcapng link type $($wireStats.LinkType); DNS packets could not be classified."
        }
        if ($wireStats.CaptureSeconds -gt 0) {
            Write-Log -Message ("Capture window: {0:N1} seconds ({1:N0} queries/second observed on the wire)" -f $wireStats.CaptureSeconds, ($wireStats.DnsQueries / [Math]::Max($wireStats.CaptureSeconds, 0.001)))
        }

        if (-not $SenderLog) {
            Write-Log -Level WARNING -Message 'No -SenderLog supplied, so no generator-side comparison is possible. Re-run with -SenderLog <path to the engine CSV export>.'
            [pscustomobject]@{
                Action           = 'Reconcile'
                CaptureFile      = $capture
                WireQueries      = $wireStats.DnsQueries
                WireResponses    = $wireStats.DnsResponses
                SenderLog        = $null
                GeneratorQueries = $null
                Delta            = $null
                DeltaPercent     = $null
                Interpretation   = 'Wire side only; supply -SenderLog to compare against the generator.'
                LogFile          = $script:LogFile
            }
            break
        }

        $senderStats = Get-SenderLogStats -Path $SenderLog
        $generatorQueries = $senderStats.TotalRows
        $delta = $wireStats.DnsQueries - $generatorQueries
        $deltaPercent = if ($generatorQueries -gt 0) { [Math]::Round(($delta / $generatorQueries) * 100.0, 2) } else { 0.0 }

        $interpretation = if ($generatorQueries -eq 0) {
            "The sender log at $SenderLog contains no records, so there is nothing to reconcile. Check the --export path from the engine run."
        } elseif ([Math]::Abs($deltaPercent) -lt 1.0) {
            'Consistent: the wire saw essentially everything the generator reported sending (within 1%). The offered load really did reach the NIC.'
        } elseif ($deltaPercent -lt 0 -and [Math]::Abs($deltaPercent) -lt 5.0) {
            ('Minor loss ({0:N2}% of generated queries were not seen on the wire). Worth checking NIC/driver discarded-packet counters; pktmon being enabled can itself account for a small shortfall.' -f [Math]::Abs($deltaPercent))
        } elseif ($deltaPercent -le -5.0) {
            ('Significant loss: {0:N2}% of generated queries never appeared on the wire. The generator is being throttled or backpressured (socket send buffer full), or the driver/NIC dropped frames while capturing. Do NOT treat per-query results from this run as authoritative - lower the query rate and repeat.' -f [Math]::Abs($deltaPercent))
        } else {
            ('The wire saw {0:N2}% MORE DNS queries than the generator logged. Suspect duplicate capture (two pktmon sessions, or capture installed on more than one component/interface), a second sender on the segment, or replay. Investigate before trusting either number.' -f $deltaPercent)
        }

        Write-Host ''
        Write-Host 'Generator (sender log) vs wire (pcapng):' -ForegroundColor Cyan
        [pscustomobject]@{
            Metric    = 'DNS queries'
            Generator = $generatorQueries
            Wire      = $wireStats.DnsQueries
            Delta     = $delta
            DeltaPct  = ('{0:N2}%' -f $deltaPercent)
        } | Format-List

        [pscustomobject]@{
            Metric    = 'DNS responses'
            Generator = 'n/a'
            Wire      = $wireStats.DnsResponses
            Delta     = 'n/a'
            DeltaPct  = 'n/a'
        } | Format-List

        if ($senderStats.ParseMode -eq 'csv') {
            Write-Host ("Generator log detail: {0:N0} record(s), {1:N0} timed out, {2:N0} errored." -f $senderStats.TotalRows, $senderStats.TimeoutRows, $senderStats.ErrorRows)
        } else {
            Write-Host ("Generator log detail: {0:N0} line(s) counted (the file is not parseable CSV, so outcome counts are unavailable)." -f $senderStats.TotalRows)
        }

        Write-Log -Level SUCCESS -Message $interpretation

        [pscustomobject]@{
            Action           = 'Reconcile'
            CaptureFile      = $capture
            WireQueries      = $wireStats.DnsQueries
            WireResponses    = $wireStats.DnsResponses
            WireUniqueIds    = $wireStats.UniqueQueryIds
            CaptureSeconds   = $wireStats.CaptureSeconds
            SenderLog        = $SenderLog
            GeneratorQueries = $generatorQueries
            Delta            = $delta
            DeltaPercent     = $deltaPercent
            Interpretation   = $interpretation
            LogFile          = $script:LogFile
        }
    }
}
