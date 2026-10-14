<#
.SYNOPSIS
    Runs a DNS Load Forge simulation and opens the live dashboard.

.DESCRIPTION
    Thin, opinionated front end for the Python engine in ..\src.  It exists so the
    everyday workflow of this repository -- a PowerShell prompt, a technician with a
    laptop in a comms room -- does not have to know where the package lives or which
    interpreter to use.

    The load generation itself is Python on purpose.  Simulating 10,000 workers needs
    tens of thousands of UDP transactions per second, and a PowerShell runspace pool
    cannot sustain that; details are in ..\ARCHITECTURE.md under "Why Python".

    What this script does for you:
      * locates a usable Python 3.10+ (py launcher preferred, then python on PATH);
      * warms the domain-list cache, because that step needs the internet and the
        machine you test from usually does not have it;
      * refuses pool mode without elevation, with an explanation rather than a crash;
      * launches the engine, then opens the dashboard in your browser.

    Everything the engine accepts can be passed through with -ExtraArgs, so this
    wrapper never has to be updated when the engine gains a flag.

.PARAMETER Server
    The resolver or filtering appliance under test.  Required unless -Mock or
    -Target is used.

.PARAMETER Target
    One or more named targets (see `python -m dnsloadforge targets`): built-in presets
    for well-known public filters plus anything in targets.json.  Naming several runs
    them back to back on identical traffic and prints a side-by-side comparison.  Each
    target carries its own scoring rules, so a family-safe resolver is not marked
    down for failing to block ads.

.PARAMETER TargetsFile
    A targets file other than .\targets.json.  See targets.example.json.

.PARAMETER AllowPublicTarget
    Permit more than 100 qps against a public resolver.  Off by default: a cloud
    resolver is somebody else's infrastructure.

.PARAMETER Mock
    Run against the built-in simulated appliance instead of a real one.  Use this to
    rehearse the whole flow, and to verify the tool itself, before touching anything
    that matters.

.PARAMETER MockScenario
    Behaviour of the simulated appliance: good, passthrough, overblocker, lossy,
    servfail, slow, refused.  'good' blocks exactly what the domain catalogue says
    should be blocked, so a clean pass (verdict FILTERING) is the expected result --
    provided the rate is one the mock can serve, which is why -Mock defaults to 2000
    qps.  Every other scenario should produce a visibly different verdict.

.PARAMETER Qps
    Target queries per second.  The 10,000-worker office target is 10000.

    With -Mock and no explicit -Qps, the rate defaults to 2000: the simulated
    appliance is a single-threaded Python responder and saturates well below what
    this generator can send, so rehearsing at 5000 would report DEGRADED for
    capacity reasons that belong to the simulator, not to the filter.  Pass -Qps
    explicitly to push it harder and see that capacity verdict deliberately.

.PARAMETER Personas
    Number of simulated workers (default 10000).

.PARAMETER Duration
    Seconds to run.  0 means run until stopped from the dashboard.

.PARAMETER Mode
    personas (default; one source IP, no privileges needed) or pool (real secondary
    source IPs, needs elevation and a NIC with the addresses assigned).

.PARAMETER SourceIpsFile
    File of pool addresses, one per line -- the -OutputFile written by
    New-LabSourceIPs.ps1.

.PARAMETER RecordLog
    Write the raw per-query evidence to this path.  Without it the export links on
    the dashboard have nothing to serve.

.PARAMETER RefreshLists
    Refetch every domain list.  Needs internet.

.PARAMETER Offline
    Never touch the network; use whatever is cached.  This is the normal state of
    affairs on-site.

.PARAMETER NoDashboard
    Run headless and print the summary to the console.

.PARAMETER ExtraArgs
    Anything else to hand to the engine verbatim, e.g. @('--threads','auto').

.EXAMPLE
    .\Invoke-DnsLoadForge.ps1 -Mock -Duration 20
    Rehearse end to end against the built-in appliance.

.EXAMPLE
    .\Invoke-DnsLoadForge.ps1 -Server 10.0.0.10 -Qps 10000 -Duration 900 -RecordLog .\runs\soak.jsonl

.EXAMPLE
    .\Invoke-DnsLoadForge.ps1 -Target 'Quad9','OpenDNS FamilyShield' -Qps 100 -Duration 120
    Compare two filters on identical traffic.

.EXAMPLE
    .\Invoke-DnsLoadForge.ps1 -Server 10.0.0.10 -Mode pool -SourceIpsFile .\pool.txt -Qps 10000

.NOTES
    Requires Python 3.10+.  Elevation is required only for -Mode pool, and for the
    packet-capture script.  Run .\Invoke-DnsLoadForge.ps1 -Server <ip> in a lab
    first: a load generator pointed at a production resolver at 10k qps is an outage,
    not a test.
#>
[CmdletBinding()]
param(
    [string]$Server,

    [string[]]$Target = @(),

    [string]$TargetsFile,

    [switch]$AllowPublicTarget,

    [switch]$Mock,

    [ValidateSet('good', 'passthrough', 'overblocker', 'lossy', 'servfail', 'slow', 'refused')]
    [string]$MockScenario = 'good',

    [switch]$MockOverblock,

    [ValidateRange(1, 1000000)]
    [double]$Qps = 5000,

    [ValidateRange(1, 1000000)]
    [int]$Personas = 10000,

    [ValidateRange(0, 86400)]
    [double]$Duration = 60,

    [ValidateSet('personas', 'pool')]
    [string]$Mode = 'personas',

    [string]$SourceIps,

    [string]$SourceIpsFile,

    [string]$RecordLog,

    [ValidateRange(0, 1024)]
    [int]$MaxPerCategory = 250000,

    [switch]$RefreshLists,

    [switch]$Offline,

    [ValidateRange(1, 65535)]
    [int]$DashboardPort = 8787,

    [switch]$OpenDashboard,

    [switch]$NoDashboard,

    [switch]$NoRecordLog,

    [string[]]$ExtraArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- locate the package and an interpreter -----------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$sourceRoot = Join-Path $projectRoot 'src'

if (-not (Test-Path (Join-Path $sourceRoot 'dnsloadforge'))) {
    throw "Cannot find the dnsloadforge package under $sourceRoot. Run this script from the repository layout it shipped in."
}

function Resolve-PythonCommand {
    <#
    Prefer the py launcher (it reports installed versions properly), then fall back
    to whatever 'python' resolves to.  Version is checked rather than assumed: the
    engine uses 3.10+ syntax, and failing at the first UDP packet with a SyntaxError
    is a bad way to find out.
    #>
    $candidates = @(
        @{ Exe = 'py';      Args = @('-3') },
        @{ Exe = 'python';  Args = @() },
        @{ Exe = 'python3'; Args = @() }
    )
    foreach ($candidate in $candidates) {
        $exe = Get-Command $candidate.Exe -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $probe = & $candidate.Exe @($candidate.Args + @('-c', 'import sys; print("%d.%d" % sys.version_info[:2])')) 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $probe) { continue }
            $version = [version]($probe | Select-Object -First 1)
            if ($version -ge [version]'3.10') {
                return [pscustomobject]@{ Exe = $candidate.Exe; Prefix = $candidate.Args; Version = $version }
            }
            Write-Warning "Found $($candidate.Exe) $version but the engine needs 3.10 or newer; continuing the search."
        }
        catch {
            continue
        }
    }
    throw 'No Python 3.10+ interpreter found. Install Python, or add it to PATH, and try again.'
}

$python = Resolve-PythonCommand
Write-Verbose "Using $($python.Exe) $($python.Prefix -join ' ') (Python $($python.Version))"

function Invoke-Engine {
    param([string[]]$EngineArgs)
    $full = @($python.Prefix) + @('-m', 'dnsloadforge') + $EngineArgs
    Write-Verbose "Running: $($python.Exe) $($full -join ' ')"
    Push-Location $sourceRoot
    try {
        # PYTHONPATH rather than an activated venv: the package has no third-party
        # dependencies, so there is nothing to install and nothing to activate.
        $env:PYTHONPATH = $sourceRoot
        # Out-Host, not a bare call.  `& python ...` puts every line the engine prints
        # into this function's *output stream*, so the caller's assignment
        # (`$exitCode = Invoke-Engine ...`) captured the whole run report into a
        # variable and printed none of it -- a run looked like it produced nothing
        # while still reporting success.  It also made the return value an array
        # ending in the exit code, and in PowerShell a non-empty array is truthy
        # under -ne 0, so every "did it fail?" check below threw even on success.
        # Out-Host writes straight to the console and returns nothing, so only the
        # exit code travels back to the caller.
        & $python.Exe @full | Out-Host
        return $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}

# --- guard rails -------------------------------------------------------------

if (-not $Mock -and [string]::IsNullOrWhiteSpace($Server) -and $Target.Count -eq 0) {
    throw 'Specify -Server <appliance ip> or -Target <name>, or use -Mock to rehearse against the built-in appliance.'
}
if ($Server -and $Target.Count -gt 0) {
    throw 'Use either -Server or -Target, not both.'
}

if ($Mode -eq 'pool') {
    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { $isAdmin = $false }

    if (-not $isAdmin) {
        throw @"
Pool mode needs elevation for one reason only: creating the secondary IP addresses
that give the appliance distinct clients. Launch an elevated prompt and re-run.

If you only need to exercise the filter's throughput and classification -- and not
its per-client policy -- drop -Mode pool. Persona mode sends the same 10,000
workers' traffic from a single address and needs no privileges at all.
"@
    }
    if (-not $SourceIpsFile -and [string]::IsNullOrWhiteSpace($SourceIps)) {
        throw 'Pool mode needs -SourceIps or -SourceIpsFile. Run .\New-LabSourceIPs.ps1 first to create the addresses and write the file.'
    }
}

# --- warm the domain lists ---------------------------------------------------

$cacheDir = Join-Path $projectRoot 'lists\cache'
$manifest = Join-Path $cacheDir 'manifest.json'

if ($RefreshLists) {
    Write-Host 'Refreshing domain lists (this needs internet access)...' -ForegroundColor Cyan
    $code = Invoke-Engine @('lists', '--refresh', '--max-per-category', "$MaxPerCategory")
    if ($code -ne 0) { throw "Refreshing the domain lists failed with exit code $code." }
}
elseif (-not (Test-Path $manifest)) {
    if ($Offline) {
        Write-Warning 'No domain lists are cached and -Offline was requested. Only the built-in curated enterprise/borderline set will be used, so the traffic mix will be almost entirely curated names. Run without -Offline once, on a connected machine.'
    }
    else {
        Write-Host 'No domain lists cached yet; fetching them once (needs internet).' -ForegroundColor Cyan
        $code = Invoke-Engine @('lists', '--refresh', '--max-per-category', "$MaxPerCategory")
        if ($code -ne 0) { Write-Warning 'The fetch failed; continuing with the built-in curated lists only.' }
    }
}

# --- rehearsal rate ----------------------------------------------------------

# The built-in mock is a single-threaded Python responder, so it saturates well below
# the rate this generator can send.  A rehearsal at the 5000 qps default therefore
# reported DEGRADED for capacity reasons that belong to the simulator rather than to
# the filter under test -- the exact opposite of what `-Mock` is for.  Default to a
# rate the mock can actually serve, and let an explicit -Qps override it so the
# capacity verdict stays reachable when you want to see it.
if ($Mock -and -not $PSBoundParameters.ContainsKey('Qps')) {
    $Qps = 2000
    Write-Host "  (mock rehearsal at $Qps qps, a rate the simulated appliance can serve;" `
        -ForegroundColor DarkGray
    Write-Host '   add -Qps to push it harder and see the capacity verdict)' -ForegroundColor DarkGray
}

# --- assemble the engine arguments ------------------------------------------

$engineArgs = [System.Collections.Generic.List[string]]::new()
$engineArgs.Add('--qps');      $engineArgs.Add("$Qps")
$engineArgs.Add('--personas'); $engineArgs.Add("$Personas")
$engineArgs.Add('--duration'); $engineArgs.Add("$Duration")
$engineArgs.Add('--mode');     $engineArgs.Add($Mode)
$engineArgs.Add('--max-per-category'); $engineArgs.Add("$MaxPerCategory")

if ($Mock) {
    $engineArgs.Add('--mock')
    $engineArgs.Add('--mock-scenario'); $engineArgs.Add($MockScenario)
    if ($MockOverblock) { $engineArgs.Add('--mock-overblock') }
}
elseif ($Target.Count -gt 0) {
    foreach ($name in $Target) { $engineArgs.Add('--target'); $engineArgs.Add($name) }
}
else {
    $engineArgs.Add('--server'); $engineArgs.Add($Server)
}
if ($TargetsFile)       { $engineArgs.Add('--targets'); $engineArgs.Add($TargetsFile) }
if ($AllowPublicTarget) { $engineArgs.Add('--allow-public-target') }

if ($SourceIps)     { $engineArgs.Add('--source-ips');      $engineArgs.Add($SourceIps) }
if ($SourceIpsFile) { $engineArgs.Add('--source-ips-file'); $engineArgs.Add($SourceIpsFile) }
if ($Offline)       { $engineArgs.Add('--offline') }

$engineArgs.Add('--dashboard-port'); $engineArgs.Add("$DashboardPort")
if ($OpenDashboard) { $engineArgs.Add('--open-dashboard') }
if ($NoDashboard)   { $engineArgs.Add('--no-dashboard') }

if ($NoRecordLog) {
    $engineArgs.Add('--no-record-log')
}
elseif ($RecordLog) {
    $engineArgs.Add('--record-log'); $engineArgs.Add((Join-Path $projectRoot $RecordLog))
}
else {
    Write-Host 'Tip: add -RecordLog .\runs\soak.jsonl to keep the per-query evidence the dashboard offers for download.' -ForegroundColor DarkGray
}

foreach ($arg in $ExtraArgs) { $engineArgs.Add($arg) }

# --- run ---------------------------------------------------------------------

$targetLabel = if ($Mock) { "the built-in mock appliance ($MockScenario)" } elseif ($Target.Count -gt 0) { $Target -join ', ' } else { $Server }
Write-Host ''
Write-Host "DNS Load Forge: $Personas simulated workers at $Qps qps for $Duration seconds" -ForegroundColor Cyan
Write-Host "  target:    $targetLabel" -ForegroundColor Cyan
Write-Host "  identity:  $Mode" -ForegroundColor Cyan
if (-not $NoDashboard) {
    Write-Host "  dashboard: http://127.0.0.1:$DashboardPort/" -ForegroundColor Cyan
}
Write-Host ''

$exitCode = Invoke-Engine $engineArgs.ToArray()
exit $exitCode
