param(
    [string[]]$Scenarios = @(
        "cnode-vmess", "xray-vmess",
        "cnode-vless", "xray-vless",
        "cnode-trojan", "xray-trojan",
        "cnode-shadowsocks", "xray-shadowsocks"
    ),
    [int]$Rounds = 3,
    [int]$Seconds = 10,
    [int]$Parallel = 8,
    [int]$CnodeWorkers = 0,
    [int]$GraceSeconds = 10,
    [ValidateSet("error", "warning", "info", "debug")]
    [string]$XrayLogLevel = "error",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

$Scenarios = @(
    foreach ($item in $Scenarios) {
        foreach ($part in ($item -split ",")) {
            $trimmed = $part.Trim()
            if ($trimmed.Length -gt 0) {
                $trimmed
            }
        }
    }
)

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "tmp\perf-harness\results"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$CsvPath = Join-Path $OutDir "bench-matrix-$Stamp.csv"

function Get-Protocol([string]$Scenario) {
    if ($Scenario -eq "direct") { return "direct" }
    return $Scenario.Substring($Scenario.IndexOf("-") + 1)
}

function Get-Impl([string]$Scenario) {
    if ($Scenario -eq "direct") { return "direct" }
    return $Scenario.Substring(0, $Scenario.IndexOf("-"))
}

function Parse-IperfReceiverGbps($Lines) {
    $line = $Lines | Where-Object { $_ -match '^\[SUM\].*receiver' } | Select-Object -Last 1
    if (!$line) { return $null }
    if ($line -match '\s([0-9.]+)\s+([KMG])bits/sec\s+receiver') {
        $value = [double]$Matches[1]
        switch ($Matches[2]) {
            "K" { return $value / 1000000.0 }
            "M" { return $value / 1000.0 }
            "G" { return $value }
        }
    }
    return $null
}

function Parse-CpuRows($Lines) {
    $rows = @{}
    foreach ($line in $Lines) {
        if ($line -match '^(iperf-server|cnode-server|xray-server|xray-client)\s+\d+\s+\S+\s+([0-9.]+)\s*$') {
            $rows[$Matches[1]] = [double]$Matches[2]
        }
    }
    return $rows
}

function Median($Values) {
    $arr = [System.Collections.Generic.List[double]]::new()
    foreach ($value in $Values) {
        if ($value -ne $null -and "$value".Length -gt 0) {
            $arr.Add([double]$value)
        }
    }
    if ($arr.Count -eq 0) { return $null }
    $arr.Sort()
    $mid = [int]($arr.Count / 2)
    if (($arr.Count % 2) -eq 1) { return $arr[$mid] }
    return ($arr[$mid - 1] + $arr[$mid]) / 2.0
}

function New-SummaryRows($Rows) {
    $Rows |
        Group-Object Protocol, Impl |
        ForEach-Object {
            $groupRows = $_.Group
            [PSCustomObject]@{
                Protocol = $groupRows[0].Protocol
                Impl = $groupRows[0].Impl
                MedianGbps = [Math]::Round((Median ($groupRows | ForEach-Object { $_.ReceiverGbps })), 3)
                MedianServerCpu = [Math]::Round((Median ($groupRows | ForEach-Object { $_.ServerCpuSeconds })), 3)
                MedianCpuPerGbps = [Math]::Round((Median ($groupRows | ForEach-Object { $_.ServerCpuPerGbps })), 3)
                Samples = $groupRows.Count
            }
        } |
        Sort-Object Protocol, Impl
}

function New-VerdictRows($SummaryRows) {
    $SummaryRows |
        Group-Object Protocol |
        ForEach-Object {
            $cnode = $_.Group | Where-Object { $_.Impl -eq "cnode" } | Select-Object -First 1
            $xray = $_.Group | Where-Object { $_.Impl -eq "xray" } | Select-Object -First 1
            if (!$cnode -or !$xray) {
                return
            }
            $throughputWin = [double]$cnode.MedianGbps -gt [double]$xray.MedianGbps
            $cpuWin = [double]$cnode.MedianServerCpu -lt [double]$xray.MedianServerCpu
            $efficiencyWin = [double]$cnode.MedianCpuPerGbps -lt [double]$xray.MedianCpuPerGbps
            [PSCustomObject]@{
                Protocol = $_.Name
                ThroughputWin = $throughputWin
                ServerCpuWin = $cpuWin
                CpuPerGbpsWin = $efficiencyWin
                Verdict = if ($throughputWin -and $cpuWin -and $efficiencyWin) { "PASS" } else { "FAIL" }
                CnodeGbps = $cnode.MedianGbps
                XrayGbps = $xray.MedianGbps
                CnodeCpu = $cnode.MedianServerCpu
                XrayCpu = $xray.MedianServerCpu
                CnodeCpuPerGbps = $cnode.MedianCpuPerGbps
                XrayCpuPerGbps = $xray.MedianCpuPerGbps
            }
        } |
        Sort-Object Protocol
}

$rows = @()
for ($round = 1; $round -le $Rounds; ++$round) {
    foreach ($scenario in $Scenarios) {
        Write-Host "===== round=$round scenario=$scenario ====="
        $output = & powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $PSScriptRoot "bench_iperf3.ps1") `
            -Scenario $scenario `
            -Seconds $Seconds `
            -Parallel $Parallel `
            -GraceSeconds $GraceSeconds `
            -CnodeWorkers $CnodeWorkers `
            -XrayLogLevel $XrayLogLevel 2>&1

        $gbps = Parse-IperfReceiverGbps $output
        $cpu = Parse-CpuRows $output
        $serverRole = if ($scenario.StartsWith("cnode-")) { "cnode-server" } elseif ($scenario.StartsWith("xray-")) { "xray-server" } else { "iperf-server" }
        $serverCpu = if ($cpu.ContainsKey($serverRole)) { $cpu[$serverRole] } else { $null }
        $cpuPerGbps = if ($gbps -and $serverCpu -ne $null) { $serverCpu / $gbps } else { $null }

        $row = [PSCustomObject]@{
            Round = $round
            Scenario = $scenario
            Impl = Get-Impl $scenario
            Protocol = Get-Protocol $scenario
            Seconds = $Seconds
            Parallel = $Parallel
            CnodeWorkers = $CnodeWorkers
            ReceiverGbps = if ($gbps -ne $null) { [Math]::Round($gbps, 3) } else { $null }
            ServerCpuSeconds = if ($serverCpu -ne $null) { [Math]::Round($serverCpu, 3) } else { $null }
            ServerCpuPerGbps = if ($cpuPerGbps -ne $null) { [Math]::Round($cpuPerGbps, 3) } else { $null }
            IperfServerCpuSeconds = if ($cpu.ContainsKey("iperf-server")) { [Math]::Round($cpu["iperf-server"], 3) } else { $null }
            XrayClientCpuSeconds = if ($cpu.ContainsKey("xray-client")) { [Math]::Round($cpu["xray-client"], 3) } else { $null }
        }
        $rows += $row
        $row | Format-Table -AutoSize
    }
}

$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

"CSV: $CsvPath"
"Summary:"
$summary = @(New-SummaryRows $rows)
$summary | Format-Table -AutoSize

"Verdict:"
$verdict = @(New-VerdictRows $summary)
$verdict | Format-Table -AutoSize

$failed = @($verdict | Where-Object { $_.Verdict -ne "PASS" })
if ($failed.Count -gt 0) {
    throw "benchmark verdict failed for: $($failed.Protocol -join ', ')"
}
