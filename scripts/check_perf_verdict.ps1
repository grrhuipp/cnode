param(
    [string]$CsvPath = "",
    [string[]]$Protocols = @("vmess", "vless", "trojan", "shadowsocks")
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = Get-ChildItem (Join-Path $Root "tmp\perf-harness\results") -Filter "bench-matrix-*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

if ([string]::IsNullOrWhiteSpace($CsvPath) -or !(Test-Path $CsvPath)) {
    throw "benchmark CSV not found: $CsvPath"
}

function Median([double[]]$Values) {
    if (!$Values -or $Values.Count -eq 0) {
        throw "cannot compute median of empty values"
    }
    $sorted = $Values | Sort-Object
    $n = $sorted.Count
    if ($n % 2 -eq 1) {
        return [double]$sorted[[int][Math]::Floor($n / 2)]
    }
    return ([double]$sorted[$n / 2 - 1] + [double]$sorted[$n / 2]) / 2.0
}

$rows = Import-Csv $CsvPath
if (!$rows -or $rows.Count -eq 0) {
    throw "benchmark CSV is empty: $CsvPath"
}

$verdicts = @()
foreach ($protocol in $Protocols) {
    $cnodeRows = @($rows | Where-Object { $_.Protocol -eq $protocol -and $_.Impl -eq "cnode" })
    $xrayRows = @($rows | Where-Object { $_.Protocol -eq $protocol -and $_.Impl -eq "xray" })
    if ($cnodeRows.Count -eq 0 -or $xrayRows.Count -eq 0) {
        throw "missing cnode/xray rows for protocol: $protocol"
    }

    $cnodeGbps = Median ([double[]]($cnodeRows | ForEach-Object { [double]$_.ReceiverGbps }))
    $xrayGbps = Median ([double[]]($xrayRows | ForEach-Object { [double]$_.ReceiverGbps }))
    $cnodeCpu = Median ([double[]]($cnodeRows | ForEach-Object { [double]$_.ServerCpuSeconds }))
    $xrayCpu = Median ([double[]]($xrayRows | ForEach-Object { [double]$_.ServerCpuSeconds }))
    $cnodeCpuPerGbps = Median ([double[]]($cnodeRows | ForEach-Object { [double]$_.ServerCpuPerGbps }))
    $xrayCpuPerGbps = Median ([double[]]($xrayRows | ForEach-Object { [double]$_.ServerCpuPerGbps }))

    $throughputWin = $cnodeGbps -gt $xrayGbps
    $cpuWin = $cnodeCpu -lt $xrayCpu
    $efficiencyWin = $cnodeCpuPerGbps -lt $xrayCpuPerGbps
    $verdicts += [PSCustomObject]@{
        Protocol = $protocol
        Samples = [Math]::Min($cnodeRows.Count, $xrayRows.Count)
        CnodeGbps = [Math]::Round($cnodeGbps, 3)
        XrayGbps = [Math]::Round($xrayGbps, 3)
        CnodeCpu = [Math]::Round($cnodeCpu, 3)
        XrayCpu = [Math]::Round($xrayCpu, 3)
        CnodeCpuPerGbps = [Math]::Round($cnodeCpuPerGbps, 3)
        XrayCpuPerGbps = [Math]::Round($xrayCpuPerGbps, 3)
        ThroughputWin = $throughputWin
        ServerCpuWin = $cpuWin
        CpuPerGbpsWin = $efficiencyWin
        Verdict = if ($throughputWin -and $cpuWin -and $efficiencyWin) { "PASS" } else { "FAIL" }
    }
}

"CSV: $((Resolve-Path $CsvPath).Path)"
$verdicts | Format-Table -AutoSize

$failed = @($verdicts | Where-Object { $_.Verdict -ne "PASS" })
if ($failed.Count -gt 0) {
    throw "performance verdict failed for: $($failed.Protocol -join ', ')"
}
