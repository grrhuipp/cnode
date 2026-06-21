$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$XrayProxyDir = Join-Path $Root "tmp\xray-core-v26.6.1\proxy"
$LatestMatrix = Get-ChildItem (Join-Path $Root "tmp\perf-harness\results") -Filter "bench-matrix-*.csv" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$coverage = @(
    [PSCustomObject]@{
        Protocol = "vmess"
        CnodeSurface = "inbound+outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "vmess")
        Evidence = "bench_matrix cnode-vmess/xray-vmess"
    },
    [PSCustomObject]@{
        Protocol = "vless"
        CnodeSurface = "inbound+outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "vless")
        Evidence = "bench_matrix cnode-vless/xray-vless"
    },
    [PSCustomObject]@{
        Protocol = "trojan"
        CnodeSurface = "inbound+outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "trojan")
        Evidence = "bench_matrix cnode-trojan/xray-trojan"
    },
    [PSCustomObject]@{
        Protocol = "shadowsocks"
        CnodeSurface = "inbound+outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "shadowsocks")
        Evidence = "bench_matrix cnode-shadowsocks/xray-shadowsocks"
    },
    [PSCustomObject]@{
        Protocol = "freedom"
        CnodeSurface = "outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "freedom")
        Evidence = "covered as selected outbound in cnode-vless/xray-vless iperf3 path"
    },
    [PSCustomObject]@{
        Protocol = "blackhole"
        CnodeSurface = "outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "blackhole")
        Evidence = "smoke_blackhole_http_compare cnode/xray 403 response"
    },
    [PSCustomObject]@{
        Protocol = "anytls"
        CnodeSurface = "inbound+outbound"
        XraySameName = Test-Path (Join-Path $XrayProxyDir "anytls")
        Evidence = "bench_anytls_self cnode end-to-end; no xray-core same-name implementation"
    }
)

"Latest matrix: $($LatestMatrix.FullName)"
$coverage | Format-Table -AutoSize

$missingSameNameEvidence = $coverage |
    Where-Object { $_.XraySameName -and [string]::IsNullOrWhiteSpace($_.Evidence) }
if ($missingSameNameEvidence) {
    throw "missing evidence for same-name protocol(s): $($missingSameNameEvidence.Protocol -join ', ')"
}
