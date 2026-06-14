param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$OutDir = "",
    [switch]$KeepGoing
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "build\e2e-external-matrix"
}

$xrayAnytls = Join-Path $Root "tools\xray-core-anytls\xray.exe"
$xrayLatest = Join-Path $Root "tools\xray-core-latest\xray.exe"
$xray = if (Test-Path $xrayAnytls) {
    $xrayAnytls
} elseif (Test-Path $xrayLatest) {
    $xrayLatest
} else {
    Join-Path $Root "tools\xray-core\xray.exe"
}
$mihomo = Join-Path $Root "tools\mihomo\mihomo-windows-amd64.exe"
$singBox = Join-Path $Root "tools\sing-box\sing-box.exe"
$cnode = Join-Path $Root "build\cnode.exe"

foreach ($tool in @($xray, $mihomo, $singBox, $cnode)) {
    if (-not (Test-Path $tool)) {
        throw "required tool not found: $tool"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$certDir = Join-Path $OutDir "cert"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    $dir = Split-Path -Parent $Path
    if ($dir) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Write-Json {
    param([string]$Path, [object]$Value)
    Write-Utf8NoBom -Path $Path -Text ($Value | ConvertTo-Json -Depth 64)
}

function Invoke-Check {
    param(
        [string]$Name,
        [string]$Exe,
        [string[]]$CommandArgs
    )
    $log = Join-Path $OutDir "$Name.log"
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Exe @CommandArgs 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    Write-Utf8NoBom -Path $log -Text (($output | Out-String).TrimEnd() + "`n")
    [pscustomobject]@{
        name = $Name
        exit_code = $exit
        ok = ($exit -eq 0)
        log = $log
        command = "$Exe $($CommandArgs -join ' ')"
    }
}

function New-XrayTlsCertificate {
    $raw = & $xray tls cert --domain=localhost
    if ($LASTEXITCODE -ne 0) {
        throw "xray tls cert failed"
    }
    $cert = ($raw | Out-String | ConvertFrom-Json)
    $certPath = Join-Path $certDir "localhost.crt"
    $keyPath = Join-Path $certDir "localhost.key"
    Write-Utf8NoBom -Path $certPath -Text (($cert.certificate -join "`n") + "`n")
    Write-Utf8NoBom -Path $keyPath -Text (($cert.key -join "`n") + "`n")
    [pscustomobject]@{
        certificatePath = $certPath
        keyPath = $keyPath
        xrayCertificate = $cert.certificate
        xrayKey = $cert.key
    }
}

$cert = New-XrayTlsCertificate
$uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
$password = "e2e-password"
$ssMethod = "aes-256-gcm"
$paddingScheme = @(
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000"
)

$ports = @{
    xray_vmess = 42101
    xray_trojan = 42102
    xray_shadowsocks = 42103
    xray_anytls = 42104
    sing_vmess = 42201
    sing_trojan = 42202
    sing_shadowsocks = 42203
    sing_anytls = 42204
    mihomo_mixed = 42300
    mihomo_vmess = 42301
    mihomo_trojan = 42302
    mihomo_shadowsocks = 42303
    mihomo_anytls = 42304
}

function New-XrayBase {
    param([array]$Inbounds, [array]$Outbounds)
    @{
        log = @{ loglevel = "warning" }
        inbounds = $Inbounds
        outbounds = $Outbounds
    }
}

function New-XrayTlsStream {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = "localhost"
            certificates = @(@{
                certificate = $cert.xrayCertificate
                key = $cert.xrayKey
            })
        }
    }
}

$xrayChecks = @()
$xrayDirect = @(@{ protocol = "freedom"; tag = "direct" })
$xraySocksInbound = @(@{ listen = "127.0.0.1"; port = 42080; protocol = "socks"; settings = @{ udp = $true } })

$xrayMatrix = @{
    vmess = @{
        inbound = @{
            listen = "127.0.0.1"; port = $ports.xray_vmess; protocol = "vmess";
            settings = @{ clients = @(@{ id = $uuid; alterId = 0; email = "vmess@example.test" }) }
        }
        outbound = @{
            protocol = "vmess"; tag = "vmess-out";
            settings = @{ vnext = @(@{ address = "127.0.0.1"; port = $ports.xray_vmess; users = @(@{ id = $uuid; alterId = 0; security = "auto" }) }) }
        }
    }
    trojan = @{
        inbound = @{
            listen = "127.0.0.1"; port = $ports.xray_trojan; protocol = "trojan";
            settings = @{ clients = @(@{ password = $password; email = "trojan@example.test" }) };
            streamSettings = New-XrayTlsStream
        }
        outbound = @{
            protocol = "trojan"; tag = "trojan-out";
            settings = @{ servers = @(@{ address = "127.0.0.1"; port = $ports.xray_trojan; password = $password }) };
            streamSettings = New-XrayTlsStream
        }
    }
    shadowsocks = @{
        inbound = @{
            listen = "127.0.0.1"; port = $ports.xray_shadowsocks; protocol = "shadowsocks";
            settings = @{ method = $ssMethod; password = $password; network = "tcp,udp" }
        }
        outbound = @{
            protocol = "shadowsocks"; tag = "ss-out";
            settings = @{ servers = @(@{ address = "127.0.0.1"; port = $ports.xray_shadowsocks; method = $ssMethod; password = $password }) }
        }
    }
    anytls = @{
        inbound = @{
            listen = "127.0.0.1"; port = $ports.xray_anytls; protocol = "anytls";
            settings = @{ users = @(@{ password = $password; email = "anytls@example.test" }); paddingScheme = $paddingScheme };
            streamSettings = New-XrayTlsStream
        }
        outbound = @{
            protocol = "anytls"; tag = "anytls-out";
            settings = @{ address = "127.0.0.1"; port = $ports.xray_anytls; password = $password; idleSessionCheckInterval = 30; idleSessionTimeout = 60; minIdleSession = 0 };
            streamSettings = New-XrayTlsStream
        }
    }
}

foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
    $inPath = Join-Path $OutDir "xray-$protocol-inbound.json"
    $outPath = Join-Path $OutDir "xray-$protocol-outbound.json"
    Write-Json -Path $inPath -Value (New-XrayBase -Inbounds @($xrayMatrix[$protocol].inbound) -Outbounds $xrayDirect)
    Write-Json -Path $outPath -Value (New-XrayBase -Inbounds $xraySocksInbound -Outbounds @($xrayMatrix[$protocol].outbound))
    $xrayChecks += Invoke-Check -Name "xray-$protocol-inbound-config" -Exe $xray -CommandArgs @("run", "-test", "-config", $inPath)
    $xrayChecks += Invoke-Check -Name "xray-$protocol-outbound-config" -Exe $xray -CommandArgs @("run", "-test", "-config", $outPath)
}

$singChecks = @()
function New-SingBase {
    param([array]$Inbounds, [array]$Outbounds)
    @{
        log = @{ disabled = $true }
        inbounds = $Inbounds
        outbounds = $Outbounds
        route = @{ final = "direct" }
    }
}

$singDirect = @(@{ type = "direct"; tag = "direct" })
$singSocksInbound = @(@{ type = "socks"; tag = "socks-in"; listen = "127.0.0.1"; listen_port = 42480 })
$singTlsServer = @{ enabled = $true; server_name = "localhost"; certificate_path = $cert.certificatePath; key_path = $cert.keyPath }
$singTlsClient = @{ enabled = $true; server_name = "localhost"; insecure = $true }
$singMatrix = @{
    vmess = @{
        inbound = @{ type = "vmess"; tag = "vmess-in"; listen = "127.0.0.1"; listen_port = $ports.sing_vmess; users = @(@{ name = "vmess"; uuid = $uuid; alterId = 0 }) }
        outbound = @{ type = "vmess"; tag = "vmess-out"; server = "127.0.0.1"; server_port = $ports.sing_vmess; uuid = $uuid; security = "auto"; alter_id = 0 }
    }
    trojan = @{
        inbound = @{ type = "trojan"; tag = "trojan-in"; listen = "127.0.0.1"; listen_port = $ports.sing_trojan; users = @(@{ name = "trojan"; password = $password }); tls = $singTlsServer }
        outbound = @{ type = "trojan"; tag = "trojan-out"; server = "127.0.0.1"; server_port = $ports.sing_trojan; password = $password; tls = $singTlsClient }
    }
    shadowsocks = @{
        inbound = @{ type = "shadowsocks"; tag = "ss-in"; listen = "127.0.0.1"; listen_port = $ports.sing_shadowsocks; method = $ssMethod; password = $password }
        outbound = @{ type = "shadowsocks"; tag = "ss-out"; server = "127.0.0.1"; server_port = $ports.sing_shadowsocks; method = $ssMethod; password = $password }
    }
    anytls = @{
        inbound = @{ type = "anytls"; tag = "anytls-in"; listen = "127.0.0.1"; listen_port = $ports.sing_anytls; users = @(@{ name = "anytls"; password = $password }); padding_scheme = $paddingScheme; tls = $singTlsServer }
        outbound = @{ type = "anytls"; tag = "anytls-out"; server = "127.0.0.1"; server_port = $ports.sing_anytls; password = $password; idle_session_check_interval = "30s"; idle_session_timeout = "60s"; min_idle_session = 0; tls = $singTlsClient }
    }
}

foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
    $inPath = Join-Path $OutDir "sing-box-$protocol-inbound.json"
    $outPath = Join-Path $OutDir "sing-box-$protocol-outbound.json"
    Write-Json -Path $inPath -Value (New-SingBase -Inbounds @($singMatrix[$protocol].inbound) -Outbounds $singDirect)
    Write-Json -Path $outPath -Value (New-SingBase -Inbounds $singSocksInbound -Outbounds @($singMatrix[$protocol].outbound))
    $singChecks += Invoke-Check -Name "sing-box-$protocol-inbound-config" -Exe $singBox -CommandArgs @("check", "-c", $inPath)
    $singChecks += Invoke-Check -Name "sing-box-$protocol-outbound-config" -Exe $singBox -CommandArgs @("check", "-c", $outPath)
}

$mihomoConfig = @"
mixed-port: $($ports.mihomo_mixed)
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
listeners:
  - name: vmess-in
    type: vmess
    listen: 127.0.0.1
    port: $($ports.mihomo_vmess)
    users:
      - username: vmess
        uuid: $uuid
        alterId: 0
  - name: trojan-in
    type: trojan
    listen: 127.0.0.1
    port: $($ports.mihomo_trojan)
    users:
      - username: trojan
        password: $password
    certificate: $($cert.certificatePath -replace '\\','/')
    private-key: $($cert.keyPath -replace '\\','/')
  - name: ss-in
    type: shadowsocks
    listen: 127.0.0.1
    port: $($ports.mihomo_shadowsocks)
    cipher: $ssMethod
    password: $password
  - name: anytls-in
    type: anytls
    listen: 127.0.0.1
    port: $($ports.mihomo_anytls)
    users:
      anytls: $password
    certificate: $($cert.certificatePath -replace '\\','/')
    private-key: $($cert.keyPath -replace '\\','/')
    padding-scheme: "$($paddingScheme -join '\n')"
proxies:
  - name: vmess-out
    type: vmess
    server: 127.0.0.1
    port: $($ports.mihomo_vmess)
    uuid: $uuid
    alterId: 0
    cipher: auto
    udp: true
  - name: trojan-out
    type: trojan
    server: 127.0.0.1
    port: $($ports.mihomo_trojan)
    password: $password
    sni: localhost
    skip-cert-verify: true
    udp: true
  - name: ss-out
    type: ss
    server: 127.0.0.1
    port: $($ports.mihomo_shadowsocks)
    cipher: $ssMethod
    password: $password
    udp: true
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: $($ports.mihomo_anytls)
    password: $password
    sni: localhost
    skip-cert-verify: true
    udp: true
    idle-session-check-interval: 30
    idle-session-timeout: 60
    min-idle-session: 0
proxy-groups:
  - name: proxy
    type: select
    proxies:
      - vmess-out
      - trojan-out
      - ss-out
      - anytls-out
rules:
  - MATCH,proxy
"@
$mihomoPath = Join-Path $OutDir "mihomo-all-protocols.yaml"
Write-Utf8NoBom -Path $mihomoPath -Text $mihomoConfig
$mihomoChecks = @(
    Invoke-Check -Name "mihomo-all-protocols-config" -Exe $mihomo -CommandArgs @("-t", "-f", $mihomoPath)
)

$cnodeDir = Join-Path $OutDir "cnode-sidecar-config"
New-Item -ItemType Directory -Force -Path $cnodeDir | Out-Null
Write-Json -Path (Join-Path $cnodeDir "config.json") -Value @{
    log = @{ loglevel = "warning"; logDir = (Join-Path $OutDir "logs") }
    workers = 1
    dns = @{ servers = @("1.1.1.1"); timeout = 5; cacheSize = 32; minTTL = 1; maxTTL = 60 }
    timeouts = @{ handshake = 5; dial = 5; read = 5; write = 5; idle = 30 }
    panels = @()
}
Write-Json -Path (Join-Path $cnodeDir "inbounds.json") -Value @{
    inbounds = @(
        $xrayMatrix.vmess.inbound,
        $xrayMatrix.trojan.inbound,
        $xrayMatrix.shadowsocks.inbound,
        $xrayMatrix.anytls.inbound
    )
}
Write-Json -Path (Join-Path $cnodeDir "outbounds.json") -Value @{
    outbounds = @(
        @{ tag = "direct"; protocol = "freedom"; settings = @{ domainStrategy = "AsIs" } },
        $xrayMatrix.vmess.outbound,
        $xrayMatrix.trojan.outbound,
        $xrayMatrix.shadowsocks.outbound,
        $xrayMatrix.anytls.outbound
    )
}
Write-Json -Path (Join-Path $cnodeDir "routing.json") -Value @{
    routing = @{
        domainStrategy = "AsIs"
        rules = @(
            @{ inboundTag = @("vmess-42101"); outboundTag = "direct" }
        )
    }
}

$checks = @()
$checks += $xrayChecks
$checks += $singChecks
$checks += $mihomoChecks

$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    mode = "config-only"
    root = $Root
    out_dir = $OutDir
    checks = $checks
}
Write-Json -Path (Join-Path $OutDir "summary.json") -Value $summary

$failed = @($checks | Where-Object { -not $_.ok })
if ($failed.Count -gt 0) {
    Write-Host "CONFIG MATRIX FAILED ($($failed.Count) failed):"
    foreach ($item in $failed) {
        Write-Host "  - $($item.name) exit=$($item.exit_code) log=$($item.log)"
    }
    if (-not $KeepGoing) {
        exit 1
    }
}

Write-Host "CONFIG MATRIX OK ($($checks.Count) checks). Output: $OutDir"
