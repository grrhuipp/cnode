param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$OutDir = "",
    [switch]$KeepGoing
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "build\e2e-external-traffic"
}

$xray = Join-Path $Root "tools\xray-core-anytls\xray.exe"
if (-not (Test-Path $xray)) {
    $xray = Join-Path $Root "tools\xray-core-latest\xray.exe"
}
$mihomo = Join-Path $Root "tools\mihomo\mihomo-windows-amd64.exe"
$singBox = Join-Path $Root "tools\sing-box\sing-box.exe"
$cnode = Join-Path $Root "build\cnode.exe"

foreach ($tool in @($xray, $mihomo, $singBox, $cnode, "curl.exe", "powershell.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue) -and -not (Test-Path $tool)) {
        throw "required tool not found: $tool"
    }
}

if (Test-Path $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
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
    Write-Utf8NoBom -Path $Path -Text ($Value | ConvertTo-Json -Depth 80)
}

function ConvertTo-ForwardPath {
    param([string]$Path)
    return ($Path -replace "\\", "/")
}

function Get-CertSha256Hex {
    param([string]$PemPath)
    $pem = Get-Content $PemPath -Raw
    $body = ($pem -replace "-----BEGIN CERTIFICATE-----", "" -replace "-----END CERTIFICATE-----", "" -replace "\s", "")
    $der = [Convert]::FromBase64String($body)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($der)
    return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function New-XrayTlsCertificate {
    $raw = & $xray tls cert --domain=localhost
    if ($LASTEXITCODE -ne 0) {
        throw "xray tls cert failed"
    }
    $cert = ($raw | Out-String | ConvertFrom-Json)
    $certPath = Join-Path $certDir "localhost.crt"
    $keyPath = Join-Path $certDir "localhost.key"
    $keyText = (($cert.key -join "`n") + "`n")
    $keyText = $keyText.Replace("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY")
    $keyText = $keyText.Replace("END RSA PRIVATE KEY", "END PRIVATE KEY")
    Write-Utf8NoBom -Path $certPath -Text (($cert.certificate -join "`n") + "`n")
    Write-Utf8NoBom -Path $keyPath -Text $keyText
    [pscustomobject]@{
        certificatePath = $certPath
        keyPath = $keyPath
        xrayCertificate = $cert.certificate
        xrayKey = $cert.key
        pinnedSha256 = Get-CertSha256Hex $certPath
    }
}

function Test-PortOpen {
    param([int]$Port)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        if (-not $task.Wait(200)) {
            $client.Close()
            return $false
        }
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

function Wait-Port {
    param([int]$Port, [string]$Name, [int]$TimeoutMs = 8000)
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortOpen $Port) {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw "timeout waiting for $Name on 127.0.0.1:$Port"
}

function Start-LoggedProcess {
    param(
        [string]$Name,
        [string]$Exe,
        [string[]]$CommandArgs,
        [string]$WorkDir = $OutDir
    )
    $logDir = Join-Path $OutDir "logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $stdout = Join-Path $logDir "$Name.out.log"
    $stderr = Join-Path $logDir "$Name.err.log"
    Remove-Item -Force $stdout,$stderr -ErrorAction SilentlyContinue
    $p = Start-Process -FilePath $Exe -ArgumentList $CommandArgs -WorkingDirectory $WorkDir `
        -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [pscustomobject]@{ name = $Name; process = $p; stdout = $stdout; stderr = $stderr }
}

function Stop-LoggedProcess {
    param($Proc)
    if ($null -ne $Proc -and $null -ne $Proc.process -and -not $Proc.process.HasExited) {
        Stop-Process -Id $Proc.process.Id -Force -ErrorAction SilentlyContinue
        $Proc.process.WaitForExit(3000) | Out-Null
    }
}

function Invoke-CurlThroughSocks {
    param([string]$Name, [int]$SocksPort, [int]$HttpPort)
    $url = "http://127.0.0.1:$HttpPort/$Name"
    $output = & curl.exe --silent --show-error --fail --max-time 10 `
        --socks5-hostname "127.0.0.1:$SocksPort" $url 2>&1
    $exit = $LASTEXITCODE
    [pscustomobject]@{
        ok = ($exit -eq 0 -and (($output | Out-String) -match "CNODE_E2E_OK"))
        exit_code = $exit
        output = ($output | Out-String).Trim()
        url = $url
    }
}

function New-XrayTlsStreamServer {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = "localhost"
            certificates = @(@{
                certificate = $script:cert.xrayCertificate
                key = $script:cert.xrayKey
            })
        }
    }
}

function New-XrayTlsStreamClient {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = "localhost"
            pinnedPeerCertSha256 = $script:cert.pinnedSha256
        }
    }
}

function New-CnodeTlsStreamServer {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = "localhost"
            certificates = @(@{
                certificateFile = $script:cert.certificatePath
                keyFile = $script:cert.keyPath
            })
        }
    }
}

function New-CnodeTlsStreamClient {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = "localhost"
            allowInsecure = $true
        }
    }
}

function New-XrayConfig {
    param([array]$Inbounds, [array]$Outbounds)
    @{ log = @{ loglevel = "warning" }; inbounds = $Inbounds; outbounds = $Outbounds }
}

function New-SingConfig {
    param([array]$Inbounds, [array]$Outbounds, [string]$Final = "proxy")
    $allOutbounds = @($Outbounds)
    if (-not ($allOutbounds | Where-Object { $_.tag -eq "direct" })) {
        $allOutbounds += @{ type = "direct"; tag = "direct" }
    }
    @{ log = @{ disabled = $true }; inbounds = $Inbounds; outbounds = $allOutbounds; route = @{ final = $Final } }
}

function Invoke-TcpGreeting {
    param([string]$Name, [int]$Port)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        if (-not $task.Wait(3000)) {
            $client.Close()
            return [pscustomobject]@{ ok = $false; exit_code = 1; output = "connect timeout"; url = "tcp://127.0.0.1:$Port/$Name" }
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 10000
        $buffer = New-Object byte[] 1024
        $n = $stream.Read($buffer, 0, $buffer.Length)
        $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $n)
        $client.Close()
        [pscustomobject]@{ ok = ($text -match "CNODE_E2E_OK"); exit_code = 0; output = $text; url = "tcp://127.0.0.1:$Port/$Name" }
    } catch {
        [pscustomobject]@{ ok = $false; exit_code = 1; output = $_.Exception.Message; url = "tcp://127.0.0.1:$Port/$Name" }
    }
}

function New-CnodeDirectory {
    param([string]$Dir, [array]$Inbounds, [array]$Outbounds, [array]$Rules)
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Write-Json -Path (Join-Path $Dir "config.json") -Value @{
        log = @{ loglevel = "warning"; logDir = (Join-Path $Dir "logs") }
        workers = 1
        dns = @{ servers = @("1.1.1.1"); timeout = 5; cacheSize = 32; minTTL = 1; maxTTL = 60 }
        timeouts = @{ handshake = 5; dial = 5; read = 5; write = 5; idle = 20 }
        panels = @()
    }
    Write-Json -Path (Join-Path $Dir "inbounds.json") -Value @{ inbounds = $Inbounds }
    Write-Json -Path (Join-Path $Dir "outbounds.json") -Value @{ outbounds = $Outbounds }
    Write-Json -Path (Join-Path $Dir "routing.json") -Value @{ routing = @{ domainStrategy = "AsIs"; rules = $Rules } }
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

$httpScript = Join-Path $OutDir "http_server.ps1"
Write-Utf8NoBom -Path $httpScript -Text @'
param([int]$Port)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $Port)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 1000
            $buffer = New-Object byte[] 4096
            try {
                $read = $stream.Read($buffer, 0, $buffer.Length)
            } catch {
                $read = 0
            }
            if ($read -le 0) {
                $body = "CNODE_E2E_OK"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($body)
                $stream.Write($bytes, 0, $bytes.Length)
                continue
            }
            $body = "CNODE_E2E_OK"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
            $stream.Write($bytes, 0, $bytes.Length)
        } finally {
            $client.Close()
        }
    }
} finally {
    $listener.Stop()
}
'@

$basePort = 45100
$caseIndex = 0
$results = @()

function Get-NextPorts {
    $script:caseIndex += 1
    $base = $script:basePort + ($script:caseIndex * 10)
    [pscustomobject]@{
        http = $base + 1
        cnode = $base + 2
        socks = $base + 3
        server = $base + 4
        ingress = $base + 5
    }
}

function Get-CnodeInbound {
    param([string]$Protocol, [int]$Port, [string]$Tag)
    $settings = switch ($Protocol) {
        "vmess" { @{ clients = @(@{ id = $script:uuid; alterId = 0; email = "vmess@example.test" }) } }
        "trojan" { @{ clients = @(@{ password = $script:password; email = "trojan@example.test" }) } }
        "shadowsocks" { @{ method = $script:ssMethod; password = $script:password; network = "tcp,udp" } }
        "anytls" { @{ users = @(@{ password = $script:password; email = "anytls@example.test" }); paddingScheme = $script:paddingScheme } }
    }
    $inbound = @{ tag = $Tag; listen = "127.0.0.1"; port = $Port; protocol = $Protocol; settings = $settings }
    if ($Protocol -eq "trojan" -or $Protocol -eq "anytls") {
        $inbound.streamSettings = New-CnodeTlsStreamServer
    }
    $inbound
}

function Get-CnodeOutbound {
    param([string]$Protocol, [int]$Port, [string]$Tag)
    $settings = switch ($Protocol) {
        "vmess" { @{ vnext = @(@{ address = "127.0.0.1"; port = $Port; users = @(@{ id = $script:uuid; alterId = 0; security = "auto" }) }) } }
        "trojan" { @{ servers = @(@{ address = "127.0.0.1"; port = $Port; password = $script:password }) } }
        "shadowsocks" { @{ servers = @(@{ address = "127.0.0.1"; port = $Port; method = $script:ssMethod; password = $script:password }) } }
        "anytls" { @{ address = "127.0.0.1"; port = $Port; password = $script:password; idleSessionCheckInterval = 30; idleSessionTimeout = 60; minIdleSession = 0 } }
    }
    $outbound = @{ tag = $Tag; protocol = $Protocol; settings = $settings }
    if ($Protocol -eq "trojan" -or $Protocol -eq "anytls") {
        $outbound.streamSettings = New-CnodeTlsStreamClient
    }
    $outbound
}

function Get-XrayOutboundToCnode {
    param([string]$Protocol, [int]$Port)
    $outbound = switch ($Protocol) {
        "vmess" { @{ protocol = "vmess"; tag = "proxy"; settings = @{ vnext = @(@{ address = "127.0.0.1"; port = $Port; users = @(@{ id = $script:uuid; alterId = 0; security = "none" }) }) } } }
        "trojan" { @{ protocol = "trojan"; tag = "proxy"; settings = @{ servers = @(@{ address = "127.0.0.1"; port = $Port; password = $script:password }) }; streamSettings = New-XrayTlsStreamClient } }
        "shadowsocks" { @{ protocol = "shadowsocks"; tag = "proxy"; settings = @{ servers = @(@{ address = "127.0.0.1"; port = $Port; method = $script:ssMethod; password = $script:password }) } } }
        "anytls" { @{ protocol = "anytls"; tag = "proxy"; settings = @{ address = "127.0.0.1"; port = $Port; password = $script:password; idleSessionCheckInterval = 30; idleSessionTimeout = 60; minIdleSession = 0 }; streamSettings = New-XrayTlsStreamClient } }
    }
    $outbound
}

function Get-XrayServerInbound {
    param([string]$Protocol, [int]$Port)
    $inbound = switch ($Protocol) {
        "vmess" { @{ listen = "127.0.0.1"; port = $Port; protocol = "vmess"; settings = @{ clients = @(@{ id = $script:uuid; alterId = 0; email = "vmess@example.test" }) } } }
        "trojan" { @{ listen = "127.0.0.1"; port = $Port; protocol = "trojan"; settings = @{ clients = @(@{ password = $script:password; email = "trojan@example.test" }) }; streamSettings = New-XrayTlsStreamServer } }
        "shadowsocks" { @{ listen = "127.0.0.1"; port = $Port; protocol = "shadowsocks"; settings = @{ method = $script:ssMethod; password = $script:password; network = "tcp,udp" } } }
        "anytls" { @{ listen = "127.0.0.1"; port = $Port; protocol = "anytls"; settings = @{ users = @(@{ password = $script:password; email = "anytls@example.test" }); paddingScheme = $script:paddingScheme }; streamSettings = New-XrayTlsStreamServer } }
    }
    $inbound
}

function Get-SingOutboundToCnode {
    param([string]$Protocol, [int]$Port)
    switch ($Protocol) {
        "vmess" { @{ type = "vmess"; tag = "proxy"; server = "127.0.0.1"; server_port = $Port; uuid = $script:uuid; security = "auto"; alter_id = 0 } }
        "trojan" { @{ type = "trojan"; tag = "proxy"; server = "127.0.0.1"; server_port = $Port; password = $script:password; tls = @{ enabled = $true; server_name = "localhost"; insecure = $true } } }
        "shadowsocks" { @{ type = "shadowsocks"; tag = "proxy"; server = "127.0.0.1"; server_port = $Port; method = $script:ssMethod; password = $script:password } }
        "anytls" { @{ type = "anytls"; tag = "proxy"; server = "127.0.0.1"; server_port = $Port; password = $script:password; idle_session_check_interval = "30s"; idle_session_timeout = "60s"; min_idle_session = 0; tls = @{ enabled = $true; server_name = "localhost"; insecure = $true } } }
    }
}

function Get-SingServerInbound {
    param([string]$Protocol, [int]$Port)
    switch ($Protocol) {
        "vmess" { @{ type = "vmess"; tag = "server"; listen = "127.0.0.1"; listen_port = $Port; users = @(@{ name = "vmess"; uuid = $script:uuid; alterId = 0 }) } }
        "trojan" { @{ type = "trojan"; tag = "server"; listen = "127.0.0.1"; listen_port = $Port; users = @(@{ name = "trojan"; password = $script:password }); tls = @{ enabled = $true; server_name = "localhost"; certificate_path = $script:cert.certificatePath; key_path = $script:cert.keyPath } } }
        "shadowsocks" { @{ type = "shadowsocks"; tag = "server"; listen = "127.0.0.1"; listen_port = $Port; method = $script:ssMethod; password = $script:password } }
        "anytls" { @{ type = "anytls"; tag = "server"; listen = "127.0.0.1"; listen_port = $Port; users = @(@{ name = "anytls"; password = $script:password }); padding_scheme = $script:paddingScheme; tls = @{ enabled = $true; server_name = "localhost"; certificate_path = $script:cert.certificatePath; key_path = $script:cert.keyPath } } }
    }
}

function Write-MihomoClientConfig {
    param([string]$Path, [string]$Protocol, [int]$SocksPort, [int]$ServerPort, [int]$TunnelTargetPort = 0)
    $proxy = switch ($Protocol) {
        "vmess" {
@"
  - name: proxy
    type: vmess
    server: 127.0.0.1
    port: $ServerPort
    uuid: $script:uuid
    alterId: 0
    cipher: auto
    udp: true
"@
        }
        "trojan" {
@"
  - name: proxy
    type: trojan
    server: 127.0.0.1
    port: $ServerPort
    password: $script:password
    sni: localhost
    skip-cert-verify: true
    udp: true
"@
        }
        "shadowsocks" {
@"
  - name: proxy
    type: ss
    server: 127.0.0.1
    port: $ServerPort
    cipher: $script:ssMethod
    password: $script:password
    udp: true
"@
        }
        "anytls" {
@"
  - name: proxy
    type: anytls
    server: 127.0.0.1
    port: $ServerPort
    password: $script:password
    sni: localhost
    skip-cert-verify: true
    udp: true
    idle-session-check-interval: 30
    idle-session-timeout: 60
    min-idle-session: 0
"@
        }
    }
    if ($Protocol -eq "trojan") {
        $yaml = @"
allow-lan: false
mode: rule
log-level: warning
tunnels:
  - network: [tcp]
    address: 127.0.0.1:$SocksPort
    target: 127.0.0.1:$TunnelTargetPort
    proxy: proxy
proxies:
$proxy
proxy-groups:
  - name: selected
    type: select
    proxies:
      - proxy
rules:
  - MATCH,selected
"@
        Write-Utf8NoBom -Path $Path -Text $yaml
        return
    }
    $yaml = @"
mixed-port: $SocksPort
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
proxies:
$proxy
proxy-groups:
  - name: selected
    type: select
    proxies:
      - proxy
rules:
  - MATCH,selected
"@
    Write-Utf8NoBom -Path $Path -Text $yaml
}

function Write-MihomoServerConfig {
    param([string]$Path, [string]$Protocol, [int]$Port)
    $mihomoCert = Join-Path (Split-Path -Parent $Path) "localhost.crt"
    $mihomoKey = Join-Path (Split-Path -Parent $Path) "localhost.key"
    Copy-Item -LiteralPath $script:cert.certificatePath -Destination $mihomoCert -Force
    Copy-Item -LiteralPath $script:cert.keyPath -Destination $mihomoKey -Force
    $listener = switch ($Protocol) {
        "vmess" {
@"
  - name: server
    type: vmess
    listen: 127.0.0.1
    port: $Port
    users:
      - username: vmess
        uuid: $script:uuid
        alterId: 0
"@
        }
        "trojan" {
@"
  - name: server
    type: trojan
    listen: 127.0.0.1
    port: $Port
    users:
      - username: trojan
        password: $script:password
    certificate: $(ConvertTo-ForwardPath $mihomoCert)
    private-key: $(ConvertTo-ForwardPath $mihomoKey)
"@
        }
        "shadowsocks" {
@"
  - name: server
    type: shadowsocks
    listen: 127.0.0.1
    port: $Port
    cipher: $script:ssMethod
    password: $script:password
"@
        }
        "anytls" {
@"
  - name: server
    type: anytls
    listen: 127.0.0.1
    port: $Port
    users:
      anytls: $script:password
    certificate: $(ConvertTo-ForwardPath $mihomoCert)
    private-key: $(ConvertTo-ForwardPath $mihomoKey)
    padding-scheme: "$($script:paddingScheme -join '\n')"
"@
        }
    }
    $yaml = @"
mixed-port: 0
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
listeners:
$listener
rules:
  - MATCH,DIRECT
"@
    Write-Utf8NoBom -Path $Path -Text $yaml
}

function Run-InboundCase {
    param([string]$Impl, [string]$Protocol)
    $ports = Get-NextPorts
    $name = "inbound-$Impl-$Protocol"
    $caseDir = Join-Path $OutDir $name
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $procs = @()
    $ok = $false
    $detail = ""
    try {
        $procs += Start-LoggedProcess -Name "$name-http" -Exe "powershell.exe" -CommandArgs @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $httpScript, "-Port", "$($ports.http)")
        Wait-Port -Port $ports.http -Name "$name http"

        New-CnodeDirectory -Dir (Join-Path $caseDir "cnode") `
            -Inbounds @((Get-CnodeInbound -Protocol $Protocol -Port $ports.cnode -Tag "tested-in")) `
            -Outbounds @(@{ tag = "direct"; protocol = "freedom"; settings = @{ domainStrategy = "AsIs" } }) `
            -Rules @()
        $procs += Start-LoggedProcess -Name "$name-cnode" -Exe $cnode -CommandArgs @("-c", (Join-Path $caseDir "cnode"))
        Wait-Port -Port $ports.cnode -Name "$name cnode"

        if ($Impl -eq "xray") {
            $cfg = New-XrayConfig `
                -Inbounds @(@{ listen = "127.0.0.1"; port = $ports.socks; protocol = "socks"; settings = @{ udp = $true } }) `
                -Outbounds @((Get-XrayOutboundToCnode -Protocol $Protocol -Port $ports.cnode))
            $path = Join-Path $caseDir "client.json"
            Write-Json -Path $path -Value $cfg
            $procs += Start-LoggedProcess -Name "$name-xray-client" -Exe $xray -CommandArgs @("run", "-config", $path)
        } elseif ($Impl -eq "sing-box") {
            $cfg = New-SingConfig `
                -Inbounds @(@{ type = "socks"; tag = "socks-in"; listen = "127.0.0.1"; listen_port = $ports.socks }) `
                -Outbounds @((Get-SingOutboundToCnode -Protocol $Protocol -Port $ports.cnode))
            $path = Join-Path $caseDir "client.json"
            Write-Json -Path $path -Value $cfg
            $procs += Start-LoggedProcess -Name "$name-sing-client" -Exe $singBox -CommandArgs @("run", "-c", $path)
        } else {
            $path = Join-Path $caseDir "client.yaml"
            Write-MihomoClientConfig -Path $path -Protocol $Protocol -SocksPort $ports.socks -ServerPort $ports.cnode -TunnelTargetPort $ports.http
            $procs += Start-LoggedProcess -Name "$name-mihomo-client" -Exe $mihomo -CommandArgs @("-f", $path, "-d", $caseDir)
        }
        Wait-Port -Port $ports.socks -Name "$name socks"
        if ($Impl -eq "mihomo" -and $Protocol -eq "trojan") {
            $curl = Invoke-TcpGreeting -Name $name -Port $ports.socks
        } else {
            $curl = Invoke-CurlThroughSocks -Name $name -SocksPort $ports.socks -HttpPort $ports.http
        }
        $ok = $curl.ok
        $detail = $curl.output
    } catch {
        $detail = $_.Exception.Message
    } finally {
        foreach ($p in @($procs | Sort-Object { $_.name } -Descending)) {
            Stop-LoggedProcess $p
        }
    }
    [pscustomobject]@{ name = $name; direction = "cnode-inbound"; implementation = $Impl; protocol = $Protocol; ok = $ok; detail = $detail; dir = $caseDir }
}

function Run-OutboundCase {
    param([string]$Impl, [string]$Protocol)
    $ports = Get-NextPorts
    $name = "outbound-$Impl-$Protocol"
    $caseDir = Join-Path $OutDir $name
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $procs = @()
    $ok = $false
    $detail = ""
    try {
        $procs += Start-LoggedProcess -Name "$name-http" -Exe "powershell.exe" -CommandArgs @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $httpScript, "-Port", "$($ports.http)")
        Wait-Port -Port $ports.http -Name "$name http"

        if ($Impl -eq "xray") {
            $path = Join-Path $caseDir "server.json"
            Write-Json -Path $path -Value (New-XrayConfig -Inbounds @((Get-XrayServerInbound -Protocol $Protocol -Port $ports.server)) -Outbounds @(@{ protocol = "freedom"; tag = "direct" }))
            $procs += Start-LoggedProcess -Name "$name-xray-server" -Exe $xray -CommandArgs @("run", "-config", $path)
        } elseif ($Impl -eq "sing-box") {
            $path = Join-Path $caseDir "server.json"
            Write-Json -Path $path -Value (New-SingConfig -Inbounds @((Get-SingServerInbound -Protocol $Protocol -Port $ports.server)) -Outbounds @(@{ type = "direct"; tag = "direct" }) -Final "direct")
            $procs += Start-LoggedProcess -Name "$name-sing-server" -Exe $singBox -CommandArgs @("run", "-c", $path)
        } else {
            $path = Join-Path $caseDir "server.yaml"
            Write-MihomoServerConfig -Path $path -Protocol $Protocol -Port $ports.server
            $procs += Start-LoggedProcess -Name "$name-mihomo-server" -Exe $mihomo -CommandArgs @("-f", $path, "-d", $caseDir)
        }
        Wait-Port -Port $ports.server -Name "$name external server"

        New-CnodeDirectory -Dir (Join-Path $caseDir "cnode") `
            -Inbounds @((Get-CnodeInbound -Protocol "vmess" -Port $ports.ingress -Tag "ingress")) `
            -Outbounds @((Get-CnodeOutbound -Protocol $Protocol -Port $ports.server -Tag "tested-out")) `
            -Rules @(@{ inboundTag = @("ingress"); outboundTag = "tested-out" })
        $procs += Start-LoggedProcess -Name "$name-cnode" -Exe $cnode -CommandArgs @("-c", (Join-Path $caseDir "cnode"))
        Wait-Port -Port $ports.ingress -Name "$name cnode ingress"

        $singClient = New-SingConfig `
            -Inbounds @(@{ type = "socks"; tag = "socks-in"; listen = "127.0.0.1"; listen_port = $ports.socks }) `
            -Outbounds @((Get-SingOutboundToCnode -Protocol "vmess" -Port $ports.ingress))
        $clientPath = Join-Path $caseDir "client.json"
        Write-Json -Path $clientPath -Value $singClient
        $procs += Start-LoggedProcess -Name "$name-sing-client" -Exe $singBox -CommandArgs @("run", "-c", $clientPath)
        Wait-Port -Port $ports.socks -Name "$name socks"

        $curl = Invoke-CurlThroughSocks -Name $name -SocksPort $ports.socks -HttpPort $ports.http
        $ok = $curl.ok
        $detail = $curl.output
    } catch {
        $detail = $_.Exception.Message
    } finally {
        foreach ($p in @($procs | Sort-Object { $_.name } -Descending)) {
            Stop-LoggedProcess $p
        }
    }
    [pscustomObject]@{ name = $name; direction = "cnode-outbound"; implementation = $Impl; protocol = $Protocol; ok = $ok; detail = $detail; dir = $caseDir }
}

foreach ($impl in @("xray", "mihomo", "sing-box")) {
    foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
        $result = Run-InboundCase -Impl $impl -Protocol $protocol
        $results += $result
        Write-Host "$($result.name): $($result.ok)"
        if (-not $result.ok -and -not $KeepGoing) { break }
    }
    if (($results | Where-Object { -not $_.ok }).Count -gt 0 -and -not $KeepGoing) { break }
}

if (($results | Where-Object { -not $_.ok }).Count -eq 0 -or $KeepGoing) {
    foreach ($impl in @("xray", "mihomo", "sing-box")) {
        foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
            $result = Run-OutboundCase -Impl $impl -Protocol $protocol
            $results += $result
            Write-Host "$($result.name): $($result.ok)"
            if (-not $result.ok -and -not $KeepGoing) { break }
        }
        if (($results | Where-Object { -not $_.ok }).Count -gt 0 -and -not $KeepGoing) { break }
    }
}

$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    mode = "traffic"
    root = $Root
    out_dir = $OutDir
    checks = $results
}
Write-Json -Path (Join-Path $OutDir "summary.json") -Value $summary

$failed = @($results | Where-Object { -not $_.ok })
if ($failed.Count -gt 0) {
    Write-Host "TRAFFIC MATRIX FAILED ($($failed.Count) failed):"
    foreach ($item in $failed) {
        Write-Host "  - $($item.name): $($item.detail) dir=$($item.dir)"
    }
    exit 1
}

Write-Host "TRAFFIC MATRIX OK ($($results.Count) checks). Output: $OutDir"
