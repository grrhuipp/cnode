param(
    [string]$RemoteHost = "node-02.11.9527app.site",
    [string]$RemoteUser = "root",
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$RemoteCnode = "/opt/cnode-e2e/bin/cnode",
    [string]$OutDir = "",
    [switch]$UseSshTunnel,
    [switch]$KeepRemoteRunning
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "build\remote-cnode-inbound-traffic"
}

$remote = "$RemoteUser@$RemoteHost"
$remoteRoot = "/opt/cnode-e2e"
$remoteConfig = "$remoteRoot/config"
$remoteHttpPort = 46200
$remoteGreetingPort = 46205
$remotePorts = @{
    vmess = 46201
    trojan = 46202
    shadowsocks = 46203
    anytls = 46204
}
$tunnelPorts = @{
    vmess = 56201
    trojan = 56202
    shadowsocks = 56203
    anytls = 56204
}
$connectHost = $RemoteHost
$connectPorts = $remotePorts

$xray = Join-Path $Root "tools\xray-core-anytls\xray.exe"
if (-not (Test-Path $xray)) {
    $xray = Join-Path $Root "tools\xray-core-latest\xray.exe"
}
$mihomo = Join-Path $Root "tools\mihomo\mihomo-windows-amd64.exe"
$singBox = Join-Path $Root "tools\sing-box\sing-box.exe"

foreach ($tool in @($xray, $mihomo, $singBox, "curl.exe", "ssh.exe", "scp.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue) -and -not (Test-Path $tool)) {
        throw "required tool not found: $tool"
    }
}

if (Test-Path $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

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

function Invoke-Remote {
    param([string]$Command)
    & ssh -o BatchMode=yes $remote $Command
    if ($LASTEXITCODE -ne 0) {
        throw "remote command failed: $Command"
    }
}

function Test-TcpOpen {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 500)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            $client.Close()
            return $false
        }
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

function Wait-TcpOpen {
    param([string]$HostName, [int]$Port, [string]$Name, [int]$TimeoutMs = 10000)
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline) {
        if (Test-TcpOpen -HostName $HostName -Port $Port) {
            return
        }
        Start-Sleep -Milliseconds 150
    }
    throw "timeout waiting for $Name on ${HostName}:$Port"
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
    param([string]$Domain, [string]$Dir)
    $raw = & $xray tls cert --domain=$Domain
    if ($LASTEXITCODE -ne 0) {
        throw "xray tls cert failed"
    }
    $cert = ($raw | Out-String | ConvertFrom-Json)
    $certPath = Join-Path $Dir "server.crt"
    $keyPath = Join-Path $Dir "server.key"
    $keyText = (($cert.key -join "`n") + "`n")
    $keyText = $keyText.Replace("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY")
    $keyText = $keyText.Replace("END RSA PRIVATE KEY", "END PRIVATE KEY")
    Write-Utf8NoBom -Path $certPath -Text (($cert.certificate -join "`n") + "`n")
    Write-Utf8NoBom -Path $keyPath -Text $keyText
    [pscustomobject]@{
        certificatePath = $certPath
        keyPath = $keyPath
        pinnedSha256 = Get-CertSha256Hex $certPath
    }
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
    param([int]$SocksPort, [string]$Name)
    $url = "http://127.0.0.1:$remoteHttpPort/$Name"
    $output = & curl.exe --silent --show-error --fail --max-time 12 `
        --socks5-hostname "127.0.0.1:$SocksPort" $url 2>&1
    $exit = $LASTEXITCODE
    [pscustomobject]@{
        ok = ($exit -eq 0 -and (($output | Out-String) -match "CNODE_REMOTE_OK"))
        exit_code = $exit
        output = ($output | Out-String).Trim()
    }
}

function Invoke-TcpGreeting {
    param([int]$Port)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        if (-not $task.Wait(3000)) {
            $client.Close()
            return [pscustomobject]@{ ok = $false; exit_code = 1; output = "connect timeout" }
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 12000
        $buffer = New-Object byte[] 1024
        $n = $stream.Read($buffer, 0, $buffer.Length)
        $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $n)
        $client.Close()
        [pscustomobject]@{ ok = ($text -match "CNODE_REMOTE_OK"); exit_code = 0; output = $text.Trim() }
    } catch {
        [pscustomobject]@{ ok = $false; exit_code = 1; output = $_.Exception.Message }
    }
}

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

$configDir = Join-Path $OutDir "remote-config"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$cert = New-XrayTlsCertificate -Domain $RemoteHost -Dir $configDir

$tlsServer = @{
    network = "tcp"
    security = "tls"
    tlsSettings = @{
        serverName = $RemoteHost
        certificates = @(@{
            certificateFile = "$remoteConfig/server.crt"
            keyFile = "$remoteConfig/server.key"
        })
    }
}

$inbounds = @(
    @{ tag = "vmess-in"; listen = "0.0.0.0"; port = $remotePorts.vmess; protocol = "vmess"; settings = @{ clients = @(@{ id = $uuid; alterId = 0; email = "vmess@example.test" }) } },
    @{ tag = "trojan-in"; listen = "0.0.0.0"; port = $remotePorts.trojan; protocol = "trojan"; settings = @{ clients = @(@{ password = $password; email = "trojan@example.test" }) }; streamSettings = $tlsServer },
    @{ tag = "shadowsocks-in"; listen = "0.0.0.0"; port = $remotePorts.shadowsocks; protocol = "shadowsocks"; settings = @{ method = $ssMethod; password = $password; network = "tcp,udp" } },
    @{ tag = "anytls-in"; listen = "0.0.0.0"; port = $remotePorts.anytls; protocol = "anytls"; settings = @{ users = @(@{ password = $password; email = "anytls@example.test" }); paddingScheme = $paddingScheme }; streamSettings = $tlsServer }
)

Write-Json -Path (Join-Path $configDir "config.json") -Value @{
    log = @{ loglevel = "debug"; logDir = "$remoteRoot/logs" }
    workers = 1
    dns = @{ servers = @("1.1.1.1"); timeout = 5; cacheSize = 32; minTTL = 1; maxTTL = 60 }
    timeouts = @{ handshake = 8; dial = 8; read = 8; write = 8; idle = 30 }
    panels = @()
}
Write-Json -Path (Join-Path $configDir "inbounds.json") -Value @{ inbounds = $inbounds }
Write-Json -Path (Join-Path $configDir "outbounds.json") -Value @{ outbounds = @(@{ tag = "direct"; protocol = "freedom"; settings = @{ domainStrategy = "AsIs" } }) }
Write-Json -Path (Join-Path $configDir "routing.json") -Value @{ routing = @{ domainStrategy = "AsIs"; rules = @() } }

$httpScript = Join-Path $OutDir "remote_http_server.py"
Write-Utf8NoBom -Path $httpScript -Text @'
import socket
import sys

port = int(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else "http"
body = b"CNODE_REMOTE_OK"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(64)
try:
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(8.0 if mode == "http" else 1.0)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                data = b""
            if data:
                try:
                    first_line = data.split(b"\r\n", 1)[0]
                    print("%s recv %d bytes: %r" % (mode, len(data), first_line), flush=True)
                except Exception:
                    pass
                response = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
                conn.sendall(response + body)
            elif mode == "greeting":
                print("%s greeting" % mode, flush=True)
                conn.sendall(body)
            else:
                print("%s timeout/no-data" % mode, flush=True)
finally:
    server.close()
'@

Invoke-Remote "set -e; mkdir -p $remoteRoot $remoteRoot/logs; if [ -f $remoteRoot/cnode.pid ]; then kill `$(cat $remoteRoot/cnode.pid) 2>/dev/null || true; rm -f $remoteRoot/cnode.pid; fi; if [ -f $remoteRoot/http.pid ]; then kill `$(cat $remoteRoot/http.pid) 2>/dev/null || true; rm -f $remoteRoot/http.pid; fi; if [ -f $remoteRoot/greeting.pid ]; then kill `$(cat $remoteRoot/greeting.pid) 2>/dev/null || true; rm -f $remoteRoot/greeting.pid; fi; rm -rf $remoteConfig; mkdir -p $remoteConfig"
& scp -q -r $configDir\* "${remote}:$remoteConfig/"
if ($LASTEXITCODE -ne 0) { throw "scp config failed" }
& scp -q $httpScript "${remote}:$remoteRoot/http_server.py"
if ($LASTEXITCODE -ne 0) { throw "scp http server failed" }

Invoke-Remote "set -e; nohup python3 $remoteRoot/http_server.py $remoteHttpPort http > $remoteRoot/http.out 2> $remoteRoot/http.err < /dev/null & echo `$! > $remoteRoot/http.pid; nohup python3 $remoteRoot/http_server.py $remoteGreetingPort greeting > $remoteRoot/greeting.out 2> $remoteRoot/greeting.err < /dev/null & echo `$! > $remoteRoot/greeting.pid; nohup $remoteCnode -c $remoteConfig > $remoteRoot/cnode.out 2> $remoteRoot/cnode.err < /dev/null & echo `$! > $remoteRoot/cnode.pid"

$tunnelProc = $null
if (-not $UseSshTunnel) {
    try {
        Wait-TcpOpen -HostName $RemoteHost -Port $remotePorts.vmess -Name "remote cnode vmess" -TimeoutMs 3000
        Wait-TcpOpen -HostName $RemoteHost -Port $remotePorts.trojan -Name "remote cnode trojan" -TimeoutMs 3000
        Wait-TcpOpen -HostName $RemoteHost -Port $remotePorts.shadowsocks -Name "remote cnode shadowsocks" -TimeoutMs 3000
        Wait-TcpOpen -HostName $RemoteHost -Port $remotePorts.anytls -Name "remote cnode anytls" -TimeoutMs 3000
    } catch {
        Write-Host "Public remote ports are not reachable, falling back to SSH local forwards: $($_.Exception.Message)"
        $UseSshTunnel = $true
    }
}

if ($UseSshTunnel) {
    $sshArgs = @(
        "-N",
        "-o", "BatchMode=yes",
        "-o", "ExitOnForwardFailure=yes",
        "-L", "$($tunnelPorts.vmess):127.0.0.1:$($remotePorts.vmess)",
        "-L", "$($tunnelPorts.trojan):127.0.0.1:$($remotePorts.trojan)",
        "-L", "$($tunnelPorts.shadowsocks):127.0.0.1:$($remotePorts.shadowsocks)",
        "-L", "$($tunnelPorts.anytls):127.0.0.1:$($remotePorts.anytls)",
        $remote
    )
    $tunnelProc = Start-Process -FilePath "ssh.exe" -ArgumentList $sshArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $OutDir "ssh-tunnel.out.log") `
        -RedirectStandardError (Join-Path $OutDir "ssh-tunnel.err.log")
    $connectHost = "127.0.0.1"
    $connectPorts = $tunnelPorts
    Wait-TcpOpen -HostName $connectHost -Port $connectPorts.vmess -Name "ssh tunnel vmess"
    Wait-TcpOpen -HostName $connectHost -Port $connectPorts.trojan -Name "ssh tunnel trojan"
    Wait-TcpOpen -HostName $connectHost -Port $connectPorts.shadowsocks -Name "ssh tunnel shadowsocks"
    Wait-TcpOpen -HostName $connectHost -Port $connectPorts.anytls -Name "ssh tunnel anytls"
}

function New-XrayTlsStreamClient {
    @{
        network = "tcp"
        security = "tls"
        tlsSettings = @{
            serverName = $RemoteHost
            pinnedPeerCertSha256 = $cert.pinnedSha256
        }
    }
}

function Get-XrayOutbound {
    param([string]$Protocol)
    $port = $connectPorts[$Protocol]
    switch ($Protocol) {
        "vmess" { @{ protocol = "vmess"; tag = "proxy"; settings = @{ vnext = @(@{ address = $connectHost; port = $port; users = @(@{ id = $uuid; alterId = 0; security = "none" }) }) } } }
        "trojan" { @{ protocol = "trojan"; tag = "proxy"; settings = @{ servers = @(@{ address = $connectHost; port = $port; password = $password }) }; streamSettings = New-XrayTlsStreamClient } }
        "shadowsocks" { @{ protocol = "shadowsocks"; tag = "proxy"; settings = @{ servers = @(@{ address = $connectHost; port = $port; method = $ssMethod; password = $password }) } } }
        "anytls" { @{ protocol = "anytls"; tag = "proxy"; settings = @{ address = $connectHost; port = $port; password = $password; idleSessionCheckInterval = 30; idleSessionTimeout = 60; minIdleSession = 0 }; streamSettings = New-XrayTlsStreamClient } }
    }
}

function Get-SingOutbound {
    param([string]$Protocol)
    $port = $connectPorts[$Protocol]
    switch ($Protocol) {
        "vmess" { @{ type = "vmess"; tag = "proxy"; server = $connectHost; server_port = $port; uuid = $uuid; security = "auto"; alter_id = 0 } }
        "trojan" { @{ type = "trojan"; tag = "proxy"; server = $connectHost; server_port = $port; password = $password; network = "tcp"; tls = @{ enabled = $true; server_name = $RemoteHost; insecure = $true } } }
        "shadowsocks" { @{ type = "shadowsocks"; tag = "proxy"; server = $connectHost; server_port = $port; method = $ssMethod; password = $password } }
        "anytls" { @{ type = "anytls"; tag = "proxy"; server = $connectHost; server_port = $port; password = $password; idle_session_check_interval = "30s"; idle_session_timeout = "60s"; min_idle_session = 0; tls = @{ enabled = $true; server_name = $RemoteHost; insecure = $true } } }
    }
}

function Write-MihomoConfig {
    param([string]$Path, [string]$Protocol, [int]$LocalPort)
    $serverPort = $connectPorts[$Protocol]
    $proxy = switch ($Protocol) {
        "vmess" {
@"
  - name: proxy
    type: vmess
    server: $connectHost
    port: $serverPort
    uuid: $uuid
    alterId: 0
    cipher: auto
    udp: true
"@
        }
        "trojan" {
@"
  - name: proxy
    type: trojan
    server: $connectHost
    port: $serverPort
    password: $password
    sni: $RemoteHost
    skip-cert-verify: true
    udp: true
"@
        }
        "shadowsocks" {
@"
  - name: proxy
    type: ss
    server: $connectHost
    port: $serverPort
    cipher: $ssMethod
    password: $password
    udp: true
"@
        }
        "anytls" {
@"
  - name: proxy
    type: anytls
    server: $connectHost
    port: $serverPort
    password: $password
    sni: $RemoteHost
    skip-cert-verify: true
    udp: true
    idle-session-check-interval: 30
    idle-session-timeout: 60
    min-idle-session: 0
"@
        }
    }
    if ($Protocol -eq "trojan") {
        Write-Utf8NoBom -Path $Path -Text @"
allow-lan: false
mode: rule
log-level: warning
tunnels:
  - network: [tcp]
    address: 127.0.0.1:$LocalPort
    target: 127.0.0.1:$remoteGreetingPort
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
        return
    }
    Write-Utf8NoBom -Path $Path -Text @"
mixed-port: $LocalPort
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
}

function Run-Case {
    param([string]$Impl, [string]$Protocol, [int]$Index)
    $name = "$Impl-$Protocol"
    $caseDir = Join-Path $OutDir $name
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $localPort = 47200 + $Index
    $proc = $null
    $ok = $false
    $detail = ""
    try {
        if ($Impl -eq "xray") {
            $cfg = @{
                log = @{ loglevel = "warning" }
                inbounds = @(@{ listen = "127.0.0.1"; port = $localPort; protocol = "socks"; settings = @{ udp = $true } })
                outbounds = @((Get-XrayOutbound -Protocol $Protocol))
            }
            $path = Join-Path $caseDir "client.json"
            Write-Json -Path $path -Value $cfg
            $proc = Start-LoggedProcess -Name $name -Exe $xray -CommandArgs @("run", "-config", $path) -WorkDir $caseDir
        } elseif ($Impl -eq "sing-box") {
            $cfg = @{
                log = @{ level = "debug"; timestamp = $true }
                inbounds = @(@{ type = "socks"; tag = "socks-in"; listen = "127.0.0.1"; listen_port = $localPort })
                outbounds = @((Get-SingOutbound -Protocol $Protocol), @{ type = "direct"; tag = "direct" })
                route = @{ final = "proxy" }
            }
            $path = Join-Path $caseDir "client.json"
            Write-Json -Path $path -Value $cfg
            $proc = Start-LoggedProcess -Name $name -Exe $singBox -CommandArgs @("run", "-c", $path) -WorkDir $caseDir
        } else {
            $path = Join-Path $caseDir "client.yaml"
            Write-MihomoConfig -Path $path -Protocol $Protocol -LocalPort $localPort
            $proc = Start-LoggedProcess -Name $name -Exe $mihomo -CommandArgs @("-f", $path, "-d", $caseDir) -WorkDir $caseDir
        }
        Wait-TcpOpen -HostName "127.0.0.1" -Port $localPort -Name "$name local client"
        if ($Impl -eq "mihomo" -and $Protocol -eq "trojan") {
            $result = Invoke-TcpGreeting -Port $localPort
        } else {
            $result = Invoke-CurlThroughSocks -SocksPort $localPort -Name $name
        }
        $ok = $result.ok
        $detail = $result.output
    } catch {
        $detail = $_.Exception.Message
    } finally {
        Stop-LoggedProcess $proc
    }
    [pscustomobject]@{ name = $name; implementation = $Impl; protocol = $Protocol; ok = $ok; detail = $detail; dir = $caseDir }
}

$results = @()
$index = 0
foreach ($impl in @("xray", "mihomo", "sing-box")) {
    foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
        $index += 1
        $result = Run-Case -Impl $impl -Protocol $protocol -Index $index
        $results += $result
        Write-Host "$($result.name): $($result.ok)"
    }
}

$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    remote = $remote
    remote_root = $remoteRoot
    remote_http_port = $remoteHttpPort
    remote_greeting_port = $remoteGreetingPort
    remote_ports = $remotePorts
    used_ssh_tunnel = [bool]$UseSshTunnel
    connect_host = $connectHost
    connect_ports = $connectPorts
    checks = $results
}
Write-Json -Path (Join-Path $OutDir "summary.json") -Value $summary

$failed = @($results | Where-Object { -not $_.ok })
if ($null -ne $tunnelProc -and -not $tunnelProc.HasExited) {
    Stop-Process -Id $tunnelProc.Id -Force -ErrorAction SilentlyContinue
    $tunnelProc.WaitForExit(3000) | Out-Null
}
if (-not $KeepRemoteRunning) {
    Invoke-Remote "if [ -f $remoteRoot/cnode.pid ]; then kill `$(cat $remoteRoot/cnode.pid) 2>/dev/null || true; rm -f $remoteRoot/cnode.pid; fi; if [ -f $remoteRoot/http.pid ]; then kill `$(cat $remoteRoot/http.pid) 2>/dev/null || true; rm -f $remoteRoot/http.pid; fi; if [ -f $remoteRoot/greeting.pid ]; then kill `$(cat $remoteRoot/greeting.pid) 2>/dev/null || true; rm -f $remoteRoot/greeting.pid; fi"
}

if ($failed.Count -gt 0) {
    Write-Host "REMOTE INBOUND TRAFFIC FAILED ($($failed.Count) failed):"
    foreach ($item in $failed) {
        Write-Host "  - $($item.name): $($item.detail) dir=$($item.dir)"
    }
    exit 1
}

Write-Host "REMOTE INBOUND TRAFFIC OK ($($results.Count) checks). Output: $OutDir"
