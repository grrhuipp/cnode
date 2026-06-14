param(
    [string]$RemoteHost = "node-02.11.9527app.site",
    [string]$RemoteUser = "root",
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$RemoteCnode = "/opt/cnode-e2e/bin/cnode",
    [string]$RemoteRunRoot = "/opt/cnode-e2e/remote-outbound",
    [string]$OutDir = "",
    [switch]$KeepGoing,
    [switch]$KeepRemoteRunning
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "build\remote-cnode-outbound-traffic"
}

$remote = "$RemoteUser@$RemoteHost"

$xray = Join-Path $Root "tools\xray-core-anytls\xray.exe"
if (-not (Test-Path $xray)) {
    $xray = Join-Path $Root "tools\xray-core-latest\xray.exe"
}
$mihomo = Join-Path $Root "tools\mihomo\mihomo-windows-amd64.exe"
$singBox = Join-Path $Root "tools\sing-box\sing-box.exe"

foreach ($tool in @($xray, $mihomo, $singBox, "curl.exe", "ssh.exe", "scp.exe", "powershell.exe")) {
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

function Test-RemoteTcpOpen {
    param([int]$Port)
    & ssh -o BatchMode=yes $remote "timeout 1 bash -c '</dev/tcp/127.0.0.1/$Port' >/dev/null 2>&1"
    return ($LASTEXITCODE -eq 0)
}

function Wait-RemoteTcpOpen {
    param([int]$Port, [string]$Name, [int]$TimeoutMs = 10000)
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline) {
        if (Test-RemoteTcpOpen -Port $Port) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timeout waiting for $Name on remote 127.0.0.1:$Port"
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

function Start-SshTunnel {
    param(
        [string]$Name,
        [int]$LocalIngressPort,
        [int]$RemoteIngressPort,
        [int]$RemoteServerPort,
        [int]$LocalServerPort
    )
    $logDir = Join-Path $OutDir "logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $stdout = Join-Path $logDir "$Name-ssh.out.log"
    $stderr = Join-Path $logDir "$Name-ssh.err.log"
    Remove-Item -Force $stdout,$stderr -ErrorAction SilentlyContinue
    $sshArgs = @(
        "-N",
        "-o", "BatchMode=yes",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-L", "$LocalIngressPort`:127.0.0.1:$RemoteIngressPort",
        "-R", "$RemoteServerPort`:127.0.0.1:$LocalServerPort",
        $remote
    )
    $p = Start-Process -FilePath "ssh.exe" -ArgumentList $sshArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [pscustomobject]@{ name = "$Name-ssh"; process = $p; stdout = $stdout; stderr = $stderr }
}

function Copy-RemoteCaseLogs {
    param([string]$RemoteCase, [string]$CaseDir)
    foreach ($file in @("cnode.out", "cnode.err")) {
        $remotePath = "$RemoteCase/$file"
        & ssh -o BatchMode=yes $remote "test -f $remotePath"
        if ($LASTEXITCODE -eq 0) {
            & scp -q "${remote}:$remotePath" (Join-Path $CaseDir "remote-$file.log")
        }
    }
}

function Invoke-CurlThroughSocks {
    param([string]$Name, [int]$SocksPort, [int]$HttpPort)
    $url = "http://127.0.0.1:$HttpPort/$Name"
    $output = & curl.exe --silent --show-error --fail --max-time 15 `
        --socks5-hostname "127.0.0.1:$SocksPort" $url 2>&1
    $exit = $LASTEXITCODE
    [pscustomobject]@{
        ok = ($exit -eq 0 -and (($output | Out-String) -match "CNODE_REMOTE_OUTBOUND_OK"))
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

function New-CnodeDirectory {
    param([string]$Dir, [array]$Inbounds, [array]$Outbounds, [array]$Rules, [string]$RemoteLogDir)
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Write-Json -Path (Join-Path $Dir "config.json") -Value @{
        log = @{ loglevel = "debug"; logDir = $RemoteLogDir }
        workers = 1
        dns = @{ servers = @("1.1.1.1"); timeout = 5; cacheSize = 32; minTTL = 1; maxTTL = 60 }
        timeouts = @{ handshake = 8; dial = 8; read = 8; write = 8; idle = 30 }
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
            $body = "CNODE_REMOTE_OUTBOUND_OK"
            if ($read -le 0) {
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($body)
                try {
                    $stream.Write($bytes, 0, $bytes.Length)
                } catch {
                }
                continue
            }
            $bytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
            try {
                $stream.Write($bytes, 0, $bytes.Length)
            } catch {
            }
        } finally {
            $client.Close()
        }
    }
} finally {
    $listener.Stop()
}
'@

function Get-CnodeVmessInbound {
    param([int]$Port)
    @{
        tag = "ingress"
        listen = "127.0.0.1"
        port = $Port
        protocol = "vmess"
        settings = @{ clients = @(@{ id = $script:uuid; alterId = 0; email = "vmess@example.test" }) }
    }
}

function Get-CnodeOutbound {
    param([string]$Protocol, [int]$Port)
    $settings = switch ($Protocol) {
        "vmess" { @{ vnext = @(@{ address = "127.0.0.1"; port = $Port; users = @(@{ id = $script:uuid; alterId = 0; security = "auto" }) }) } }
        "trojan" { @{ servers = @(@{ address = "127.0.0.1"; port = $Port; password = $script:password }) } }
        "shadowsocks" { @{ servers = @(@{ address = "127.0.0.1"; port = $Port; method = $script:ssMethod; password = $script:password }) } }
        "anytls" { @{ address = "127.0.0.1"; port = $Port; password = $script:password; idleSessionCheckInterval = 30; idleSessionTimeout = 60; minIdleSession = 0 } }
    }
    $outbound = @{ tag = "tested-out"; protocol = $Protocol; settings = $settings }
    if ($Protocol -eq "trojan" -or $Protocol -eq "anytls") {
        $outbound.streamSettings = New-CnodeTlsStreamClient
    }
    $outbound
}

function Get-SingOutboundToCnode {
    param([int]$Port)
    @{ type = "vmess"; tag = "proxy"; server = "127.0.0.1"; server_port = $Port; uuid = $script:uuid; security = "auto"; alter_id = 0 }
}

function Get-XrayServerInbound {
    param([string]$Protocol, [int]$Port)
    switch ($Protocol) {
        "vmess" { @{ listen = "127.0.0.1"; port = $Port; protocol = "vmess"; settings = @{ clients = @(@{ id = $script:uuid; alterId = 0; email = "vmess@example.test" }) } } }
        "trojan" { @{ listen = "127.0.0.1"; port = $Port; protocol = "trojan"; settings = @{ clients = @(@{ password = $script:password; email = "trojan@example.test" }) }; streamSettings = New-XrayTlsStreamServer } }
        "shadowsocks" { @{ listen = "127.0.0.1"; port = $Port; protocol = "shadowsocks"; settings = @{ method = $script:ssMethod; password = $script:password; network = "tcp,udp" } } }
        "anytls" { @{ listen = "127.0.0.1"; port = $Port; protocol = "anytls"; settings = @{ users = @(@{ password = $script:password; email = "anytls@example.test" }); paddingScheme = $script:paddingScheme }; streamSettings = New-XrayTlsStreamServer } }
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

function Get-CasePorts {
    param([int]$Index)
    $localBase = 48100 + ($Index * 20)
    $remoteBase = 46600 + ($Index * 20)
    [pscustomobject]@{
        localHttp = $localBase + 1
        localServer = $localBase + 2
        localSocks = $localBase + 3
        localIngressTunnel = $localBase + 4
        remoteIngress = $remoteBase + 1
        remoteServerTunnel = $remoteBase + 2
    }
}

function Start-ExternalServer {
    param([string]$Impl, [string]$Protocol, [int]$Port, [string]$CaseDir, [string]$Name)
    if ($Impl -eq "xray") {
        $path = Join-Path $CaseDir "server.json"
        Write-Json -Path $path -Value (New-XrayConfig -Inbounds @((Get-XrayServerInbound -Protocol $Protocol -Port $Port)) -Outbounds @(@{ protocol = "freedom"; tag = "direct" }))
        return Start-LoggedProcess -Name "$Name-xray-server" -Exe $xray -CommandArgs @("run", "-config", $path) -WorkDir $CaseDir
    }
    if ($Impl -eq "sing-box") {
        $path = Join-Path $CaseDir "server.json"
        Write-Json -Path $path -Value (New-SingConfig -Inbounds @((Get-SingServerInbound -Protocol $Protocol -Port $Port)) -Outbounds @(@{ type = "direct"; tag = "direct" }) -Final "direct")
        return Start-LoggedProcess -Name "$Name-sing-server" -Exe $singBox -CommandArgs @("run", "-c", $path) -WorkDir $CaseDir
    }
    $path = Join-Path $CaseDir "server.yaml"
    Write-MihomoServerConfig -Path $path -Protocol $Protocol -Port $Port
    Start-LoggedProcess -Name "$Name-mihomo-server" -Exe $mihomo -CommandArgs @("-f", $path, "-d", $CaseDir) -WorkDir $CaseDir
}

function Run-Case {
    param([string]$Impl, [string]$Protocol, [int]$Index)
    $name = "remote-outbound-$Impl-$Protocol"
    $caseDir = Join-Path $OutDir $name
    $remoteCase = "$RemoteRunRoot/$name"
    $remoteConfig = "$remoteCase/config"
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $ports = Get-CasePorts -Index $Index
    $procs = @()
    $sshTunnel = $null
    $ok = $false
    $detail = ""
    try {
        $procs += Start-LoggedProcess -Name "$name-http" -Exe "powershell.exe" -CommandArgs @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $httpScript, "-Port", "$($ports.localHttp)")
        Wait-TcpOpen -HostName "127.0.0.1" -Port $ports.localHttp -Name "$name http"

        $procs += Start-ExternalServer -Impl $Impl -Protocol $Protocol -Port $ports.localServer -CaseDir $caseDir -Name $name
        Wait-TcpOpen -HostName "127.0.0.1" -Port $ports.localServer -Name "$name external server"

        $localConfig = Join-Path $caseDir "remote-config"
        New-CnodeDirectory -Dir $localConfig `
            -Inbounds @((Get-CnodeVmessInbound -Port $ports.remoteIngress)) `
            -Outbounds @((Get-CnodeOutbound -Protocol $Protocol -Port $ports.remoteServerTunnel)) `
            -Rules @(@{ inboundTag = @("ingress"); outboundTag = "tested-out" }) `
            -RemoteLogDir "$remoteCase/logs"

        Invoke-Remote "set -e; mkdir -p $RemoteRunRoot $remoteCase/logs; if [ -f $remoteCase/cnode.pid ]; then kill `$(cat $remoteCase/cnode.pid) 2>/dev/null || true; rm -f $remoteCase/cnode.pid; fi; rm -rf $remoteConfig; mkdir -p $remoteConfig"
        & scp -q -r $localConfig\* "${remote}:$remoteConfig/"
        if ($LASTEXITCODE -ne 0) { throw "scp remote config failed" }

        $sshTunnel = Start-SshTunnel -Name $name `
            -LocalIngressPort $ports.localIngressTunnel `
            -RemoteIngressPort $ports.remoteIngress `
            -RemoteServerPort $ports.remoteServerTunnel `
            -LocalServerPort $ports.localServer
        Start-Sleep -Milliseconds 500
        if ($sshTunnel.process.HasExited) {
            throw "ssh tunnel exited early; stderr=$($sshTunnel.stderr)"
        }

        Invoke-Remote "set -e; nohup $RemoteCnode -c $remoteConfig > $remoteCase/cnode.out 2> $remoteCase/cnode.err < /dev/null & echo `$! > $remoteCase/cnode.pid"
        Wait-RemoteTcpOpen -Port $ports.remoteIngress -Name "$name remote cnode ingress"
        Wait-TcpOpen -HostName "127.0.0.1" -Port $ports.localIngressTunnel -Name "$name local ingress tunnel"

        $clientCfg = New-SingConfig `
            -Inbounds @(@{ type = "socks"; tag = "socks-in"; listen = "127.0.0.1"; listen_port = $ports.localSocks }) `
            -Outbounds @((Get-SingOutboundToCnode -Port $ports.localIngressTunnel))
        $clientPath = Join-Path $caseDir "client.json"
        Write-Json -Path $clientPath -Value $clientCfg
        $procs += Start-LoggedProcess -Name "$name-sing-client" -Exe $singBox -CommandArgs @("run", "-c", $clientPath) -WorkDir $caseDir
        Wait-TcpOpen -HostName "127.0.0.1" -Port $ports.localSocks -Name "$name socks"

        $curl = Invoke-CurlThroughSocks -Name $name -SocksPort $ports.localSocks -HttpPort $ports.localHttp
        $ok = $curl.ok
        $detail = $curl.output
    } catch {
        $detail = $_.Exception.Message
    } finally {
        Copy-RemoteCaseLogs -RemoteCase $remoteCase -CaseDir $caseDir
        if (-not $KeepRemoteRunning) {
            try {
                Invoke-Remote "if [ -f $remoteCase/cnode.pid ]; then kill `$(cat $remoteCase/cnode.pid) 2>/dev/null || true; rm -f $remoteCase/cnode.pid; fi"
            } catch {
            }
        }
        if ($null -ne $sshTunnel) {
            Stop-LoggedProcess $sshTunnel
        }
        foreach ($p in @($procs | Sort-Object { $_.name } -Descending)) {
            Stop-LoggedProcess $p
        }
    }
    [pscustomobject]@{
        name = $name
        direction = "remote-cnode-outbound"
        implementation = $Impl
        protocol = $Protocol
        ok = $ok
        detail = $detail
        dir = $caseDir
        remote_case = $remoteCase
        ports = $ports
    }
}

Invoke-Remote "test -x $RemoteCnode"

$results = @()
$index = 0
foreach ($impl in @("xray", "mihomo", "sing-box")) {
    foreach ($protocol in @("vmess", "trojan", "shadowsocks", "anytls")) {
        $index += 1
        $result = Run-Case -Impl $impl -Protocol $protocol -Index $index
        $results += $result
        Write-Host "$($result.name): $($result.ok)"
        if (-not $result.ok -and -not $KeepGoing) { break }
    }
    if (($results | Where-Object { -not $_.ok }).Count -gt 0 -and -not $KeepGoing) { break }
}

$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    remote = $remote
    remote_cnode = $RemoteCnode
    remote_run_root = $RemoteRunRoot
    checks = $results
}
Write-Json -Path (Join-Path $OutDir "summary.json") -Value $summary

$failed = @($results | Where-Object { -not $_.ok })
if ($failed.Count -gt 0) {
    Write-Host "REMOTE OUTBOUND TRAFFIC FAILED ($($failed.Count) failed):"
    foreach ($item in $failed) {
        Write-Host "  - $($item.name): $($item.detail) dir=$($item.dir) remote=$($item.remote_case)"
    }
    exit 1
}

Write-Host "REMOTE OUTBOUND TRAFFIC OK ($($results.Count) checks). Output: $OutDir"
