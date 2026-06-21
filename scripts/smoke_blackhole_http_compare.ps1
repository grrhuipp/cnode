param(
    [int]$EntryPort = 5212,
    [int]$CnodePort = 10106,
    [int]$XrayPort = 10107,
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root "tmp\blackhole-compare"
$LogDir = Join-Path $Tmp "logs"
$CnodeDir = Join-Path $Tmp "cnode"
$XrayClientDir = Join-Path $Tmp "xray-client"
$XrayServerDir = Join-Path $Tmp "xray-server"
$Cnode = Join-Path $Root "build\Release\cnode.exe"
$Xray = Join-Path $Root "tmp\xray\xray.exe"
$BenchUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

if (!(Test-Path $Cnode)) { throw "cnode not found at $Cnode" }
if (!(Test-Path $Xray)) { throw "xray not found at $Xray" }

New-Item -ItemType Directory -Force -Path $LogDir, $CnodeDir, $XrayClientDir, $XrayServerDir | Out-Null

function Write-Utf8NoBom($Path, $Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Stop-Processes($Processes) {
    foreach ($process in $Processes) {
        if ($process -and !$process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-XrayClientConfig([int]$ListenPort, [int]$ServerPort) {
    Write-Utf8NoBom (Join-Path $XrayClientDir "config.json") @"
{
  "log": { "loglevel": "error" },
  "inbounds": [
    {
      "tag": "entry",
      "listen": "127.0.0.1",
      "port": $ListenPort,
      "protocol": "dokodemo-door",
      "settings": { "address": "example.com", "port": 80, "network": "tcp" }
    }
  ],
  "outbounds": [
    {
      "tag": "to-server",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": $ServerPort,
            "users": [{ "id": "$BenchUuid", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
  ]
}
"@
}

function Read-HttpResponse([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new("127.0.0.1", $Port)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $TimeoutMs
    $request = [Text.Encoding]::ASCII.GetBytes(
        "GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n")
    $stream.Write($request, 0, $request.Length)

    $chunks = New-Object System.Collections.Generic.List[byte]
    $buffer = New-Object byte[] 1024
    while ($true) {
        try {
            $n = $stream.Read($buffer, 0, $buffer.Length)
        } catch {
            break
        }
        if ($n -le 0) { break }
        for ($i = 0; $i -lt $n; ++$i) {
            $chunks.Add($buffer[$i])
        }
        if ($chunks.Count -ge 4096) { break }
    }
    $client.Close()
    return [Text.Encoding]::ASCII.GetString($chunks.ToArray())
}

function Run-CnodeBlackhole {
    Write-Utf8NoBom (Join-Path $CnodeDir "config.json") @"
{
  "log": {
    "loglevel": "error",
    "access": "$($LogDir.Replace('\','/'))/cnode-access.log",
    "error": "$($LogDir.Replace('\','/'))/cnode-error.log"
  },
  "workers": 1,
  "dns": { "servers": ["8.8.8.8"] },
  "panels": []
}
"@

    Write-Utf8NoBom (Join-Path $CnodeDir "inbounds.json") @"
[
  {
    "tag": "bh-vless-in",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": $CnodePort,
    "settings": {
      "clients": [{ "id": "$BenchUuid", "email": "bench@example.com" }],
      "decryption": "none"
    },
    "streamSettings": { "network": "tcp", "security": "none" },
    "routingEnabled": true
  }
]
"@

    Write-Utf8NoBom (Join-Path $CnodeDir "outbounds.json") @"
[
  {
    "tag": "blackhole",
    "protocol": "blackhole",
    "settings": { "response": { "type": "http" } }
  }
]
"@

    Write-Utf8NoBom (Join-Path $CnodeDir "routing.json") @"
{
  "domainStrategy": "AsIs",
  "rules": [{ "network": "tcp", "outboundTag": "blackhole" }]
}
"@

    Write-XrayClientConfig $EntryPort $CnodePort
    $processes = @()
    try {
        $server = Start-Process -FilePath $Cnode -ArgumentList "--config-dir", $CnodeDir -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "cnode.out") -RedirectStandardError (Join-Path $LogDir "cnode.err")
        $processes += $server
        Start-Sleep -Milliseconds 900
        $client = Start-Process -FilePath $Xray -ArgumentList "run", "-config", (Join-Path $XrayClientDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-client-cnode.out") -RedirectStandardError (Join-Path $LogDir "xray-client-cnode.err")
        $processes += $client
        Start-Sleep -Milliseconds 900
        return Read-HttpResponse $EntryPort
    } finally {
        Stop-Processes $processes
    }
}

function Run-XrayBlackhole {
    Write-Utf8NoBom (Join-Path $XrayServerDir "config.json") @"
{
  "log": { "loglevel": "error" },
  "inbounds": [
    {
      "tag": "bh-vless-in",
      "listen": "127.0.0.1",
      "port": $XrayPort,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$BenchUuid", "email": "bench@example.com" }],
        "decryption": "none"
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
  ],
  "outbounds": [
    {
      "tag": "blackhole",
      "protocol": "blackhole",
      "settings": { "response": { "type": "http" } }
    }
  ],
  "routing": {
    "rules": [{ "network": "tcp", "outboundTag": "blackhole" }]
  }
}
"@

    Write-XrayClientConfig $EntryPort $XrayPort
    $processes = @()
    try {
        $server = Start-Process -FilePath $Xray -ArgumentList "run", "-config", (Join-Path $XrayServerDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-server.out") -RedirectStandardError (Join-Path $LogDir "xray-server.err")
        $processes += $server
        Start-Sleep -Milliseconds 900
        $client = Start-Process -FilePath $Xray -ArgumentList "run", "-config", (Join-Path $XrayClientDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-client-xray.out") -RedirectStandardError (Join-Path $LogDir "xray-client-xray.err")
        $processes += $client
        Start-Sleep -Milliseconds 900
        return Read-HttpResponse $EntryPort
    } finally {
        Stop-Processes $processes
    }
}

$cnodeResponse = Run-CnodeBlackhole
Start-Sleep -Milliseconds 500
$xrayResponse = Run-XrayBlackhole

"cnode response:"
$cnodeResponse
"xray response:"
$xrayResponse

foreach ($name in @("cnode", "xray")) {
    $response = if ($name -eq "cnode") { $cnodeResponse } else { $xrayResponse }
    if ($response -notmatch "HTTP/1\.1 403 Forbidden") {
        throw "$name blackhole did not return 403"
    }
    if ($response -notmatch "Content-Length: 0") {
        throw "$name blackhole did not return zero content length"
    }
}
