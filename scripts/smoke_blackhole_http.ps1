param(
    [int]$EntryPort = 5212,
    [int]$CnodePort = 10106,
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root "tmp\blackhole-smoke"
$LogDir = Join-Path $Tmp "logs"
$CnodeDir = Join-Path $Tmp "cnode"
$XrayClientDir = Join-Path $Tmp "xray-client"
$Cnode = Join-Path $Root "build\Release\cnode.exe"
$Xray = Join-Path $Root "tmp\xray\xray.exe"
$BenchUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

if (!(Test-Path $Cnode)) { throw "cnode not found at $Cnode" }
if (!(Test-Path $Xray)) { throw "xray not found at $Xray" }

New-Item -ItemType Directory -Force -Path $LogDir, $CnodeDir, $XrayClientDir | Out-Null

function Write-Utf8NoBom($Path, $Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

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

Write-Utf8NoBom (Join-Path $XrayClientDir "config.json") @"
{
  "log": { "loglevel": "error" },
  "inbounds": [
    {
      "tag": "entry",
      "listen": "127.0.0.1",
      "port": $EntryPort,
      "protocol": "dokodemo-door",
      "settings": { "address": "example.com", "port": 80, "network": "tcp" }
    }
  ],
  "outbounds": [
    {
      "tag": "to-cnode",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": $CnodePort,
            "users": [{ "id": "$BenchUuid", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
  ]
}
"@

$processes = @()
try {
    $cnodeProcess = Start-Process -FilePath $Cnode `
        -ArgumentList "--config-dir", $CnodeDir `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "cnode.out") `
        -RedirectStandardError (Join-Path $LogDir "cnode.err")
    $processes += $cnodeProcess
    Start-Sleep -Milliseconds 900

    $xrayProcess = Start-Process -FilePath $Xray `
        -ArgumentList "run", "-config", (Join-Path $XrayClientDir "config.json") `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "xray.out") `
        -RedirectStandardError (Join-Path $LogDir "xray.err")
    $processes += $xrayProcess
    Start-Sleep -Milliseconds 900

    $client = [Net.Sockets.TcpClient]::new("127.0.0.1", $EntryPort)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $TimeoutMs
    $request = [Text.Encoding]::ASCII.GetBytes(
        "GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n")
    $stream.Write($request, 0, $request.Length)

    $buffer = New-Object byte[] 512
    $n = $stream.Read($buffer, 0, $buffer.Length)
    $response = [Text.Encoding]::ASCII.GetString($buffer, 0, $n)
    $client.Close()

    $response
    if ($response -notmatch "HTTP/1\.1 403 Forbidden") {
        throw "blackhole http response smoke failed"
    }
} finally {
    foreach ($process in $processes) {
        if ($process -and !$process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
