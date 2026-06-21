param(
    [int]$Seconds = 10,
    [int]$Parallel = 4,
    [int]$IperfPort = 5201,
    [int]$EntryPort = 5202,
    [int]$CnodeVlessPort = 10086,
    [int]$CnodeAnyTlsPort = 10088,
    [int]$CnodeWorkers = 0,
    [int]$GraceSeconds = 10,
    [int]$HalfCloseSeconds = 5,
    [ValidateSet("trace", "debug", "info", "warn", "error")]
    [string]$CnodeLogLevel = "error",
    [ValidateSet("error", "warning", "info", "debug")]
    [string]$XrayLogLevel = "error"
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root "tmp\perf-harness-anytls"
$LogDir = Join-Path $Tmp "logs"
$CnodeDir = Join-Path $Tmp "cnode"
$XrayClientDir = Join-Path $Tmp "xray-client"
$Iperf = Join-Path $Root "tmp\iperf3\iperf3.exe"
$Xray = Join-Path $Root "tmp\xray\xray.exe"
$Cnode = Join-Path $Root "build\Release\cnode.exe"
$BenchUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
$BenchPassword = "bench-password"
$BenchEmail = "bench@example.com"

if (!(Test-Path $Iperf)) { throw "iperf3 not found at $Iperf" }
if (!(Test-Path $Xray)) { throw "xray not found at $Xray" }
if (!(Test-Path $Cnode)) { throw "cnode not found at $Cnode" }

New-Item -ItemType Directory -Force -Path $Tmp, $LogDir, $CnodeDir, $XrayClientDir | Out-Null

function Write-Utf8NoBom($Path, $Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Add-BenchProcess([ref]$Entries, [string]$Role, [System.Diagnostics.Process]$Process) {
    $Entries.Value += [PSCustomObject]@{
        Role = $Role
        Process = $Process
    }
}

function Stop-BenchProcesses($Entries) {
    foreach ($Entry in $Entries) {
        $Process = $Entry.Process
        if ($Process -and !$Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Snapshot-Cpu($Entries) {
    $Rows = @()
    foreach ($Entry in $Entries) {
        $Process = $Entry.Process
        if ($Process -and !$Process.HasExited) {
            $Fresh = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
            if ($Fresh) {
                $Rows += [PSCustomObject]@{
                    Id = $Fresh.Id
                    Role = $Entry.Role
                    Name = $Fresh.ProcessName
                    CPU = [double]$Fresh.CPU
                }
            }
        }
    }
    return $Rows
}

function Emit-CpuDelta($Before, $After) {
    foreach ($Row in $After) {
        $Start = $Before | Where-Object { $_.Id -eq $Row.Id } | Select-Object -First 1
        $CpuSeconds = if ($Start) { $Row.CPU - $Start.CPU } else { $Row.CPU }
        [PSCustomObject]@{
            Role = $Row.Role
            Id = $Row.Id
            Name = $Row.Name
            CpuSeconds = [Math]::Round($CpuSeconds, 3)
        }
    }
}

Write-Utf8NoBom (Join-Path $XrayClientDir "config.json") @"
{
  "log": { "loglevel": "$XrayLogLevel" },
  "inbounds": [
    {
      "tag": "iperf-entry",
      "listen": "127.0.0.1",
      "port": $EntryPort,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": $IperfPort, "network": "tcp" }
    }
  ],
  "outbounds": [
    {
      "tag": "to-cnode-entry",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": $CnodeVlessPort,
            "users": [{ "id": "$BenchUuid", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
  ]
}
"@

Write-Utf8NoBom (Join-Path $CnodeDir "config.json") @"
{
  "log": { "loglevel": "$CnodeLogLevel", "access": "$($LogDir.Replace('\','/'))/cnode-access.log", "error": "$($LogDir.Replace('\','/'))/cnode-error.log", "logDir": "$($LogDir.Replace('\','/'))" },
  "workers": $CnodeWorkers,
  "dns": { "servers": ["8.8.8.8"], "timeout": 5, "cacheSize": 1024, "minTTL": 60, "maxTTL": 300 },
  "timeouts": { "handshake": 10, "dial": 10, "read": 60, "write": 60, "idle": 300, "uplinkOnly": $HalfCloseSeconds, "downlinkOnly": $HalfCloseSeconds },
  "panels": []
}
"@

Write-Utf8NoBom (Join-Path $CnodeDir "inbounds.json") @"
[
  {
    "tag": "client-vless-in",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": $CnodeVlessPort,
    "settings": {
      "clients": [{ "id": "$BenchUuid", "email": "$BenchEmail" }],
      "decryption": "none"
    },
    "streamSettings": { "network": "tcp", "security": "none" },
    "sniffing": { "enabled": false },
    "routingEnabled": true
  },
  {
    "tag": "server-anytls-in",
    "protocol": "anytls",
    "listen": "127.0.0.1",
    "port": $CnodeAnyTlsPort,
    "settings": {
      "users": [{ "password": "$BenchPassword", "email": "$BenchEmail" }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": { "serverName": "localhost" }
    },
    "sniffing": { "enabled": false },
    "routingEnabled": true
  }
]
"@

Write-Utf8NoBom (Join-Path $CnodeDir "outbounds.json") @"
[
  {
    "tag": "to-anytls",
    "protocol": "anytls",
    "settings": {
      "address": "127.0.0.1",
      "port": $CnodeAnyTlsPort,
      "password": "$BenchPassword"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": { "serverName": "localhost", "allowInsecure": true }
    }
  },
  {
    "tag": "direct",
    "protocol": "freedom",
    "settings": { "domainStrategy": "AsIs", "redirect": "" },
    "sendThrough": "auto"
  }
]
"@

Write-Utf8NoBom (Join-Path $CnodeDir "routing.json") @"
{
  "domainStrategy": "AsIs",
  "rules": [
    { "inboundTag": ["client-vless-in"], "outboundTag": "to-anytls" },
    { "inboundTag": ["server-anytls-in"], "outboundTag": "direct" }
  ]
}
"@

$ProcessEntries = @()
try {
    $IperfServerOut = Join-Path $LogDir "iperf-server-stdout.log"
    $IperfServerErr = Join-Path $LogDir "iperf-server-stderr.log"
    $IperfServer = Start-Process -FilePath $Iperf -ArgumentList "-s","-1","-p",$IperfPort -WindowStyle Hidden -PassThru -RedirectStandardOutput $IperfServerOut -RedirectStandardError $IperfServerErr
    Add-BenchProcess ([ref]$ProcessEntries) "iperf-server" $IperfServer
    Start-Sleep -Milliseconds 400

    $CnodeProcess = Start-Process -FilePath $Cnode -ArgumentList "--config-dir",$CnodeDir -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "cnode-stdout.log") -RedirectStandardError (Join-Path $LogDir "cnode-stderr.log")
    Add-BenchProcess ([ref]$ProcessEntries) "cnode-anytls" $CnodeProcess
    Start-Sleep -Milliseconds 1000

    $XrayClient = Start-Process -FilePath $Xray -ArgumentList "run","-config",(Join-Path $XrayClientDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-client-stdout.log") -RedirectStandardError (Join-Path $LogDir "xray-client-stderr.log")
    Add-BenchProcess ([ref]$ProcessEntries) "xray-entry" $XrayClient
    Start-Sleep -Milliseconds 900

    $Before = Snapshot-Cpu $ProcessEntries
    $IperfOut = Join-Path $LogDir "iperf-client-stdout.log"
    $IperfErr = Join-Path $LogDir "iperf-client-stderr.log"
    $IperfClient = Start-Process -FilePath $Iperf -ArgumentList "-c","127.0.0.1","-p",$EntryPort,"-t",$Seconds,"-P",$Parallel -NoNewWindow -PassThru -RedirectStandardOutput $IperfOut -RedirectStandardError $IperfErr
    $Exited = $IperfClient.WaitForExit(($Seconds + $GraceSeconds) * 1000)
    if (!$Exited) {
        Stop-Process -Id $IperfClient.Id -Force -ErrorAction SilentlyContinue
    }
    $After = Snapshot-Cpu $ProcessEntries
    Get-Content $IperfOut -ErrorAction SilentlyContinue
    Get-Content $IperfErr -ErrorAction SilentlyContinue
    "iperf server stderr:"
    Get-Content $IperfServerErr -ErrorAction SilentlyContinue
    if (!$Exited) {
        throw "iperf3 client timed out after $($Seconds + $GraceSeconds)s; see $LogDir"
    }
    "CPU delta:"
    Emit-CpuDelta $Before $After | Format-Table -AutoSize
} finally {
    Stop-BenchProcesses $ProcessEntries
}
