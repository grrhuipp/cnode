param(
    [ValidateSet(
        "direct",
        "cnode-vmess", "xray-vmess",
        "cnode-vless", "xray-vless",
        "cnode-trojan", "xray-trojan",
        "cnode-shadowsocks", "xray-shadowsocks"
    )]
    [string]$Scenario = "cnode-vmess",
    [int]$Seconds = 10,
    [int]$Parallel = 4,
    [int]$IperfPort = 5201,
    [int]$EntryPort = 5202,
    [int]$CnodePort = 10086,
    [int]$XrayPort = 10087,
    [int]$CnodeWorkers = 0,
    [int]$GraceSeconds = 10,
    [ValidateSet("auto", "aes-128-gcm", "chacha20-poly1305", "none")]
    [string]$VmessSecurity = "auto",
    [string]$ShadowsocksMethod = "aes-256-gcm",
    [ValidateSet("error", "warning", "info", "debug")]
    [string]$XrayLogLevel = "error"
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root "tmp\perf-harness"
$LogDir = Join-Path $Tmp "logs"
$CnodeDir = Join-Path $Tmp "cnode"
$XrayClientDir = Join-Path $Tmp "xray-client"
$XrayServerDir = Join-Path $Tmp "xray-server"
$Iperf = Join-Path $Root "tmp\iperf3\iperf3.exe"
$Xray = Join-Path $Root "tmp\xray\xray.exe"
$Cnode = Join-Path $Root "build\Release\cnode.exe"
$BenchUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
$BenchPassword = "bench-password"
$BenchEmail = "bench@example.com"

if (!(Test-Path $Iperf)) { throw "iperf3 not found at $Iperf" }
if ($Scenario -ne "direct" -and !(Test-Path $Xray)) { throw "xray not found at $Xray" }
if ($Scenario.StartsWith("cnode-") -and !(Test-Path $Cnode)) { throw "cnode not found at $Cnode" }

New-Item -ItemType Directory -Force -Path $Tmp, $LogDir, $CnodeDir, $XrayClientDir, $XrayServerDir | Out-Null

function Write-Utf8NoBom($Path, $Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Get-BenchProtocol($ScenarioName) {
    if ($ScenarioName -eq "direct") { return "direct" }
    return $ScenarioName.Substring($ScenarioName.IndexOf("-") + 1)
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

function New-XrayClientOutboundJson([string]$Protocol, [int]$ServerPort) {
    switch ($Protocol) {
        "vmess" {
            return @"
{
      "tag": "to-server",
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": $ServerPort,
            "users": [{ "id": "$BenchUuid", "alterId": 0, "security": "$VmessSecurity" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        "vless" {
            return @"
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
"@
        }
        "trojan" {
            return @"
{
      "tag": "to-server",
      "protocol": "trojan",
      "settings": {
        "servers": [{ "address": "127.0.0.1", "port": $ServerPort, "password": "$BenchPassword" }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        "shadowsocks" {
            return @"
{
      "tag": "to-server",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{ "address": "127.0.0.1", "port": $ServerPort, "method": "$ShadowsocksMethod", "password": "$BenchPassword" }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        default { throw "unsupported protocol for xray client: $Protocol" }
    }
}

function New-XrayServerInboundJson([string]$Protocol, [int]$ListenPort) {
    switch ($Protocol) {
        "vmess" {
            return @"
{
      "tag": "bench-vmess-in",
      "listen": "127.0.0.1",
      "port": $ListenPort,
      "protocol": "vmess",
      "settings": {
        "clients": [{ "id": "$BenchUuid", "alterId": 0, "email": "$BenchEmail" }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        "vless" {
            return @"
{
      "tag": "bench-vless-in",
      "listen": "127.0.0.1",
      "port": $ListenPort,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$BenchUuid", "email": "$BenchEmail" }],
        "decryption": "none"
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        "trojan" {
            return @"
{
      "tag": "bench-trojan-in",
      "listen": "127.0.0.1",
      "port": $ListenPort,
      "protocol": "trojan",
      "settings": {
        "clients": [{ "password": "$BenchPassword", "email": "$BenchEmail" }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        "shadowsocks" {
            return @"
{
      "tag": "bench-shadowsocks-in",
      "listen": "127.0.0.1",
      "port": $ListenPort,
      "protocol": "shadowsocks",
      "settings": { "method": "$ShadowsocksMethod", "password": "$BenchPassword", "email": "$BenchEmail" },
      "streamSettings": { "network": "tcp", "security": "none" }
    }
"@
        }
        default { throw "unsupported protocol for xray server: $Protocol" }
    }
}

function New-CnodeInboundJson([string]$Protocol, [int]$ListenPort) {
    switch ($Protocol) {
        "vmess" {
            $Settings = '"clients": [{ "id": "' + $BenchUuid + '", "email": "' + $BenchEmail + '" }]'
        }
        "vless" {
            $Settings = '"clients": [{ "id": "' + $BenchUuid + '", "email": "' + $BenchEmail + '" }], "decryption": "none"'
        }
        "trojan" {
            $Settings = '"clients": [{ "password": "' + $BenchPassword + '", "email": "' + $BenchEmail + '" }]'
        }
        "shadowsocks" {
            $Settings = '"method": "' + $ShadowsocksMethod + '", "password": "' + $BenchPassword + '", "email": "' + $BenchEmail + '"'
        }
        default { throw "unsupported protocol for cnode server: $Protocol" }
    }
    return @"
[
  {
    "tag": "bench-$Protocol-in",
    "protocol": "$Protocol",
    "listen": "127.0.0.1",
    "port": $ListenPort,
    "settings": { $Settings },
    "streamSettings": { "network": "tcp", "security": "none" },
    "sniffing": { "enabled": false },
    "routingEnabled": true
  }
]
"@
}

$Protocol = Get-BenchProtocol $Scenario
$ProcessEntries = @()
try {
    if ($Scenario -ne "direct") {
        $ServerPort = if ($Scenario.StartsWith("cnode-")) { $CnodePort } else { $XrayPort }
        $ClientOutbound = New-XrayClientOutboundJson $Protocol $ServerPort

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
    $ClientOutbound
  ]
}
"@
    }

    if ($Scenario.StartsWith("cnode-")) {
        Write-Utf8NoBom (Join-Path $CnodeDir "config.json") @"
{
  "log": { "loglevel": "error", "access": "$($LogDir.Replace('\','/'))/cnode-access.log", "error": "$($LogDir.Replace('\','/'))/cnode-error.log", "logDir": "$($LogDir.Replace('\','/'))" },
  "workers": $CnodeWorkers,
  "dns": { "servers": ["8.8.8.8"], "timeout": 5, "cacheSize": 1024, "minTTL": 60, "maxTTL": 300 },
  "timeouts": { "handshake": 10, "dial": 10, "read": 60, "write": 60, "idle": 300 },
  "panels": []
}
"@
        Write-Utf8NoBom (Join-Path $CnodeDir "inbounds.json") (New-CnodeInboundJson $Protocol $CnodePort)
        Write-Utf8NoBom (Join-Path $CnodeDir "outbounds.json") @"
[
  { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs", "redirect": "" }, "sendThrough": "auto" }
]
"@
        Write-Utf8NoBom (Join-Path $CnodeDir "routing.json") '{ "domainStrategy": "AsIs", "rules": [] }'
    } elseif ($Scenario.StartsWith("xray-")) {
        $ServerInbound = New-XrayServerInboundJson $Protocol $XrayPort
        Write-Utf8NoBom (Join-Path $XrayServerDir "config.json") @"
{
  "log": { "loglevel": "$XrayLogLevel" },
  "inbounds": [
    $ServerInbound
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "AsIs",
        "finalRules": [
          { "action": "allow", "network": "tcp", "port": $IperfPort }
        ]
      }
    }
  ]
}
"@
    }

    $IperfServer = Start-Process -FilePath $Iperf -ArgumentList "-s","-1","-p",$IperfPort -WindowStyle Hidden -PassThru
    Add-BenchProcess ([ref]$ProcessEntries) "iperf-server" $IperfServer
    Start-Sleep -Milliseconds 400

    $ClientPort = $IperfPort
    if ($Scenario.StartsWith("cnode-")) {
        $CnodeProcess = Start-Process -FilePath $Cnode -ArgumentList "--config-dir",$CnodeDir -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "cnode-stdout.log") -RedirectStandardError (Join-Path $LogDir "cnode-stderr.log")
        Add-BenchProcess ([ref]$ProcessEntries) "cnode-server" $CnodeProcess
        Start-Sleep -Milliseconds 900
        $XrayClient = Start-Process -FilePath $Xray -ArgumentList "run","-config",(Join-Path $XrayClientDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-client-stdout.log") -RedirectStandardError (Join-Path $LogDir "xray-client-stderr.log")
        Add-BenchProcess ([ref]$ProcessEntries) "xray-client" $XrayClient
        Start-Sleep -Milliseconds 900
        $ClientPort = $EntryPort
    } elseif ($Scenario.StartsWith("xray-")) {
        $XrayServer = Start-Process -FilePath $Xray -ArgumentList "run","-config",(Join-Path $XrayServerDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-server-stdout.log") -RedirectStandardError (Join-Path $LogDir "xray-server-stderr.log")
        Add-BenchProcess ([ref]$ProcessEntries) "xray-server" $XrayServer
        Start-Sleep -Milliseconds 900
        $XrayClient = Start-Process -FilePath $Xray -ArgumentList "run","-config",(Join-Path $XrayClientDir "config.json") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $LogDir "xray-client-stdout.log") -RedirectStandardError (Join-Path $LogDir "xray-client-stderr.log")
        Add-BenchProcess ([ref]$ProcessEntries) "xray-client" $XrayClient
        Start-Sleep -Milliseconds 900
        $ClientPort = $EntryPort
    }

    $Before = Snapshot-Cpu $ProcessEntries
    $IperfOut = Join-Path $LogDir "iperf-client-stdout.log"
    $IperfErr = Join-Path $LogDir "iperf-client-stderr.log"
    $IperfClient = Start-Process -FilePath $Iperf -ArgumentList "-c","127.0.0.1","-p",$ClientPort,"-t",$Seconds,"-P",$Parallel -NoNewWindow -PassThru -RedirectStandardOutput $IperfOut -RedirectStandardError $IperfErr
    $Exited = $IperfClient.WaitForExit(($Seconds + $GraceSeconds) * 1000)
    if (!$Exited) {
        Stop-Process -Id $IperfClient.Id -Force -ErrorAction SilentlyContinue
    }
    $After = Snapshot-Cpu $ProcessEntries
    Get-Content $IperfOut -ErrorAction SilentlyContinue
    Get-Content $IperfErr -ErrorAction SilentlyContinue
    if (!$Exited) {
        throw "iperf3 client timed out after $($Seconds + $GraceSeconds)s; see $LogDir"
    }
    "CPU delta:"
    Emit-CpuDelta $Before $After | Format-Table -AutoSize
} finally {
    Stop-BenchProcesses $ProcessEntries
}
