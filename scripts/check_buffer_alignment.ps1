$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$XrayRoot = Join-Path $Root "tmp\xray-core-v26.6.1"

function Read-Text($Path) {
    if (!(Test-Path $Path)) {
        throw "missing file: $Path"
    }
    return [System.IO.File]::ReadAllText($Path)
}

function Assert-Match($Name, $Path, $Pattern, $Expected) {
    $text = Read-Text $Path
    $ok = [regex]::IsMatch($text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    [PSCustomObject]@{
        Check = $Name
        File = Resolve-Path $Path
        Expected = $Expected
        Pass = $ok
    }
}

$checks = @()

$checks += Assert-Match `
    "xray buf.Size" `
    (Join-Path $XrayRoot "common\buf\buffer.go") `
    "Size\s*=\s*8192" `
    "8192 bytes"

$checks += Assert-Match `
    "cnode Buffer::kSize" `
    (Join-Path $Root "include\acppnode\common\buf\multi_buffer.hpp") `
    "static\s+constexpr\s+uint32_t\s+kSize\s*=\s*8192" `
    "8192 bytes"

$checks += Assert-Match `
    "xray readv cap" `
    (Join-Path $XrayRoot "common\buf\readv_reader.go") `
    "if\s+s\.current\s*>\s*8\s*\{[\s\S]*s\.current\s*=\s*8" `
    "max 8 buffers"

$checks += Assert-Match `
    "cnode normal readv cap" `
    (Join-Path $Root "src\transport\internet\tcp_read_policy.hpp") `
    "kNormalReadBufferCap\s*=\s*4" `
    "normal max 4 buffers"

$checks += Assert-Match `
    "cnode pressure readv cap" `
    (Join-Path $Root "src\transport\internet\tcp_read_policy.hpp") `
    "kPressureReadBufferCap\s*=\s*2" `
    "pressure max 2 buffers"

$checks += Assert-Match `
    "xray auth read batch" `
    (Join-Path $XrayRoot "common\crypto\auth.go") `
    "const\s+readSize\s*=\s*16" `
    "16 chunks"

$checks += Assert-Match `
    "cnode vmess read batch" `
    (Join-Path $Root "src\proxy\vmess\encoding\server.cpp") `
    "kStreamReadBatchChunks\s*=\s*16" `
    "16 chunks"

$checks += Assert-Match `
    "cnode shadowsocks read batch" `
    (Join-Path $Root "src\proxy\shadowsocks\server.cpp") `
    "kStreamReadBatchChunks\s*=\s*16" `
    "16 chunks"

$checks += Assert-Match `
    "xray vmess max padding" `
    (Join-Path $XrayRoot "proxy\vmess\encoding\auth.go") `
    "MaxPaddingLen\(\)\s+uint16\s*\{[\s\S]*return\s+64" `
    "64 bytes"

$checks += Assert-Match `
    "cnode vmess max padding" `
    (Join-Path $Root "src\proxy\vmess\encoding\client.cpp") `
    "kStreamMaxPaddingLen\s*=\s*64" `
    "64 bytes"

$checks += Assert-Match `
    "cnode vmess dynamic padding budget" `
    (Join-Path $Root "src\proxy\vmess\encoding\server.cpp") `
    "max_padding_len\s*=\s*[\s\S]*state\.global_padding\s*&&\s*state\.mask[\s\S]*\?\s*kStreamMaxPaddingLen\s*:\s*0" `
    "deduct padding only when enabled"

$checks += Assert-Match `
    "xray auth payload formula" `
    (Join-Path $XrayRoot "common\crypto\auth.go") `
    "payloadSize\s*:=\s*buf\.Size\s*-\s*int32\(w\.auth\.Overhead\(\)\)\s*-\s*w\.sizeParser\.SizeBytes\(\)\s*-\s*maxPadding" `
    "buf.Size - overhead - size - maxPadding"

$checks += Assert-Match `
    "cnode shadowsocks payload formula" `
    (Join-Path $Root "src\proxy\shadowsocks\client.cpp") `
    "kStreamChunkPayloadSize\s*=\s*[\s\S]*buf::Buffer::kSize\s*-\s*\(2\s*\+\s*SsAeadCipher::kTagSize\)\s*-\s*SsAeadCipher::kTagSize" `
    "8192 - (2+16) - 16 = 8158"

$checks += Assert-Match `
    "xray chunk stream slice" `
    (Join-Path $XrayRoot "common\crypto\chunk.go") `
    "const\s+sliceSize\s*=\s*8192" `
    "8192 bytes"

$checks += Assert-Match `
    "xray vless pipe limit" `
    (Join-Path $XrayRoot "proxy\vless\outbound\outbound.go") `
    "pipe\.WithSizeLimit\(2\s*\*\s*buf\.Size\)" `
    "2 * 8192"

$checks += Assert-Match `
    "cnode vless pending limit" `
    (Join-Path $Root "src\proxy\vless\outbound\vless_outbound.cpp") `
    "pending_\.capacity\(\)\s*>\s*buf::Buffer::kSize\s*\*\s*2" `
    "2 * 8192"

$checks += Assert-Match `
    "cnode anytls frame payload" `
    (Join-Path $Root "src\proxy\anytls\anytls_codec.hpp") `
    "kMaxFramePayload\s*=\s*0xffff" `
    "65535 bytes"

$checks | Format-Table -AutoSize

$failed = $checks | Where-Object { -not $_.Pass }
if ($failed) {
    throw "buffer alignment check failed: $($failed.Check -join ', ')"
}
