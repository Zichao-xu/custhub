# custhub 接入(Windows 10 1809 起, 用管理员身份打开 PowerShell):
#   irm https://github.com/__REPO__/releases/latest/download/custhub3-join.ps1 | iex
# 取发布清单、本平台程序、种子(GitHub 直连 → ghfast → gh-proxy) → 按清单里的 sha512 核对程序 → custhub join --seed
# 环境变量: CUSTHUB_BASE 下载地址(默认 https://github.com/__REPO__/releases), CUSTHUB_JOIN_ARGS 额外给 join 的参数
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'                    # 不刷进度条(经 ssh 会变成一堆 XML, 还拖慢下载)
# 提示文字用 UTF-8 的 base64 写: irm … | iex 按 Latin-1 解码脚本, 直接写中文会乱码
function M($b) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) }
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
$repo = '__REPO__'
$base = if ($env:CUSTHUB_BASE) { $env:CUSTHUB_BASE } else { "https://github.com/$repo/releases" }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072   # TLS 1.2
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw (M '6KaB566h55CG5ZGY5p2D6ZmQOiDlj7PplK4gUG93ZXJTaGVsbCDihpIg5Lul566h55CG5ZGY6Lqr5Lu96L+Q6KGMLCDlho3miafooYzkuIDmrKE=') }
$plat = if ([Environment]::Is64BitOperatingSystem) { 'win-x64' } else { 'win-x86' }
$t = Join-Path $env:TEMP ("custhub-" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $t | Out-Null
function Fetch($url, $out) {
    $pre = if ($url -like 'https://github.com/*') { @('', 'https://ghfast.top/', 'https://gh-proxy.com/') } else { @('') }
    foreach ($p in $pre) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 -Uri ($p + $url) -OutFile $out; return } catch { } }
    throw ((M '5LiL6L295LiN5LqG') + ' ' + $url)
}
try {
    Write-Host ((M 'Y3VzdGh1YiDmjqXlhaU6IOW5s+WPsA==') + ' ' + $plat)
    Fetch "$base/latest/download/custhub3.release" "$t\rel"
    $rel = Get-Content "$t\rel"
    $ver = ($rel | Where-Object { $_ -like 'version *' } | Select-Object -First 1).Substring(8)
    $line = $rel | Where-Object { $_ -like "file $plat *" } | Select-Object -First 1
    if (-not $ver -or -not $line) { throw ((M '5Y+R5biD5riF5Y2V6YeM5rKh5pyJ6L+Z5Liq5bmz5Y+w55qE56iL5bqPOg==') + ' ' + $plat) }
    Write-Host ('  ' + (M '5LiL6L2956iL5bqPLCDniYjmnKw=') + ' ' + $ver)
    Fetch "$base/download/v$ver/custhub3-$ver-$plat.exe" "$t\custhub.exe"
    Fetch "$base/latest/download/custhub3.seed" "$t\seed"
    $want = ($line -split ' ')[3]
    $got = (Get-FileHash -Algorithm SHA512 "$t\custhub.exe").Hash.ToLower()
    if ($got -ne $want) { throw (M '56iL5bqP55qEIHNoYTUxMiDlkozlj5HluIPmuIXljZXlr7nkuI3kuIosIOS4jeijhQ==') }
    $extra = if ($env:CUSTHUB_JOIN_ARGS) { $env:CUSTHUB_JOIN_ARGS -split ' ' } else { @() }
    & "$t\custhub.exe" join --seed "$t\seed" @extra
} finally { Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue }
