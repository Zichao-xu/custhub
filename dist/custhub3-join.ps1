# custhub 接入(Windows 7 起, 用管理员身份打开 PowerShell):
#   Win10 / 11:  irm https://github.com/__REPO__/releases/latest/download/custhub3-join.ps1 | iex
#   Win7 / 8:    iex (New-Object Net.WebClient).DownloadString('http://<任一台可达机器的 IP:端口>/releases/latest/download/custhub3-join.ps1')  (Win7 连不了 GitHub 的 HTTPS, 从网里的机器取)
# 取发布清单、本平台程序、种子(GitHub 直连 → ghfast → gh-proxy) → 按清单里的 sha512 核对程序 → custhub join --seed
#   平台: Win10 1809 起用 win-x64 / win-x86; 更老的(Win7 / 8 / 8.1、没有 ConPTY 的 Win10)用 win7-x64 / win7-x86(补丁模块版)
# 只用 PowerShell 2.0 就有的写法(Win7 自带 2.0): 不用 Invoke-WebRequest / Get-FileHash / ::new
# 环境变量: CUSTHUB_BASE 下载地址(默认 https://github.com/__REPO__/releases), CUSTHUB_JOIN_ARGS 额外给 join 的参数
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'                    # 不刷进度条(经 ssh 会变成一堆 XML, 还拖慢下载)
# 提示文字用 UTF-8 的 base64 写: irm … | iex 按 Latin-1 解码脚本, 直接写中文会乱码
function M($b) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) }
# PowerShell 2.0(Win7 自带)在 UTF-8 代码页下一输出中文就整个崩掉(窗口直接没了): 只在 3.0 起切; custhub.exe 自己会切过去再切回来
if ($PSVersionTable.PSVersion.Major -ge 3) { try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { } }
$repo = '__REPO__'
$base = 'https://github.com/__REPO__/releases'   # 从某台机器的 http://IP:端口 取时, 它发出来的这一行已换成它自己
if ($env:CUSTHUB_BASE) { $base = $env:CUSTHUB_BASE }
$tls12 = $true
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch { $tls12 = $false }   # TLS 1.2: .NET 3.5 没有
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw (M '6KaB566h55CG5ZGY5p2D6ZmQOiDlj7PplK4gUG93ZXJTaGVsbCDihpIg5Lul566h55CG5ZGY6Lqr5Lu96L+Q6KGMLCDlho3miafooYzkuIDmrKE=') }
$v = [Environment]::OSVersion.Version
$arch = 'x86'
if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { $arch = 'x64' }
$plat = "win-$arch"
if ($v.Major -lt 10 -or $v.Build -lt 17763) { $plat = "win7-$arch" }   # 没有 ConPTY: 补丁模块版
$t = Join-Path $env:TEMP ("custhub-" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $t | Out-Null
function Fetch($url, $out) {
    $pre = @('')
    if ($url -like 'https://github.com/*') { $pre = @('', 'https://ghfast.top/', 'https://gh-proxy.com/') }
    foreach ($p in $pre) { try { (New-Object Net.WebClient).DownloadFile($p + $url, $out); return } catch { } }
    $m = (M '5LiL6L295LiN5LqG') + ' ' + $url
    if (-not $tls12) { $m = $m + ' ' + (M 'KFdpbjcg6KaB6KOFIC5ORVQgNC41IOS7peS4iuaJjeiDvei/niBHaXRIdWI6IOezu+e7n+WPquaciSAuTkVUIDMuNSDml7bkuIvovb3kvJrlpLHotKUp') }
    throw $m
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
    $sha = [Security.Cryptography.SHA512]::Create(); $fs = [IO.File]::OpenRead("$t\custhub.exe")
    try { $got = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $fs.Close() }
    if ($got -ne $want) { throw (M '56iL5bqP55qEIHNoYTUxMiDlkozlj5HluIPmuIXljZXlr7nkuI3kuIosIOS4jeijhQ==') }
    $extra = @()
    if ($env:CUSTHUB_JOIN_ARGS) { $extra = $env:CUSTHUB_JOIN_ARGS -split ' ' }
    & "$t\custhub.exe" join --seed "$t\seed" @extra
} finally { Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue }
