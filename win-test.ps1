# mesh sh 的 Windows 验收(由 win-test.sh 拷到 Windows 机器上跑; 在那台本机起 r / b / e 三个节点)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
Set-Location "$env:TEMP\meshtest"
$M = "$PWD\mesh.exe"
$pass = 0; $fail = 0
function ok($m) { Write-Output "  OK   $m"; $script:pass++ }
function ng($m) { Write-Output "  FAIL $m"; $script:fail++ }
function bytes($f) { if (Test-Path $f) { [IO.File]::ReadAllBytes("$PWD\$f") } else { @() } }
function hex($b) { ($b | ForEach-Object { $_.ToString('x2') }) -join '' }

$ps = foreach ($n in 'r', 'b', 'e') { Start-Process -FilePath $M -ArgumentList 'run', $n -PassThru -WindowStyle Hidden -WorkingDirectory $PWD }
Start-Sleep 3

Write-Output "== 1 跑命令(管道, 输出原样)"
cmd /c "`"$M`" sh e b -- echo hello> o1.txt"; $c = $LASTEXITCODE
$h = hex (bytes o1.txt)
if ($h -eq '68656c6c6f0d0a' -and $c -eq 0) { ok "echo hello: 输出逐字节原样(cmd 自己的 CRLF), 退出码 0" } else { ng "echo: $h 退出码 $c" }
cmd /c "`"$M`" sh e b -- exit 3 > nul"; $c = $LASTEXITCODE
if ($c -eq 3) { ok "退出码原样带回(3)" } else { ng "退出码 $c" }
cmd /c "`"$M`" sh e b -- echo 中文测试> o2.txt"
$h = hex (bytes o2.txt)
if ($h -eq 'e4b8ade69687e6b58be8af950d0a') { ok "中文: 命令和输出都是 UTF-8" } else { ng "中文: $h" }
cmd /c "echo abc| `"$M`" sh e b -- findstr x* > o3.txt"; $c = $LASTEXITCODE
$t = [Text.Encoding]::UTF8.GetString((bytes o3.txt))
if ($t -match 'abc' -and $c -eq 0) { ok "标准输入送到对方, 输入到头后命令正常结束" } else { ng "标准输入: [$t] $c" }
cmd /c "`"$M`" sh e b -- powershell -NoProfile -Command `"'x'*3000000`" > o4.txt"
$n = ((bytes o4.txt) | Where-Object { $_ -eq 120 }).Count
if ($n -eq 3000000) { ok "3MB 输出一个字节不少" } else { ng "大输出只收到 $n" }
cmd /c "`"$M`" sh e b -- whoami > o5.txt"
$t = ([Text.Encoding]::UTF8.GetString((bytes o5.txt))).Trim()
if ($t -eq (whoami)) { ok "以守护进程的身份跑($t)" } else { ng "身份: [$t]" }

Write-Output "== 2 交互(ConPTY)"
cmd /c "(echo echo hi-%NUMBER_OF_PROCESSORS%-zz& echo exit 7) | `"$M`" sh e b > o6.txt"; $c = $LASTEXITCODE
$t = [Text.Encoding]::UTF8.GetString((bytes o6.txt))
if ($t -match "hi-$env:NUMBER_OF_PROCESSORS-zz" -and $c -eq 7) { ok "管道喂给 PowerShell(ConPTY): 输出对, 退出码 7" } else { ng "交互: 退出码 $c, 输出 [$($t.Substring(0, [Math]::Min(300, $t.Length)))]" }
if ($t.Contains([string][char]27 + "[")) { ok "交互输出是 VT 序列(ConPTY)" } else { ng "交互输出里没有 VT 序列" }

Write-Output "== 3 拒绝"
Copy-Item e\pass e.pass.good; Copy-Item e.pass.noshell e\pass -Force
cmd /c "`"$M`" sh e b -- echo x > nul 2> o7.txt"; $c = $LASTEXITCODE
$t = [Text.Encoding]::UTF8.GetString((bytes o7.txt))
if ($c -eq 255 -and $t -match '不含这项服务') { ok "通行证没有 sh 被拒: $($t.Trim())" } else { ng "证里无 sh: $c [$t]" }
Copy-Item e.pass.good e\pass -Force

Write-Output "== 4 工程师那头走了, 整棵进程树收掉"
$cli = Start-Process -FilePath $M -ArgumentList 'sh', 'e', 'b', '--', 'ping -n 300 127.0.0.1' -PassThru -WindowStyle Hidden
Start-Sleep 3
$before = @(Get-CimInstance Win32_Process -Filter "Name='PING.EXE'" | Where-Object { $_.CommandLine -match '300' }).Count
if ($before -ge 1) { ok "长命令在跑(ping)" } else { ng "长命令没起来" }
Stop-Process -Id $cli.Id -Force
Start-Sleep 3
$after = @(Get-CimInstance Win32_Process -Filter "Name='PING.EXE'" | Where-Object { $_.CommandLine -match '300' }).Count
if ($after -eq 0) { ok "工程师走了, 对方的 ping 和 cmd 都收掉了" } else { ng "工程师走了, 还剩 $after 个 ping"; Get-CimInstance Win32_Process -Filter "Name='PING.EXE'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } }

$ps | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Write-Output "== 日志(b)"
Get-Content b.log -Encoding UTF8 | Select-Object -Last 12
Write-Output "== 结果: 通过 $pass, 失败 $fail"
