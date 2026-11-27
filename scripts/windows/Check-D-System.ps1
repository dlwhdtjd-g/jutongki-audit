#Requires -RunAsAdministrator
# [D] 패치·로그·시스템 점검 - 진단 전용(설정을 바꾸지 않음)        ( ? = Where-Object , % = ForEach-Object )
# 실행: powershell -ExecutionPolicy Bypass -File .\Check-D-System.ps1
$title = '패치·로그 관리 점검'; $file = 'system'; $R = @()
if ('가'.Length -ne 1) { 'Save this file as UTF-8 with BOM'; return }      # 한글 인코딩 확인

# Chk : 점검 1건을 실행해 결과를 한 줄로 출력한다. 검사 블록은 (판정, 근거) 두 값을 돌려준다
#       판정: $true=양호   $false=취약   $null=수동확인   'NA'=해당없음   ($skip 가 참이면 검사 없이 해당없음)
function Chk($code, $name, [scriptblock]$test, $skip = $false, $skipMsg = '') {
    try { if ($skip) { $ok, $ev = 'NA', $skipMsg } else { $ok, $ev = & $test } } catch { $ok, $ev = $null, "오류: $($_.Exception.Message)" }
    $s = if ($null -eq $ok) { '수동확인' } elseif ('NA' -eq $ok) { '해당없음' } elseif ($ok) { '양호' } else { '취약' }
    $color = @{ '양호' = 'Green'; '취약' = 'Red'; '수동확인' = 'Yellow'; '해당없음' = 'Gray' }[$s]
    Write-Host "  [$s]" -ForegroundColor $color -NoNewline; Write-Host " $code $name  ($ev)"
    $script:R += [pscustomobject]@{ 코드 = $code; 항목 = $name; 결과 = $s; 근거 = $ev }
}
function V($x) { if ($null -eq $x -or "$x" -eq '') { '미설정' } else { $x } }    # 빈 값은 '미설정'으로 표시
function Reg($p, $n) { (Get-ItemProperty $p -Name $n -EA 0).$n }                # 레지스트리 값 읽기
Write-Host "■ $title   $env:COMPUTERNAME   $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

$mp = Get-MpComputerStatus -EA 0; $now = Get-Date
$hf = (Get-HotFix | ? InstalledOn | sort InstalledOn -Descending | select -First 1).InstalledOn
$days = if ($hf) { [int]($now - $hf).TotalDays } else { 9999 }                 # 마지막 패치 후 경과일
$last = if ($hf) { $hf.ToString('yyyy-MM-dd') } else { '기록없음' }

Chk W-27 '최신OS빌드적용' {
    $c = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $days -le 90; "빌드=$($c.CurrentBuild).$($c.UBR), 마지막 패치 $last (${days}일 전, 기준 90일)"
}
Chk W-38 '보안패치적용' { $days -le 90; "마지막 보안패치 $last (${days}일 전, 기준 90일)" }
Chk W-39 '백신업데이트' {
    if (-not $mp) { $null; 'Defender 정보 없음 - 타사 백신 확인'; return }
    $d = [int]($now - $mp.AntivirusSignatureLastUpdated).TotalDays; $d -le 7; "시그니처 ${d}일 전 (기준 7일)"
}
Chk W-45 '백신설치' {
    if (-not $mp) { $null; 'Defender 정보 없음 - 타사 백신 확인'; return }
    [bool]($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled); "Defender=$($mp.AntivirusEnabled), 실시간보호=$($mp.RealTimeProtectionEnabled)"
}
Chk W-40 '시스템로깅설정' {
    $cat = [ordered]@{ '0CCE923F'='계정로그온'; '0CCE9235'='계정관리'; '0CCE9215'='로그온'; '0CCE921D'='개체접근'
                       '0CCE922F'='정책변경'; '0CCE9228'='권한사용'; '0CCE9210'='시스템'; '0CCE922B'='프로세스추적' }
    $a = auditpol /get /category:* /r | select -Skip 1 | ConvertFrom-Csv -Header M, T, N, G, I, E
    $bad = $cat.Keys | ? { $id = $_; -not ($a | ? { $_.G -match $id -and $_.I -match '성공|실패|Success|Failure' }) } | % { $cat[$_] }
    -not $bad; '감사 없음: ' + $(if ($bad) { $bad -join ',' } else { '없음' })
}
Chk W-41 'NTP시각동기화' {
    $s = (Get-Service w32time).Status; $src = w32tm /query /source
    $s -eq 'Running' -and $src -notmatch 'Local CMOS|Free-running'; "w32time=$s, 시간원본=$src"
}
Chk W-42 '이벤트로그관리' {
    $l = Get-WinEvent -ListLog Application, Security, System
    $o = Get-EventLog -List | ? { $_.Log -in 'Application', 'Security', 'System' }                                    # 덮어쓰기 설정(보존 일수)
    $bad = $l | ? { $_.MaximumSizeInBytes -lt 10240KB -or $_.FileSize -ge 0.9 * $_.MaximumSizeInBytes }               # KISA 기준 10,240KB 미만, 또는 90% 이상 사용(90일 전에 덮어쓰는 중)
    $ow = $o | ? { $_.OverflowAction -ne 'OverwriteOlder' -or $_.MinimumRetentionDays -ne 90 }                         # 90일 이후 이벤트 덮어쓰기가 아님
    -not $bad -and -not $ow
    ($l | % { $n = $_.LogName; $e = $o | ? Log -eq $n; "$n $([int]($_.FileSize / 1MB))/$($_.MaximumSizeInBytes / 1MB)MB, 덮어쓰기=$($e.OverflowAction)($($e.MinimumRetentionDays)일)" }) -join ', '
}
Chk W-63 '도메인시간동기화' { $null; "도메인 가입 - 시간원본=$(w32tm /query /source)" } (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) '워크그룹 서버(도메인 미가입)'
Chk W-35 'ODBC데이터소스' { $d = Get-OdbcDsn -EA 0; -not $d; 'ODBC 데이터 소스: ' + $(if ($d) { $d.Name -join ',' } else { '없음' }) }
Chk W-37 '예약작업점검' {
    $t = Get-ScheduledTask | ? { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -notmatch 'EdgeUpdate' }
    $cmd = $t | % { "$($_.TaskName): $($_.Actions.Execute) $($_.Actions.Arguments)" }
    if ($cmd -match ' -enc|EncodedCommand|mshta|certutil|bitsadmin|http|\\Temp\\|AppData') { $false } elseif ($cmd) { $null } else { $true }
    '비MS 작업: ' + $(if ($cmd) { $cmd -join ' | ' } else { '없음' })
}
Chk W-62 '시작프로그램분석' {
    $s = Get-CimInstance Win32_StartupCommand | % { "$($_.Name): $($_.Command)" }
    $out = $s | ? { $_ -notmatch ': "?(%windir%|%ProgramFiles%|[A-Z]:\\(Windows|Program Files))' }     # 기본 경로 밖의 항목
    if ($out -match 'Temp|AppData|http') { $false } elseif ($out) { $null } else { $true }
    '항목: ' + (($s | % { $_.Split(':')[0] }) -join ', ')
}

$dir = 'C:\check\log'; New-Item $dir -ItemType Directory -Force | Out-Null
$csv = "$dir\result_${file}_$(Get-Date -f 'yyMMdd_HHmm').csv"; $R | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host ("`n  " + (($R | Group-Object 결과 | % { "$($_.Name) $($_.Count)" }) -join '  /  '))
Write-Host "`n▶ 저장 : $csv"; Write-Host '※ 수동확인 항목은 설정을 직접 검토해 판정' -ForegroundColor Yellow
 