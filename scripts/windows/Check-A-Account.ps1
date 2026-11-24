#Requires -RunAsAdministrator
# [A] 계정·로컬 보안 정책 점검 - 진단 전용(설정을 바꾸지 않음)        ( ? = Where-Object , % = ForEach-Object )
# 실행: powershell -ExecutionPolicy Bypass -File .\Check-A-Account.ps1
$title = '계정 관리 점검'; $file = 'account'; $R = @()
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

# --- 사전 수집: 보안 정책(secedit), 암호 정책(net accounts), 계정 ---
$sec = @{}; $f = "$env:TEMP\sec.cfg"; secedit /export /cfg $f /areas SECURITYPOLICY USER_RIGHTS | Out-Null
Get-Content $f | % { if ($_ -match '^\s*(\w+)\s*=\s*(.*)$') { $sec[$Matches[1]] = $Matches[2].Trim('"') } }
Remove-Item $f
$na = (net accounts) -match ':' | % { [int](($_ -split ':')[-1] -replace '\D', '') }   # [2]최대기간 [3]최소길이 [4]기록 [5]임계값 [6]잠금기간 [7]관찰창
$u = Get-LocalUser; $adm = $u | ? SID -like '*-500'; $guest = $u | ? SID -like '*-501'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$wl  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
function Names($r) {       # 권한 목록의 SID 를 계정 이름으로 변환
    ($r -split ',') -replace '\*' | % { try { ([Security.Principal.SecurityIdentifier]$_).Translate([Security.Principal.NTAccount]).Value } catch { $_ } }
}

Chk W-01 'Administrator계정명변경' { $adm.Name -ne 'Administrator'; "계정명=$($adm.Name)" }
Chk W-02 'Guest계정비활성화' { -not $guest.Enabled; "Guest활성화=$($guest.Enabled)" }
Chk W-03 '불필요계정제거' { $null; '활성 계정 용도 검토: ' + (($u | ? Enabled | % Name) -join ', ') }
Chk W-04 '계정잠금임계값' { $na[5] -in 1..5; "임계값=$($na[5]) (0=미설정)" }
Chk W-05 '암호복호화가능저장해제' { $sec.ClearTextPassword -eq '0'; "ClearTextPassword=$($sec.ClearTextPassword)" }
Chk W-06 '관리자그룹최소화' {
    $m = Get-LocalGroup -SID S-1-5-32-544 | Get-LocalGroupMember
    @($m | ? SID -notlike '*-500').Count -eq 0; '구성원: ' + ($m.Name -join ', ')
}
Chk W-07 'Everyone익명적용' { $v = Reg $lsa EveryoneIncludesAnonymous; -not $v; "EveryoneIncludesAnonymous=$(V $v)" }
Chk W-08 '계정잠금기간' { $na[6] -ge 60 -and $na[7] -ge 60; "잠금기간=$($na[6])분, 관찰창=$($na[7])분 (기준 60분 이상)" }
Chk W-09 '패스워드정책' {
    $sec.PasswordComplexity -eq 1 -and $na[3] -ge 8 -and $na[2] -in 1..90 -and $na[4] -ge 4
    "복잡성=$($sec.PasswordComplexity), 최소길이=$($na[3]), 최대기간=$($na[2])(0=무제한), 기록=$($na[4])"
}
Chk W-10 '마지막사용자표시안함' { $v = Reg $pol DontDisplayLastUserName; $v -eq 1; "DontDisplayLastUserName=$(V $v)" }
Chk W-11 '로컬로그온허용' { $n = Names $sec.SeInteractiveLogonRight; -not ($n | ? { $_ -notmatch 'Administrators|IUSR' }); "허용=$($n -join ', ')" }
Chk W-12 '익명SID변환해제' { $sec.LSAAnonymousNameLookup -eq '0'; "LSAAnonymousNameLookup=$($sec.LSAAnonymousNameLookup)" }
Chk W-13 '빈암호사용제한' { $v = Reg $lsa LimitBlankPasswordUse; $v -in $null, 1; "LimitBlankPasswordUse=$(V $v)" }
Chk W-14 '원격터미널사용자제한' { $null; 'Remote Desktop Users 구성원 직접 확인' } ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections) -eq 1) 'RDP 비활성화'
Chk W-15 '개인키암호입력' { $v = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' ForceKeyProtection; $v -eq 2; "ForceKeyProtection=$(V $v)" }
Chk W-47 '화면보호기' {
    $p = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; $d = 'HKCU:\Control Panel\Desktop'    # 정책 값이 있으면 우선
    $a, $t, $s = 'ScreenSaveActive', 'ScreenSaveTimeOut', 'ScreenSaverIsSecure' | % { $v = Reg $p $_; if ($null -eq $v) { $v = Reg $d $_ }; $v }
    $a -eq 1 -and $t -gt 0 -and $t -le 600 -and $s -eq 1; "사용=$(V $a), 대기시간(초)=$(V $t), 암호보호=$(V $s) (실행 계정 기준)"
}
Chk W-48 '로그온없이종료' { $v = Reg $pol ShutdownWithoutLogon; $v -in $null, 0; "ShutdownWithoutLogon=$(V $v)" }
Chk W-49 '원격강제종료' { $n = Names $sec.SeRemoteShutdownPrivilege; ($n -join ',') -eq 'BUILTIN\Administrators'; "허용=$($n -join ', ')" }
Chk W-50 '감사불가시종료' { $v = Reg $lsa CrashOnAuditFail; $v -in $null, 0; "CrashOnAuditFail=$(V $v)" }
Chk W-51 'SAM익명열거' {
    $a, $b = (Reg $lsa RestrictAnonymous), (Reg $lsa RestrictAnonymousSAM)
    $a -ge 1 -and $b -in $null, 1; "RestrictAnonymous=$(V $a), RestrictAnonymousSAM=$(V $b)"
}
Chk W-52 '자동로그온' { $v = Reg $wl AutoAdminLogon; $v -ne 1; "AutoAdminLogon=$(V $v)" }
Chk W-53 '이동식미디어' {
    $v = Reg $wl AllocateDASD
    if ($null -eq $v) { $null; 'AllocateDASD 미설정(기본 Administrators) - 가이드 확인'; return }
    "$v" -eq '0'; "AllocateDASD=$v"
}
Chk W-54 'DoS방어설정' {
    $t = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; $n = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
    $v = (Reg $t SynAttackProtect), (Reg $t EnableDeadGWDetect), (Reg $t KeepAliveTime), (Reg $n NoNameReleaseOnDemand)
    ($v -join ',') -eq '1,0,300000,1'; "값=$(($v | % { V $_ }) -join ',') (기준 1,0,300000,1)"
}
Chk W-55 '프린터드라이버설치' {
    $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' AddPrinterDrivers
    $v -eq 1; "AddPrinterDrivers=$(V $v)"
}
Chk W-56 'SMB세션중단' { $v = Reg $srv autodisconnect; $v -ge 1 -and $v -le 15; "autodisconnect=$(V $v)분 (기준 15분 이하)" }
Chk W-57 '로그온경고메시지' {
    $c = Reg $pol LegalNoticeCaption; $t = Reg $pol LegalNoticeText
    "$c".Trim() -ne '' -and "$t".Trim() -ne ''; "제목=$(V $c), 내용=$(V $t)"
}
Chk W-59 'LANManager인증' {
    $v = Reg $lsa LmCompatibilityLevel
    if ($null -eq $v) { $null; 'LmCompatibilityLevel 미설정 - 정책 확인'; return }
    $v -ge 3; "LmCompatibilityLevel=$v (기준 3 이상)"
}
Chk W-60 '보안채널서명암호화' {
    $v = 'RequireSignOrSeal', 'SealSecureChannel', 'SignSecureChannel' | % { Reg $nl $_ }
    ($v -join ',') -eq '1,1,1'; "Sign/Seal=$(($v | % { V $_ }) -join ',')"
}

$dir = 'C:\check\log'; New-Item $dir -ItemType Directory -Force | Out-Null
$csv = "$dir\result_${file}_$(Get-Date -f 'yyMMdd_HHmm').csv"; $R | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host ("`n  " + (($R | Group-Object 결과 | % { "$($_.Name) $($_.Count)" }) -join '  /  '))
Write-Host "`n▶ 저장 : $csv"; Write-Host '※ 수동확인 항목은 설정을 직접 검토해 판정' -ForegroundColor Yellow
