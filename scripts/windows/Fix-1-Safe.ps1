#Requires -RunAsAdministrator
# Fix-1-Safe : 서비스 영향이 작은 16개 항목 조치 (W-04 08 09 10 11 15 20 33 40 42 47 51 53 54 57 59)
# 실행: powershell -ExecutionPolicy Bypass -File .\Fix-1-Safe.ps1        ( % = ForEach-Object )
if ('가'.Length -ne 1) { 'Save this file as UTF-8 with BOM'; return }      # 한글 인코딩 확인
$ErrorActionPreference = 'Stop'; $bak = 'C:\check\backup'; $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Write-Host "■ Fix-1 조치 (안전 항목 16개)   $env:COMPUTERNAME   $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
if ((Read-Host '설정을 변경합니다. 계속하려면 y 입력') -ne 'y') { return }

# Fix   : 조치 1건을 실행하고 [완료] 또는 [실패] 로 한 줄 출력 (명령 프로그램의 종료 코드가 0이 아니면 실패)
# SetReg: 레지스트리 값을 설정 (키가 없으면 만든다)
function Fix($code, $name, $desc, [scriptblock]$do) {
    try { $global:LASTEXITCODE = 0; & $do | Out-Null; if ($LASTEXITCODE) { throw "종료 코드 $LASTEXITCODE" }
          Write-Host "  [완료] $code $name  ($desc)" -ForegroundColor Green }
    catch { Write-Host "  [실패] $code $name  ($($_.Exception.Message))" -ForegroundColor Red }
}
function SetReg($path, $name, $value, $type = 'DWord') {
    if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
    New-ItemProperty $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
}

# --- 0. 백업: 조치 전 설정을 저장 (되돌릴 때 사용) ---
New-Item $bak -ItemType Directory -Force | Out-Null
secedit /export /cfg "$bak\secpol_before.cfg" | Out-Null; auditpol /backup /file:"$bak\audit_before.csv" | Out-Null
net accounts > "$bak\net_accounts_before.txt"
foreach ($k in 'SYSTEM\CurrentControlSet\Control\Lsa', 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
               'SYSTEM\CurrentControlSet\Services\NetBT\Parameters', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') {
    reg export "HKLM\$k" "$bak\$($k -replace '\W', '_').reg" /y | Out-Null
}
Write-Host "  백업 완료: $bak`n" -ForegroundColor DarkGray

# --- 1. 계정·암호 정책 ---
Fix W-04 '계정잠금임계값' '5회 실패 시 잠금' { net accounts /lockoutthreshold:5 }
Fix W-08 '계정잠금기간' '잠금 60분, 재설정 60분' { net accounts /lockoutduration:60 /lockoutwindow:60 }
Fix W-09 '패스워드정책' '최소 8자, 최대 90일, 기록 4개' { net accounts /minpwlen:8 /maxpwage:90 /uniquepw:4 }
Fix W-10 '마지막사용자표시안함' 'DontDisplayLastUserName=1' { SetReg $pol DontDisplayLastUserName 1 }
Fix W-11 '로컬로그온허용' 'Administrators 만 허용' {      # 보안 정책 템플릿을 만들어 secedit 으로 적용
    $inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544
'@
    $inf | Set-Content "$bak\logon.inf" -Encoding Unicode
    secedit /configure /db "$bak\logon.sdb" /cfg "$bak\logon.inf" /areas USER_RIGHTS
}
Fix W-15 '개인키암호입력' 'ForceKeyProtection=2' { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' ForceKeyProtection 2 }

# --- 2. 보안 옵션 (레지스트리) ---
Fix W-47 '화면보호기' '대기 10분, 암호 보호 (실행 계정 기준)' {
    $d = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    SetReg $d ScreenSaveActive '1' String; SetReg $d ScreenSaveTimeOut '600' String
    SetReg $d ScreenSaverIsSecure '1' String; SetReg $d 'SCRNSAVE.EXE' 'scrnsave.scr' String
}
Fix W-51 'SAM익명열거' 'RestrictAnonymous=1' { SetReg $lsa RestrictAnonymous 1 }
Fix W-53 '이동식미디어' 'AllocateDASD=0 (Administrators)' { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AllocateDASD '0' String }
Fix W-54 'DoS방어설정' 'SYN 공격 방어 등 4개 값' {
    $t = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    SetReg $t SynAttackProtect 1; SetReg $t EnableDeadGWDetect 0; SetReg $t KeepAliveTime 300000
    SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' NoNameReleaseOnDemand 1
}
Fix W-57 '로그온경고메시지' '경고 제목·내용 설정' {
    SetReg $pol LegalNoticeCaption '경고' String
    SetReg $pol LegalNoticeText '이 시스템은 허가된 사용자만 사용할 수 있습니다. 무단 접속 시 법적 책임이 따를 수 있습니다.' String
}
Fix W-59 'LANManager인증' 'LmCompatibilityLevel=3 (NTLMv2)' { SetReg $lsa LmCompatibilityLevel 3 }

# --- 3. 네트워크·IIS·로그 ---
Fix W-20 'NetBIOS바인딩' '모든 어댑터에서 NetBIOS 사용 안 함' {
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | % {
        $r = Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
        if ($r.ReturnValue -notin 0, 1) { throw "반환 코드 $($r.ReturnValue)" }       # 0=성공, 1=재부팅 필요
    }
}
Fix W-33 'HTTP/FTP배너차단' 'Server 헤더 제거, FTP 기본 배너 숨김' {
    & $appcmd set config /section:requestFiltering /removeServerHeader:true /commit:apphost; if ($LASTEXITCODE) { throw 'IIS 설정 실패' }
    & $appcmd set config -section:system.applicationHost/sites "/[name='Webhard'].ftpServer.messages.suppressDefaultBanner:true" /commit:apphost
}
Fix W-40 '시스템로깅설정' '8개 감사 범주를 성공/실패로 설정' {
    foreach ($id in '0CCE923F', '0CCE9235', '0CCE9215', '0CCE921D', '0CCE922F', '0CCE9228', '0CCE9210', '0CCE922B') {
        auditpol /set /subcategory:"{$id-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE) { throw "auditpol 실패 ($id)" }
    }
    SetReg $lsa SCENoApplyLegacyAuditPolicy 1                 # 세부 감사 정책을 우선 적용
}
Fix W-42 '이벤트로그관리' 'Security 200MB, Application/System 50MB, 90일 이후 이벤트 덮어쓰기' {
    wevtutil sl Security /ms:209715200; if ($LASTEXITCODE) { throw 'wevtutil 실패' }
    wevtutil sl Application /ms:52428800; wevtutil sl System /ms:52428800
    Limit-EventLog -LogName Application, Security, System -OverflowAction OverwriteOlder -RetentionDays 90     # 보존 일수는 wevtutil 에 옵션이 없어 이 명령으로 설정
}

# --- 4. 선택: user 계정은 암호가 필수가 아님 -> 암호 설정 (그냥 Enter 를 누르면 건너뜀) ---
$pw = Read-Host "`nuser 계정 새 암호 (8자 이상, 영문·숫자·특수문자 / 건너뛰려면 Enter)" -AsSecureString
if ($pw.Length -gt 0) { Fix W-09 'user계정암호필수' '암호 설정 + 암호 필수' { Set-LocalUser user -Password $pw; net user user /passwordreq:yes } }

Write-Host "`n▶ 백업 위치 : $bak" -ForegroundColor Cyan
Write-Host '※ W-11, W-20, W-54 등은 재부팅 후 적용됩니다. 재부팅한 뒤 점검 스크립트(A~D)로 확인하세요.' -ForegroundColor Yellow
 