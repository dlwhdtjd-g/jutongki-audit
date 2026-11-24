#Requires -RunAsAdministrator
# [C] 네트워크·서비스 점검 - 진단 전용(설정을 바꾸지 않음)        ( ? = Where-Object , % = ForEach-Object )
# 실행: powershell -ExecutionPolicy Bypass -File .\Check-C-Service.ps1
$title = '서비스 관리 점검'; $file = 'service'; $R = @()
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

# --- 사전 수집: IIS/FTP 설정(applicationHost.config), 서비스, DNS 영역 ---
$x = [xml](Get-Content "$env:windir\System32\inetsrv\config\applicationHost.config" -Raw -EA 0)
$ftp = if ($x) { @($x.SelectNodes("//site[bindings/binding[@protocol='ftp']]"))[0] }      # 첫 번째 FTP 사이트 기준
$iis = Get-Service W3SVC -EA 0; $dns = Get-Service DNS -EA 0; $snmp = Get-Service SNMP -EA 0
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; $rdp = "$ts\WinStations\RDP-Tcp"
$noRdp = (Reg $ts fDenyTSConnections) -eq 1; $noFtp = -not $ftp; $noSnmp = -not $snmp; $noDns = -not $dns   # 해당없음 조건
$zones = if ($dns) { Get-DnsServerZone | ? { -not $_.IsAutoCreated } }; $snmpKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'
$wide = '^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)$'

Chk W-18 '불필요서비스제거' {
    $b = Get-Service Alerter, ClipSrv, Messenger, SimpTcp, TlntSvr -EA 0 | ? Status -eq Running
    -not $b; '구동중: ' + $(if ($b) { $b.Name -join ',' } else { '없음' })
}
Chk W-19 '불필요IIS서비스' { if (-not $iis) { $true; 'IIS 미설치' } else { $null; 'IIS 구동중 - 사용 목적 검토 (' + ($x.SelectNodes('//site').name -join ',') + ')' } }
Chk W-20 'NetBIOS바인딩' {
    $n = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true'
    -not ($n | ? TcpipNetbiosOptions -ne 2); 'NetBIOS옵션=' + ($n.TcpipNetbiosOptions -join ',') + ' (2=사용안함)'
}
Chk W-21 '암호화안된FTP' {
    $s = $ftp.ftpServer.security.ssl; $s.controlChannelPolicy -eq 'SslRequire' -and $s.dataChannelPolicy -eq 'SslRequire'
    "SSL정책=$(V $s.controlChannelPolicy)/$(V $s.dataChannelPolicy) (기준 SslRequire)"
} $noFtp 'FTP 미구동'
Chk W-22 'FTP디렉터리권한' {
    $p = [Environment]::ExpandEnvironmentVariables($ftp.application.virtualDirectory.physicalPath)
    $acl = (Get-Acl $p).Access | ? { $_.IdentityReference -match $wide -and $_.FileSystemRights -match 'Modify|FullControl' }
    $rule = $x.SelectNodes("//location[@path='$($ftp.name)']//authorization/add[contains(@permissions,'Write')][@users='*' or @users='?']")
    -not ($acl -or $rule.Count); "홈=$p, 광범위쓰기권한=$(@($acl).Count), 전체사용자쓰기규칙=$($rule.Count)"
} $noFtp 'FTP 미구동'
Chk W-24 'FTP접근제어' { $ip = $x.SelectNodes("//location[@path='$($ftp.name)']//ipSecurity/add"); $ip.Count -gt 0; "IP제한 규칙=$($ip.Count)개" } $noFtp 'FTP 미구동'
Chk W-25 'DNSZoneTransfer' {
    $any = $zones | ? SecureSecondaries -eq 'TransferAnyServer'; -not $any; "영역 $(@($zones).Count)개 중 모든 서버 전송 허용 $(@($any).Count)개"
} $noDns 'DNS 미구동'
Chk W-26 'RDS제거' { $null; 'IIS MSADC 가상 디렉터리 직접 확인' } ([Environment]::OSVersion.Version.Major -ge 6) 'Windows Server 2008 이상 - 대상 아님'
Chk W-28 '터미널암호화수준' { $v = Reg $rdp MinEncryptionLevel; $v -ge 2; "MinEncryptionLevel=$(V $v) (기준 2 이상)" } $noRdp 'RDP 비활성화'
Chk W-29 'SNMP서비스구동' { -not ($snmp -and $snmp.Status -eq 'Running'); 'SNMP: ' + $(if ($snmp) { $snmp.Status } else { '미설치' }) }
Chk W-30 'SNMPCommunity' {
    $c = (Get-Item "$snmpKey\ValidCommunities" -EA 0).Property; -not ($c -match '^(public|private)$'); "Community $(@($c).Count)개 (이름 비공개)"
} $noSnmp 'SNMP 미설치'
Chk W-31 'SNMPAccessControl' {
    $m = (Get-Item "$snmpKey\PermittedManagers" -EA 0).Property; @($m).Count -gt 0; "허용 호스트 $(@($m).Count)개"
} $noSnmp 'SNMP 미설치'
Chk W-32 'DNS서비스구동' {
    -not ($zones | ? DynamicUpdate -eq 'NonsecureAndSecure'); '동적업데이트: ' + (($zones.DynamicUpdate | ? { $_ } | sort -Unique) -join ',')
} $noDns 'DNS 미구동'
Chk W-33 'HTTP/FTP배너차단' {
    $h = $x.SelectNodes("//requestFiltering[@removeServerHeader='true']").Count
    $b = $x.SelectNodes("//ftpServer/messages[@suppressDefaultBanner='true']").Count
    ($h -gt 0 -or -not $iis) -and ($b -gt 0 -or $noFtp); "HTTP헤더제거=$h, FTP기본배너숨김=$b"
} (-not ($iis -or $ftp)) 'IIS/FTP 미구동'
Chk W-34 'Telnet비활성화' { $s = Get-Service TlntSvr -EA 0; -not ($s -and $s.Status -eq 'Running'); 'Telnet: ' + $(if ($s) { $s.Status } else { '미설치' }) }
Chk W-36 '원격터미널타임아웃' { $v = Reg $rdp MaxIdleTime; $v -gt 0 -and $v -le 1800000; "MaxIdleTime=$(V $v)ms (기준 30분 이하)" } $noRdp 'RDP 비활성화'
Chk W-44 '원격레지스트리' { $s = Get-Service RemoteRegistry -EA 0; -not ($s -and $s.Status -eq 'Running'); "RemoteRegistry: $($s.Status)" }
Chk W-64 '방화벽설정' {
    $off = (Get-NetFirewallProfile | ? Enabled -eq $false).Name
    $ap = (Get-NetConnectionProfile).NetworkCategory -replace 'DomainAuthenticated', 'Domain'      # 현재 사용 중인 프로필
    $open = Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow |
        ? { $_.Profile -match "Any|$($ap -join '|')" } | % {
            $p = ($_ | Get-NetFirewallPortFilter).LocalPort -join ','; $any = ($_ | Get-NetFirewallAddressFilter).RemoteAddress -eq 'Any'
            if ($any -and $p -match '(^|,)(135|137|138|139|445|3389|5985)(,|$)|\d+-\d+') { "$($_.DisplayName)($p)" } }
    -not ($off -or $open); "꺼진프로필=$($off -join ',') / 전체허용 위험규칙 $(@($open).Count)개 예) $(@($open)[0..1] -join ', ')"
}

$dir = 'C:\check\log'; New-Item $dir -ItemType Directory -Force | Out-Null
$csv = "$dir\result_${file}_$(Get-Date -f 'yyMMdd_HHmm').csv"; $R | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host ("`n  " + (($R | Group-Object 결과 | % { "$($_.Name) $($_.Count)" }) -join '  /  '))
Write-Host "`n▶ 저장 : $csv"; Write-Host '※ 수동확인 항목은 설정을 직접 검토해 판정' -ForegroundColor Yellow
