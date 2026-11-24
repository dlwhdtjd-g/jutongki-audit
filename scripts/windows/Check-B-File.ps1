#Requires -RunAsAdministrator
# [B] 공유·파일 권한 점검 - 진단 전용(설정을 바꾸지 않음)        ( ? = Where-Object , % = ForEach-Object )
# 실행: powershell -ExecutionPolicy Bypass -File .\Check-B-File.ps1
$title = '파일·디렉터리 점검'; $file = 'file'; $R = @()
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

$all = Get-SmbShare; $sh = $all | ? { -not $_.Special }          # 사용자 공유만 (C$, ADMIN$, IPC$ 제외)
$wide = '^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)$'   # 너무 넓은 권한 대상
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

Chk W-16 '공유권한설정' {
    $bad = foreach ($s in $sh) {
        Get-SmbShareAccess $s.Name | ? AccountName -eq 'Everyone' | % { "$($s.Name) 공유권한 Everyone/$($_.AccessRight)" }
        (Get-Acl $s.Path).Access | ? { $_.IdentityReference -match $wide -and $_.FileSystemRights -match 'Modify|FullControl' } |
            % { "$($s.Name) NTFS $($_.IdentityReference)" }
    }
    -not $bad; if ($bad) { $bad -join ' | ' } else { '사용자 공유: ' + ($sh.Name -join ', ') }
}
Chk W-17 '기본공유제거' { $d = $all | ? Name -match '^[A-Z]\$$'; -not $d; '드라이브 기본공유: ' + $(if ($d) { $d.Name -join ',' } else { '없음' }) }
Chk W-23 '공유익명접근제한' { $r = Reg $srv restrictnullsessaccess; $r -eq 1 -and -not (Reg $srv NullSessionShares); "RestrictNullSessAccess=$(V $r)" }
Chk W-43 '이벤트로그접근통제' {
    $a = foreach ($f in 'Logs', 'Logs\Application.evtx', 'Logs\Security.evtx', 'Logs\System.evtx') {
        (Get-Acl "$env:SystemRoot\System32\winevt\$f").Access | ? IdentityReference -match 'Everyone'
    }
    -not $a; 'Everyone 권한: ' + $(if ($a) { '있음' } else { '없음' })
}
Chk W-46 'SAM파일접근통제' {
    $x = (Get-Acl "$env:SystemRoot\System32\config\SAM").Access | ? IdentityReference -notmatch 'SYSTEM|Administrators'
    -not $x; 'Administrators/SYSTEM 외 권한: ' + $(if ($x) { $x.IdentityReference -join ',' } else { '없음' })
}
Chk W-58 '홈디렉터리권한' {
    $x = Get-ChildItem C:\Users -Directory | ? Name -notin 'Public', 'Default', 'Default User', 'All Users' |
         ? { (Get-Acl $_.FullName).Access.IdentityReference -match 'Everyone' }
    -not $x; 'Everyone 권한 있는 홈: ' + $(if ($x) { $x.Name -join ',' } else { '없음' })
}
Chk W-61 '파일시스템보호' {
    $v = Get-Volume | ? { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
    -not ($v | ? FileSystem -notin 'NTFS', 'ReFS'); ($v | % { "$($_.DriveLetter): $($_.FileSystem)" }) -join ', '
}

$dir = 'C:\check\log'; New-Item $dir -ItemType Directory -Force | Out-Null
$csv = "$dir\result_${file}_$(Get-Date -f 'yyMMdd_HHmm').csv"; $R | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host ("`n  " + (($R | Group-Object 결과 | % { "$($_.Name) $($_.Count)" }) -join '  /  '))
Write-Host "`n▶ 저장 : $csv"; Write-Host '※ 수동확인 항목은 설정을 직접 검토해 판정' -ForegroundColor Yellow
