#!/bin/bash
# 주통기 파일·디렉터리 관리 점검 U-14~U-33 | 읽기전용 | sudo 실행 권장
G="\e[32m"; R="\e[31m"; Y="\e[33m"; N="\e[0m"
CSV="result_file_$(date +%y%m%d_%H%M).csv"
printf '\xEF\xBB\xBF코드,항목,결과,근거\n' > "$CSV"

chk(){ case "$3" in 양호) c=$G;; 해당없음|수동확인) c=$Y;; *) c=$R;; esac
  echo -e "  ${c}[$3]${N} $1 $2  ($4)"; echo "$1,$2,$3,\"$4\"" >> "$CSV"; }

# perm 코드 항목 파일 최대권한  → 소유자 root & 권한 이하면 양호
perm(){ [ -e "$3" ] || { chk "$1" "$2" 해당없음 "$3 없음"; return; }
  local o=$(stat -c %U "$3") p=$(stat -c %a "$3")
  { [ "$o" = root ] && [ "$p" -le "$4" ]; } && chk "$1" "$2" 양호 "$o $p" \
    || chk "$1" "$2" 취약 "$o $p (기준:root $4 이하)"; }

echo -e "■ 파일·디렉터리 관리 점검  $(hostname)  $(date '+%F %T')"

# U-14 root PATH 내 '.' 포함
echo "$PATH" | grep -qE '(^|:)\.(:|$)|::' \
  && chk U-14 rootPATH설정 취약 "PATH에 . 포함" || chk U-14 rootPATH설정 양호 "PATH 정상"

# U-15 소유자/그룹 없는 파일
n=$(find / -xdev \( -nouser -o -nogroup \) -not -path "*/containerd/*" 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-15 파일소유자설정 양호 "소유자없는파일 0" || chk U-15 파일소유자설정 취약 "소유자/그룹없음 ${n}개"

perm U-16 passwd권한   /etc/passwd 644
# U-17 시작스크립트 타인쓰기
n=$(find /etc/rc.d /etc/init.d -type f -perm -0002 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-17 시작스크립트권한 양호 "타인쓰기 0" || chk U-17 시작스크립트권한 취약 "타인쓰기 ${n}개"
perm U-18 shadow권한   /etc/shadow 400
perm U-19 hosts권한    /etc/hosts 600
# U-20 inetd
if   [ -e /etc/xinetd.conf ]; then perm U-20 inetd권한 /etc/xinetd.conf 600
elif [ -e /etc/inetd.conf  ]; then perm U-20 inetd권한 /etc/inetd.conf 600
else chk U-20 inetd권한 해당없음 "inetd 미사용"; fi
perm U-21 syslog권한   /etc/rsyslog.conf 640
perm U-22 services권한 /etc/services 644

# U-23 SUID/SGID (수동 검토)
n=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null|wc -l)
chk U-23 SUID/SGID점검 수동확인 "SUID/SGID ${n}개 — 목록 검토 필요"
# U-24 환경변수 파일 타인쓰기
n=$(find /etc/profile /etc/bashrc /etc/profile.d -type f -perm -0002 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-24 환경변수파일권한 양호 "타인쓰기 0" || chk U-24 환경변수파일권한 취약 "타인쓰기 ${n}개"
# U-25 world writable
n=$(find / -xdev -type f -perm -0002 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-25 worldwritable점검 양호 "쓰기가능 0" || chk U-25 worldwritable점검 취약 "world writable ${n}개"
# U-26 /dev 비정상 파일
n=$(find /dev -type f -not -path "/dev/shm/*" -not -path "/dev/mqueue/*" 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-26 dev파일점검 양호 "일반파일 0" || chk U-26 dev파일점검 취약 "일반파일 ${n}개"
# U-27 .rhosts / hosts.equiv
n=$(find /root /home \( -name .rhosts -o -name hosts.equiv \) 2>/dev/null|wc -l)
[ "$n" -eq 0 ] && chk U-27 rhosts사용금지 양호 "파일 없음" || chk U-27 rhosts사용금지 취약 "${n}개 존재"
# U-30 UMASK (022 이상)
u=$(grep -hiE '^[[:space:]]*umask' /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null|grep -oE '[0-7]{3}'|head -1)
if [ -n "$u" ] && [ $((8#$u & 8#022)) -eq $((8#022)) ]; then chk U-30 UMASK설정 양호 "umask=$u"
else chk U-30 UMASK설정 취약 "umask=${u:-미설정} (022 권장)"; fi

echo -e "\n✔ 저장: $(pwd)/$CSV"
echo -e "${Y}※ 수동확인(U-23 등)은 목록을 직접 검토해 양호/취약 판정${N}"
