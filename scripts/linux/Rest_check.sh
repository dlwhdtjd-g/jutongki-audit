#!/bin/bash
# 주통기 나머지 점검: 계정 U-07~13 / 파일 U-28·29·31·32·33 / 로그 U-65~67 | 읽기전용 | sudo
G="\e[32m"; R="\e[31m"; Y="\e[33m"; N="\e[0m"
mkdir -p /root/check/log; CSV="/root/check/log/result_rest_$(date +%y%m%d_%H%M).csv"
printf '\xEF\xBB\xBF코드,항목,결과,근거\n' > "$CSV"
chk(){ case "$3" in 양호)c=$G;; 해당없음|수동확인)c=$Y;; *)c=$R;; esac
  echo -e "  ${c}[$3]${N} $1 $2 ($4)"; echo "$1,$2,$3,\"$4\"">>"$CSV"; }
act(){ systemctl is-active --quiet "$1" 2>/dev/null; }

echo -e "■ 나머지 점검 $(hostname) $(date '+%F %T')"

echo -e "\n[계정 관리]"
# U-07 불필요 기본계정 로그인쉘 보유
b=$(egrep '^(lp|uucp|nuucp|games|news|gopher|operator):' /etc/passwd 2>/dev/null|awk -F: '$7!~/nologin|false|sync|shutdown|halt/{print $1}'|tr '\n' ' ')
[ -z "$b" ]&&chk U-07 불필요계정제거 양호 "기본계정 로그인쉘 없음"||chk U-07 불필요계정제거 취약 "로그인쉘:$b"
# U-08 root(gid0) 그룹 추가원
m=$(awk -F: '$1=="root"{print $4}' /etc/group)
[ -z "$m" ]&&chk U-08 관리자그룹최소 양호 "root그룹 추가원 없음"||chk U-08 관리자그룹최소 수동확인 "root그룹:$m"
# U-09 계정 GID가 group에 존재
miss=""; for g in $(awk -F: '{print $4}' /etc/passwd|sort -u); do getent group "$g" >/dev/null||miss="$miss $g"; done
[ -z "$miss" ]&&chk U-09 GID존재확인 양호 "모든 GID 존재"||chk U-09 GID존재확인 취약 "없는GID:$miss"
# U-10 동일 UID
d=$(awk -F: '{print $3}' /etc/passwd|sort|uniq -d|tr '\n' ' ')
[ -z "$d" ]&&chk U-10 동일UID금지 양호 "중복 UID 없음"||chk U-10 동일UID금지 취약 "중복:$d"
# U-11 시스템계정(UID<1000) 로그인쉘 보유
b=$(awk -F: '($3<1000&&$3!=0&&$7!~/nologin|false|sync|shutdown|halt/){print $1}' /etc/passwd|tr '\n' ' ')
[ -z "$b" ]&&chk U-11 사용자Shell점검 양호 "시스템계정 로그인쉘 없음"||chk U-11 사용자Shell점검 취약 "로그인쉘:$b"
# U-12 세션 종료시간(TMOUT)
grep -qE '^[[:space:]]*(export[[:space:]]+)?TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null \
  &&chk U-12 세션종료시간 양호 "TMOUT 설정"||chk U-12 세션종료시간 취약 "TMOUT 미설정"
# U-13 암호 알고리즘 SHA512
if grep -qiE '^ENCRYPT_METHOD[[:space:]]+SHA512' /etc/login.defs 2>/dev/null; then chk U-13 암호알고리즘 양호 "SHA512"
elif awk -F: '$2~/^\$6\$|^\$y\$/{f=1}END{exit !f}' /etc/shadow 2>/dev/null; then chk U-13 암호알고리즘 양호 "SHA512 해시"
else chk U-13 암호알고리즘 취약 "SHA512 미사용"; fi

echo -e "\n[파일·디렉터리]"
# U-28 접속 IP·포트 제한(방화벽/TCP Wrapper)
if act firewalld; then chk U-28 접속IP포트제한 양호 "firewalld 활성"
elif grep -qiE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null; then chk U-28 접속IP포트제한 양호 "hosts.deny ALL:ALL"
else chk U-28 접속IP포트제한 취약 "방화벽/접근제어 미설정"; fi
# U-29 hosts.lpd
if [ ! -e /etc/hosts.lpd ]; then chk U-29 hostslpd권한 양호 "파일 없음"
else o=$(stat -c %U /etc/hosts.lpd); p=$(stat -c %a /etc/hosts.lpd)
  { [ "$o" = root ]&&[ "$p" -le 600 ]; }&&chk U-29 hostslpd권한 양호 "$o $p"||chk U-29 hostslpd권한 취약 "$o $p"; fi
# U-31 홈디렉터리 타인쓰기
n=$(find /home -maxdepth 1 -type d -perm -0002 2>/dev/null|wc -l)
[ "$n" -eq 0 ]&&chk U-31 홈디렉터리권한 양호 "타인쓰기 없음"||chk U-31 홈디렉터리권한 취약 "타인쓰기 ${n}개"
# U-32 홈디렉터리 실제 존재
miss=""; for h in $(awk -F: '($3>=1000&&$3<65534){print $6}' /etc/passwd); do [ -d "$h" ]||miss="$miss $h"; done
[ -z "$miss" ]&&chk U-32 홈디렉터리존재 양호 "모든 홈 존재"||chk U-32 홈디렉터리존재 취약 "없음:$miss"
# U-33 숨김파일(수동)
chk U-33 숨김파일점검 수동확인 "홈 숨김파일 수동 검토"

echo -e "\n[로그 관리]"
# U-65 NTP 시각 동기화
if act chronyd || act ntpd; then chk U-65 NTP동기화 양호 "시각동기화 활성"; else chk U-65 NTP동기화 취약 "NTP 미구동"; fi
# U-66 시스템 로깅
act rsyslog&&chk U-66 시스템로깅 양호 "rsyslog 활성"||chk U-66 시스템로깅 취약 "rsyslog 미구동"
# U-67 로그 디렉터리 권한
o=$(stat -c %U /var/log 2>/dev/null); p=$(stat -c %a /var/log 2>/dev/null)
{ [ "$o" = root ]&&[ "$p" -le 755 ]; }&&chk U-67 로그디렉터리권한 양호 "$o $p"||chk U-67 로그디렉터리권한 취약 "$o $p"

echo -e "\n✔ 저장: $CSV"
echo -e "${Y}※ 수동확인 항목은 직접 검토해 판정${N}"
