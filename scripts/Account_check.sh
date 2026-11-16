#!/bin/bash
# 주통기 계정 관리 점검 U-01~U-06 | 읽기전용 | sudo 실행 권장
G="\e[32m"; R="\e[31m"; N="\e[0m"
CSV="result_account_$(date +%y%m%d_%H%M).csv"
printf '\xEF\xBB\xBF코드,항목,결과,근거\n' > "$CSV"

# chk 코드 항목 판정 근거
chk(){ [ "$3" = 양호 ] && c=$G || c=$R
  echo -e "  ${c}[$3]${N} $1 $2  ($4)"
  echo "$1,$2,$3,\"$4\"" >> "$CSV"; }

echo -e "■ 계정 관리 점검  $(hostname)  $(date '+%F %T')"

# U-01 root 원격접속
v=$(sshd -T 2>/dev/null|awk '/permitrootlogin/{print $2}')
[[ $v =~ ^(no|prohibit-password|without-password)$ ]] && r=양호 || r=취약
chk U-01 root원격접속제한 $r "PermitRootLogin=${v:-미확인}"

# U-02 패스워드 정책
d=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs); d=${d:-99999}
m=$(grep -oE '^\s*minlen\s*=\s*[0-9]+' /etc/security/pwquality.conf 2>/dev/null|grep -oE '[0-9]+')
[ "$d" -le 90 ] && [ "${m:-0}" -ge 8 ] && r=양호 || r=취약
chk U-02 패스워드정책 $r "MAX_DAYS=$d,minlen=${m:-X}"

# U-03 계정잠금
dy=$(grep -hE '^[[:space:]]*deny' /etc/security/faillock.conf 2>/dev/null|grep -oE '[0-9]+'|head -1)
[ -z "$dy" ] && dy=$(grep -rhE 'pam_faillock' /etc/pam.d/ 2>/dev/null|grep -vE '^[[:space:]]*#'|grep -oE 'deny=[0-9]+'|grep -oE '[0-9]+'|head -1)
[ -n "$dy" ] && [ "$dy" -le 10 ] && r=양호 || r=취약
chk U-03 계정잠금임계값 $r "deny=${dy:-미설정}"

# U-04 shadow 보호
b=$(awk -F: '$2!="x"&&$2!="*"&&$2!="!"{print $1}' /etc/passwd|tr '\n' ' ')
[ -z "$b" ] && chk U-04 패스워드파일보호 양호 "전계정 x" || chk U-04 패스워드파일보호 취약 "평문:$b"

# U-05 UID 0
u=$(awk -F: '$3==0{print $1}' /etc/passwd|tr '\n' ' ')
[ "$(echo $u)" = root ] && chk U-05 UID0제한 양호 "root" || chk U-05 UID0제한 취약 "$u"

# U-06 su 제한
grep -E pam_wheel /etc/pam.d/su 2>/dev/null|grep -qvE '^\s*#' && chk U-06 su사용제한 양호 "pam_wheel활성" || chk U-06 su사용제한 취약 "pam_wheel미설정"

echo -e "\n✔ 저장: $(pwd)/$CSV"
