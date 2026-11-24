#!/bin/bash
# 주통기 서비스 관리 점검 U-34~U-63 | 읽기전용 | sudo 실행 권장
G="\e[32m"; R="\e[31m"; Y="\e[33m"; N="\e[0m"
mkdir -p /root/check/log; CSV="/root/check/log/result_service_$(date +%y%m%d_%H%M).csv"
printf '\xEF\xBB\xBF코드,항목,결과,근거\n' > "$CSV"
chk(){ case "$3" in 양호)col=$G;; 해당없음|수동확인)col=$Y;; *)col=$R;; esac
  echo -e "  ${col}[$3]${N} $1 $2 ($4)"; echo "$1,$2,$3,\"$4\"">>"$CSV"; }
act(){ systemctl is-active --quiet "$1" 2>/dev/null; }
lis(){ ss -tuln 2>/dev/null|grep -qE "[:.]$1[[:space:]]"; }

echo -e "■ 서비스 관리 점검 $(hostname) $(date '+%F %T')"

# 불필요 서비스: 미구동이면 양호 (p=포트 / s=유닛)
while read code name t val; do
  if [ "$t" = p ]; then lis $val && chk $code $name 취약 "포트 $val LISTEN" || chk $code $name 양호 "포트 $val 미사용"
  else act $val && chk $code $name 취약 "$val 구동중" || chk $code $name 양호 "$val 미구동"; fi
done <<'EOF'
U-34 Finger비활성 p 79
U-36 r계열비활성 p 513
U-41 automountd제거 s autofs
U-43 NIS점검 s ypserv
U-44 tftp_talk비활성 p 69
U-52 Telnet비활성 p 23
EOF

# 개별 점검
p=$(stat -c %a /etc/crontab 2>/dev/null); { [ -n "$p" ]&&[ "$p" -le 640 ]; }&&chk U-37 crontab권한 양호 "$p"||chk U-37 crontab권한 취약 "${p:-없음}(640이하)"
d=""; for pt in 7 9 13 19; do lis $pt&&d="$d $pt"; done; [ -z "$d" ]&&chk U-38 DoS서비스 양호 "미사용"||chk U-38 DoS서비스 취약 "$d"
act smb&&{ grep -qiE 'guest ok *= *yes|map to guest' /etc/samba/smb.conf 2>/dev/null&&chk U-35 공유익명접근 취약 "guest허용"||chk U-35 공유익명접근 양호 "guest비허용"; }||chk U-35 공유익명접근 해당없음 "samba미구동"
act nfs-server&&chk U-39 NFS서비스 수동확인 "구동중-필요시양호"||chk U-39 NFS서비스 양호 "미구동"
act rpcbind&&{ act nfs-server&&chk U-42 RPC서비스 양호 "rpcbind(NFS의존)"||chk U-42 RPC서비스 취약 "rpcbind단독구동"; }||chk U-42 RPC서비스 양호 "rpcbind미구동"
[ -s /etc/exports ]&&{ grep -qE '\*|no_root_squash' /etc/exports&&chk U-40 NFS접근통제 취약 "*/no_root_squash"||chk U-40 NFS접근통제 양호 "호스트제한"; }||chk U-40 NFS접근통제 해당없음 "exports없음"

# 메일(postfix)
if act postfix; then
  chk U-45 메일버전 수동확인 "$(postconf mail_version 2>/dev/null|awk '{print $3}') 패치확인"
  chk U-46 메일사용자실행제한 수동확인 "권한확인"
  postconf -h smtpd_relay_restrictions 2>/dev/null|grep -qE 'unauth'&&chk U-47 스팸릴레이제한 양호 "설정됨"||chk U-47 스팸릴레이제한 취약 "미설정"
  grep -qE '^disable_vrfy_command *= *yes' /etc/postfix/main.cf 2>/dev/null&&chk U-48 vrfy제한 양호 "disable"||chk U-48 vrfy제한 취약 "미제한"
else for c in "U-45 메일버전" "U-46 메일실행제한" "U-47 스팸릴레이" "U-48 vrfy제한"; do chk ${c% *} ${c#* } 해당없음 "메일미구동"; done; fi

# DNS(named)
if act named; then
  chk U-49 DNS버전 수동확인 "패치확인"
  grep -qi 'allow-transfer' /etc/named.conf 2>/dev/null&&chk U-50 ZoneTransfer 양호 "제한설정"||chk U-50 ZoneTransfer 취약 "미설정"
  grep -qiE 'allow-update *\{ *none' /etc/named.conf 2>/dev/null&&chk U-51 동적업데이트 양호 "none"||chk U-51 동적업데이트 수동확인 "설정확인"
else for c in "U-49 DNS버전" "U-50 ZoneTransfer" "U-51 동적업데이트"; do chk ${c% *} ${c#* } 해당없음 "DNS미구동"; done; fi

# FTP(21)
lis 21&&{ st=수동확인; m=구동-설정확인; }||{ st=해당없음; m=미구동; }
for c in "U-53 FTP정보노출" "U-54 평문FTP" "U-55 FTP계정Shell" "U-56 FTP접근제어" "U-57 Ftpusers"; do chk ${c% *} ${c#* } $st "$m"; done

# SNMP
if act snmpd; then
  chk U-58 SNMP구동 취약 "구동중"; chk U-59 SNMP버전 수동확인 "v3확인"
  grep -qiE '^com2sec.*(public|private)' /etc/snmp/snmpd.conf 2>/dev/null&&chk U-60 SNMPCommunity 취약 "기본community"||chk U-60 SNMPCommunity 수동확인 "확인"
  chk U-61 SNMPAccessControl 수동확인 "ACL확인"
else for c in "U-58 SNMP구동" "U-59 SNMP버전" "U-60 SNMPCommunity" "U-61 SNMPACL"; do chk ${c% *} ${c#* } 양호 "미구동"; done; fi

# U-62 경고메시지 / U-63 sudo
{ [ -s /etc/issue ]||[ -s /etc/motd ]; }&&chk U-62 경고메시지 양호 "설정됨"||chk U-62 경고메시지 취약 "미설정"
[ -s /etc/sudoers ]&&chk U-63 sudo접근관리 수동확인 "sudoers검토"||chk U-63 sudo접근관리 취약 "없음"

echo -e "\n✔ 저장: $CSV"
echo -e "${Y}※ 수동확인 항목은 설정 파일을 직접 검토해 판정${N}"
