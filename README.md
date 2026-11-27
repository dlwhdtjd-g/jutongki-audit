# 주통기 기술적 취약점 진단 — Linux · Windows

KISA 『주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드』 기준으로 Rocky Linux·Windows Server를 스크립트로 자동 점검하고, 취약 항목을 조치한 뒤 재점검한 프로젝트입니다.

> EST 인프라보안 3차 프로젝트 · 자체 구축 랩(ESXi) · 2인 수행(리눅스 / 윈도우)

---

## 개요

| 항목 | 내용 |
|---|---|
| 점검 기준 | KISA 주통기 기술적 취약점 분석·평가 상세가이드 (Linux U-코드 / Windows W-코드) |
| 점검 대상 | Rocky Linux 10.2 (MASTER·SLAVE, keepalived+haproxy 이중화) · Windows Server 2022 |
| 점검 방식 | 스크립트 자동 점검 → 수동 검증(오탐 제외) → 조치 → 재점검 |
| 점검 범위 | 계정 / 파일·디렉터리 / 서비스 / 패치 / 로그 / (윈도우) 보안 관리 |

---

## 점검 결과

### Linux (Rocky Linux, 67개 항목)

| 분야 | 점검 | 양호 | 취약 | 해당없음 |
|---|---|---|---|---|
| 계정 관리 | 13 | 7 | 6 | 0 |
| 파일·디렉터리 관리 | 20 | 16 | 3 | 1 |
| 서비스 관리 | 30 | 19 | 6 | 5 |
| 패치 관리 *(수동)* | 1 | 0 | 1 | 0 |
| 로그 관리 | 3 | 3 | 0 | 0 |
| **합계** | **67** | **45** | **16** | **6** |

취약 16건 중 **14건 조치 완료**, 2건(U-28 호스트 방화벽 · U-64 패치)은 운영 리스크·아웃바운드 차단 환경을 고려해 **권고**. SLAVE 노드도 동일 기준 점검해 동일 결과 확인(이중화 일관성).

### Windows (Windows Server 2022, 64개 항목)

| 분야 | 점검 | 양호 | 취약 | 해당없음 |
|---|---|---|---|---|
| 계정 관리 | 14 | 6 | 7 | 1 |
| 서비스 관리 | 23 | 9 | 9 | 5 |
| 패치 관리 | 2 | 0 | 2 | 0 |
| 로그 관리 | 4 | 1 | 3 | 0 |
| 보안 관리 | 21 | 12 | 8 | 1 |
| **합계** | **64** | **28** | **29** | **7** |

취약 29건 중 **24건 조치 완료**, 5건(W-06 관리자 그룹 · W-27·W-38 패치 · W-39 백신 · W-41 시각 동기화)은 **권고**.

### 주요 조치 사례

| OS | 사례 |
|---|---|
| Linux | U-01 root 원격 접속 차단 · U-13 MD5(`$1$`)→yescrypt(`$y$`) 재해시 · U-40 NFS `root_squash` · U-52 평문 Telnet 비활성화 |
| Windows | W-01 Administrator 계정명 변경 · W-21 평문 FTP→SSL 강제 · W-16 공유 Everyone 권한 제거 · W-44 원격 레지스트리 비활성화 |

---

## 스크립트 구성

### 점검 (읽기 전용)

**Linux — Bash**

| 스크립트 | 점검 범위 |
|---|---|
| `scripts/linux/Account_check.sh` | 계정 관리 (U-01~U-06) |
| `scripts/linux/File_check.sh` | 파일·디렉터리 관리 (U-14~U-30) |
| `scripts/linux/Service_check.sh` | 서비스 관리 (U-34~U-63) |
| `scripts/linux/Rest_check.sh` | 잔여 항목 (계정 U-07~13 / 파일 U-28~33 / 로그 U-65~67) |

**Windows — PowerShell**

| 스크립트 | 점검 범위 |
|---|---|
| `scripts/windows/Check-A-Account.ps1` | 계정·로컬 보안 정책 (W-01~15, 47~57, 59, 60) |
| `scripts/windows/Check-B-File.ps1` | 공유·파일 권한 (W-16, 17, 23, 43, 46, 58, 61) |
| `scripts/windows/Check-C-Service.ps1` | 네트워크·서비스 (W-18~34, 36, 44, 64) |
| `scripts/windows/Check-D-System.ps1` | 패치·로그·시스템 (W-27, 35, 37~42, 45, 62, 63) |

### 조치 (Windows — PowerShell)

| 스크립트 | 내용 |
|---|---|
| `scripts/windows/Fix-1-Safe.ps1` | 서비스 영향이 작은 16개 항목 일괄 조치 (W-04·08·09·10·11·15·20·33·40·42·47·51·53·54·57·59). 변경 전 설정 자동 백업 |

> 패치 관리(U-64)는 방화벽 아웃바운드 차단으로 `dnf` 저장소 접근이 불가해 **수동 점검**(스크립트 미포함). Linux 자동 점검 스크립트는 66개 항목 대상이며, 합계 67은 수동 점검 1건 포함.

### 사용법

```bash
# Linux (sudo 권장) — 결과: /root/check/log/*.csv
sudo bash scripts/linux/Account_check.sh
```

```powershell
# Windows (관리자 PowerShell) — 결과: C:\check\log\*.csv
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Check-A-Account.ps1
# 조치 (변경 전 자동 백업)
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Fix-1-Safe.ps1
```

- 점검 1건을 `chk()`(Bash) / `Chk`(PowerShell) 헬퍼로 실행해 **양호·취약·수동확인·해당없음**을 자동 판정, CSV 저장.
- 점검 스크립트는 **읽기 전용**(설정 미변경) — 조치 전·후 2회 실행해 개선 효과 검증.
- 조치 스크립트는 변경 전 설정을 **자동 백업**(`C:\check\backup`).

---

## 오탐·수동확인 처리

자동 점검 결과를 수동 검증으로 보정했습니다.

**Linux 오탐 5건**

| 항목 | 오탐 | 처리 |
|---|---|---|
| U-15 | 소유자 없는 파일 = 컨테이너 레이어 | `containerd` 경로 제외 |
| U-24 | 심볼릭 링크 권한 | `-type f`로 링크 제외 |
| U-26 | `/dev/shm` 공유메모리 | 경로 제외 |
| U-42 | rpcbind = NFS 의존 서비스 | NFS 구동 시 양호 판별 |
| U-47 | 메일 relay 내부망 제한 | 실제 적용값(`postconf`) 기준 판별 |

**Windows**

- 수동확인(`$null`) 항목(W-03 불필요 계정, W-19 IIS 용도, W-37 예약 작업 등)은 서버 상황을 직접 검토해 판정.
- W-44(원격 레지스트리)는 중지 상태였으나 시작 유형이 '자동'이라 **재부팅 후 Running 확인 → 취약**으로 보정.

---

## 이중화(HA) 환경 고려

리눅스 대상 서버는 `keepalived(VRRP)` + `haproxy`로 이중화되어 있어, **서비스 중단·HA 통신 영향이 없는 설정 변경 위주**로 조치했습니다. U-28(호스트 방화벽)은 Docker iptables·NFS 동적 포트·VRRP 의존성을 식별해 **NFS 포트 고정 후 노드별 순차 적용**을 권고했습니다.

---

## 참고

- 점검 기준: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드
- 국제 기준 참고: CIS Benchmark
- 상세 점검·조치 내역은 별도 **진단 보고서**(전체 항목 + 조치 전/후 재점검 + 잔여 위험 관리 계획) 참조
