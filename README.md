# Home MCP

ChatGPT에서 홈 서버의 파일·명령·Git·빌드·컨테이너·서비스를 다루는 개인용 MCP다. 새 채팅 UI와 스케줄러는 만들지 않는다.

## 진행 상태

| 단계 | 상태 |
| --- | --- |
| 1. 인증·기본 파일·짧은 명령·작업 공간 격리 | 소스 반영 |
| 2. 긴 작업·Git·관리 작업·별도 승인 | 소스 반영 |
| 3. 설치/업데이트 명령·도메인 연결·실제 검증 | 남음 |

**현재는 설치·실행·보안 테스트 미검증 상태다. 3단계 전에는 서비스 파일을 수동으로 적용하지 않는다.**

## 사용 방식

- 기본 작업장 `/mnt/storage/dev`는 일반 작업의 쓰기 범위다. 소스 전달 폴더 `/mnt/storage/dev/server`는 보호한다.
- 파일/짧은 명령은 직접 호출하고 긴 빌드/테스트는 작업 번호로 상태·로그·결과를 조회한다.
- 외부 경로 변경·Docker·서비스·네트워크 작업은 등록된 대상에만 별도 승인 요청을 만든다.
- 승인 페이지에서 허용/거부를 결정한다. 제한된 비관리자 범위만 항상 허용할 수 있으며 root는 작업별 승인이다.
- `.gitignore` 없이 소스·예제·설치 정의만 Git에 넣는다. 실제 암호·토큰·로그·DB·설치 의존성은 레포 밖에 둔다.

## 주소·포트

| 용도 | 연결 |
| --- | --- |
| MCP | `https://k9m2x7p4vq3b8z1.12190529.xyz/mcp` → `127.0.0.1:18790` |
| 승인 화면 | 같은 도메인의 `/approval/` → `127.0.0.1:18791` |
| 외부 포워딩 | TCP 443 → 기존 HTTPS 프록시. 80은 인증서 방식에 따라 판단 |
| 내부 포트 | **18790·18791은 포트포워딩하지 않는다** |

현재 프록시가 Coolify 컨테이너인지 호스트 프로세스인지는 아직 검증하지 않았다. 예제 Caddy를 기존 프록시와 함께 띄우지 않는다.

## 도구

기존: workspace_status, files_list, files_read, files_write, files_mkdir, terminal_run.

2단계: task_start, task_status, task_list, task_cancel, git_local, admin_catalog, admin_request, admin_status, admin_execute, admin_cancel.

관리 도구는 요청만으로 root를 열지 않는다. 다른 UID의 승인 웹 서비스와 root broker가 결정한다. 기본 관리 대상 목록은 비어 있으며 3단계에서 등록/설치 절차를 제공한다. 임의 root 셸은 제공하지 않는다.

일반 셸은 오프라인이다. 승인된 네트워크 작업은 공인 IP 제한을 실제 커널에서 확인한 뒤 실행한다. 이 기능에는 cgroup v2/BPF 지원과 bpftool이 필요하다. unsupported 환경에서 제한을 없애는 fallback은 없다.

## 위치

| 내용 | 위치 |
| --- | --- |
| 전달용 소스 | `/mnt/storage/dev/server` |
| 관리자 소유 실행본·Python 환경 | `/opt/home-mcp` |
| 관리자 정책 | `/etc/home-mcp/config.json`, `/etc/home-mcp/phase2.json` |
| OAuth 인증 상태 | `/var/lib/home-mcp/private` |
| 일반 작업 기록 | `/var/lib/home-mcp-runner` |
| 승인·관리 실행 기록 | `/var/lib/home-mcp-broker` |
| 승인 전용 비밀번호 해시 | `/var/lib/home-mcp-owner/private` |
| 임시 승인 네트워크 작업 설정 | `/var/lib/home-mcp-network` |

상세: `docs/PHASE2.md`, `docs/SECURITY.md`, `docs/NETWORK.md`. `docs/PHASE1.md`는 1단계 당시 범위이며 추가 기능은 PHASE2 문서가 우선한다. 단위 검증 코드도 포함하지만 아직 실행하지 않았다.
