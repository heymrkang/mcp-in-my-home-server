# Home MCP

ChatGPT에서 개인 홈 서버의 파일·명령·Git·빌드·등록된 관리 작업을 다루는 MCP다. 별도 채팅 UI나 스케줄러를 만들지 않으며 기존 Agent Hub를 변경하지 않는다.

## 진행 상태

| 단계 | 상태 |
| --- | --- |
| 1. OAuth·파일·짧은 명령·격리 | 소스 반영 |
| 2. 긴 작업·Git·관리자 승인 | 소스 반영 |
| 3. 설치·업데이트·프록시 연결·검증 명령 | 소스 반영, 실제 서버 검증 대기 |

**설치 코드가 존재한다는 뜻이다. 실기기 설치, ChatGPT 연결, 보안 테스트 통과를 주장하지 않는다.**

## 설치

Linux/systemd, Python 3.11+, cgroup v2가 필요하다. Debian/Ubuntu 패키지 설치와 기존 Coolify Traefik 연결을 지원한다. rootful Docker가 아닌 환경이나 다른 프록시는 자동으로 바꾸지 않는다.

저장소를 처음 받을 때:

```bash
sudo mkdir -p /mnt/storage/dev
sudo git clone https://github.com/heymrkang/mcp-in-my-home-server.git /mnt/storage/dev/server
sudo bash /mnt/storage/dev/server/scripts/install.sh
```

이미 받았다면 `git pull --ff-only`로 최신 소스를 받은 뒤 같은 설치 명령을 실행한다. 설치 확인 질문에 yes를 입력한다. 패키지 설치 없이 준비된 호스트에 적용하려면 `--no-packages`를 붙인다.

설치 후:

```bash
sudo home-mcp status
sudo home-mcp verify --public
sudo home-mcp update
sudo home-mcp rollback
```

update는 기존 키·정책·DB·작업장을 유지하고 커밋된 새 실행본만 교체한다. rollback은 코드용이며 DB나 외부 변경을 되돌리지 않는다. 진행 작업이 있으면 먼저 끝낸다. 설치 절차·실패 복구·고급 옵션은 **docs/PHASE3.md**에 있다.

## 연결

모바일 원격 MCP 클라이언트는 선택적으로 별도 Bearer API 키로 인증할 수 있다. ChatGPT의 기존 OAuth는 유지된다. 설치 후 `sudo home-mcp api-key init`으로 생성하며, 원문은 `/var/lib/home-mcp/mobile-api-key.json`에 root 전용으로 보관한다. 모바일 앱 HTTP Header에 `Authorization=Bearer hmcp_...` 형식으로 입력한다. 기존에 발급한 OAuth 토큰과 Client ID/Secret은 변경하지 않는다. 외부 공개된 MCP이므로 키는 채팅이나 Git에 공유하지 않는다.

| 용도 | 주소/방식 |
| --- | --- |
| MCP | `https://k9m2x7p4vq3b8z1.12190529.xyz/mcp` |
| 별도 사용자 승인 | 같은 도메인의 `/approval/` |
| 외부 HTTPS | 기존 Coolify Traefik 443 유지 |
| 내부 HTTP | 호스트 `127.0.0.1:18790`, `127.0.0.1:18791` |
| 컨테이너 연결 | 비관리자 중계 컨테이너와 UNIX socket bridge |

18790/18791은 포트포워딩하지 않는다. 설치기는 DNS/공유기/기존 프록시 구성을 변경하지 않는다. 도메인이 기존 HTTPS 프록시로 연결돼 있어야 한다. 중계 컨테이너에는 공개 ports와 Docker socket을 주지 않는다. 기존 Coolify 앱을 삭제하거나 새 앱의 볼륨을 수동으로 만들 필요 없다.

최초 인증정보는 `/var/lib/home-mcp/setup-credentials.json`, 승인 비밀번호는 `/var/lib/home-mcp/phase2-setup-credentials.json`에 root 전용으로 생성한다. 원문은 Git·설치 로그·MCP 응답에 넣지 않는다. ChatGPT 연결 설정의 고정 OAuth client 항목에 client_id/client_secret을 입력하고 실제 OAuth 연결을 확인한다. 비밀번호·secret을 채팅에 붙이지 않는다.

## 도구와 권한

기본: workspace_status, files_list, files_read, files_write, files_mkdir, terminal_run.

확장: task_start, task_status, task_list, task_cancel, git_local, admin_catalog, admin_request, admin_status, admin_execute, admin_cancel.

일반 작업장은 `/mnt/storage/dev`이며 소스 폴더 `server`는 작업에서 보호한다. 일반 셸은 오프라인·비관리자다. 긴 작업은 ID로 조회하고 중단한다. 외부 파일·Docker·서비스·네트워크 작업은 등록된 범위와 별도 승인만 허용한다. 임의 root 셸이나 Docker socket을 AI 작업에 주지 않는다.

새 설치의 대상 목록은 비어 있다. 후보 정책을 로컬에서 편집하고 `sudo home-mcp policy /root/home-mcp-policy.json`으로 등록한다. 커널 BPF를 확인하지 못한 네트워크 작업은 실행하지 않는다. 개인 PAT/SSH 키를 일반 MCP 명령에 자동 전달하지 않으며, 무인 비공개 Git 원격 인증은 별도 미구현 범위다.

## 저장 위치

| 내용 | 위치 |
| --- | --- |
| 전달 checkout | `/mnt/storage/dev/server` |
| 실행본/venv/의존성 lock/중계 구성 | `/opt/home-mcp/releases/` |
| 현재 실행 포인터 | `/opt/home-mcp/app`, `/opt/home-mcp/venv` |
| 관리자 정책 | `/etc/home-mcp/config.json`, `/etc/home-mcp/phase2.json` |
| OAuth 상태 | `/var/lib/home-mcp/private` |
| 작업 기록 | `/var/lib/home-mcp-runner` |
| 승인·관리 실행 기록 | `/var/lib/home-mcp-broker` |
| 승인 비밀번호 해시 | `/var/lib/home-mcp-owner/private` |
| 임시 승인 네트워크 실행 | `/var/lib/home-mcp-network` |
| 설치 상태·이전 실행본 기록 | `/var/lib/home-mcp-installer` |

`.gitignore`를 만들지 않는다. 실제 비밀값·DB·로그·wheel·가상환경은 저장소 밖에 생성한다. 첫 설치에서 플랫폼별 의존성을 해석해 버전/해시를 기록하고 이후 재사용한다. 작성 시점에 실제 의존성 설치·빌드·테스트를 수행한 것은 아니다.

문서: docs/PHASE3.md(현재 설치 절차), docs/PHASE2.md(관리/승인 계약), docs/PHASE1.md, docs/SECURITY.md. 과거 단계의 '설치기 미구현' 표시는 PHASE3의 현재 상태로 대체한다.
