# Home MCP

ChatGPT에서 개인 홈 서버의 파일과 명령을 다룬다. 별도 채팅 UI·AI 계정 래퍼·스케줄러는 만들지 않는다.

## 현재: 1단계 소스 구현 완료

| 도구 | 기능 |
| --- | --- |
| workspace_status | 작업장·읽기 허용 경로·실행기 준비 상태 |
| files_list | 파일 목록 |
| files_read | 파일 읽기와 수정 전 해시 확인 |
| files_write | 파일 생성·명시적 덮어쓰기 |
| files_mkdir | 폴더 생성 |
| terminal_run | 제한된 환경에서 짧은 명령 실행 |

인증은 ChatGPT 연결용 OAuth이며, 명령 실행기는 로그인 정보를 가진 프로세스와 별도 계정이다. 기본 작업장은 `/mnt/storage/dev`다. 소스 폴더 `/mnt/storage/dev/server`는 실행 환경에서 가려져 수정할 수 없다. 다른 폴더는 관리자 설정의 읽기 허용 목록만 보여준다.

**아직 서버 설치·실계정 연결·실행 검증은 하지 않았다.** 1단계의 짧은 명령은 60초 이하이고 외부 네트워크·root·Docker 제어는 없다. 이 상태를 최종 운영 설치로 오해하지 않는다.

## 총 3단계

1. **완료(소스):** 본인 인증, MCP 연결, 작업장 보호, 파일·짧은 명령.
2. **예정:** Git/빌드의 통신 정책, 긴 작업 관리, Docker·서버 관리와 작업별 관리자 승인.
3. **예정:** 설치·업데이트 명령 한 개, 서비스 자동 시작, 실제 HTTPS 연결과 검증.

최종적으로 이 레포를 `/mnt/storage/dev/server`에 받은 뒤 설치 명령을 실행한다. 실제 서비스 코드는 관리자 소유 `/opt/home-mcp`에 복사한다. 레포가 없어져도 설치된 서비스는 그 복사본으로 동작한다. Git 삭제 이후에는 Git 업데이트만 불가능하다.

## 포트

| 포트 | 용도 |
| --- | --- |
| TCP 443 | 외부 HTTPS. 직접 연결이면 공유기 → 기존 HTTPS 프록시로 전달 |
| TCP 80 | 인증서/리다이렉트 방식에 따라 사용. 무조건 추가로 열지 않음 |
| 127.0.0.1:18790 | 내부 MCP. **포트포워딩하지 않음** |

목표 주소는 `https://k9m2x7p4vq3b8z1.12190529.xyz/mcp`다. 기존 Coolify가 443을 사용한다면 두 번째 프록시로 덮어쓰지 않는다. 현재 도메인의 실제 연결 방식은 아직 확인하지 않았다. 자세한 기준은 `docs/NETWORK.md`에 있다.

## 저장 위치

- 소스: `/mnt/storage/dev/server`
- 실행 코드·가상환경: `/opt/home-mcp`
- 관리자 정책: `/etc/home-mcp/config.json`
- 실제 인증 DB·비밀번호 해시: `/var/lib/home-mcp/private`
- 최초 연결 정보: `/var/lib/home-mcp/setup-credentials.json` (root 전용, 안전하게 보관 후 삭제)
- 실행 이력: systemd journal. 명령 본문·파일 내용·비밀번호·토큰은 감사 로그에 기록하지 않는다.

`.gitignore`는 만들지 않는다. 실제 비밀값, DB, 로그, 설치된 의존성은 애초에 레포 안에 생성하지 않는다. `requirements.txt`와 소스는 포함하지만 가상환경/배포판 바이너리를 Git에 넣는 구조는 아니다.

## 구현 문서

- `docs/PHASE1.md`: 범위, 인증 연결, 검증 항목과 미실행 상태
- `docs/SECURITY.md`: 격리 경계와 주의사항
- `docs/NETWORK.md`: 포트·프록시
- `deploy/`: 자동 시작·프록시 정의. 아직 자동 설치 프로그램은 아님
- `scripts/preflight.sh`: 변경 없는 사전 환경 조회
- `tests/test_phase1.py`: 오프라인 검증 코드. 실행 결과는 아직 없음

현재 소스 기준은 Linux/systemd, Python 3.11+, bubblewrap의 `--disable-userns` 지원, libseccomp다. 해당 격리가 불가능하면 일반 호스트 셸로 대체하지 않고 실행을 거부한다.
