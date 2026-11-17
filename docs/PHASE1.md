# 1단계 인계

2026-11-17 작성. 비어 있던 main에 개인용 MCP 기반을 추가했다. Agent Hub Core와 n8n에는 변경하지 않았다.

## 작성한 범위

Python 공식 MCP SDK 1.30.0을 고정해 Streamable HTTP /mcp를 제공한다. SDK의 인증 검사와 protected-resource discovery를 사용하고, 같은 개인 서버에 고정 클라이언트용 OAuth 승인/토큰/폐기 경로를 추가했다. 인증 없는 MCP 호출은 허용하지 않는다.

도구는 workspace_status, files_list, files_read, files_write, files_mkdir, terminal_run 여섯 개다. 실제 실행은 socket-activated 일반 사용자 서비스로 분리한다. 파일/명령은 동일한 OS 샌드박스를 통과한다. 셸이 강제로 root로 실행되거나 격리 실패 후 호스트에서 재실행되는 경로는 없다.

root 작업 승인, Docker/서비스 관리, 긴 작업 ID/큐/취소, 네트워크가 필요한 Git/빌드 기능은 2단계다. 최종 install/update 명령과 프록시 실환경 연결은 3단계다. 따라서 지금 deploy의 unit 정의를 그대로 설치해 운영하는 것을 완료로 취급하지 않는다.

## 3단계 설치에서 반드시 처리할 사항

1. 실제 OS/Python/systemd/bubblewrap/사용자 네임스페이스/AppArmor 지원을 확인한다. 격리 정책을 전역으로 끄는 방식으로 문제를 숨기지 않는다.
2. home-mcp와 home-mcp-runner를 서로 다른 비로그인 사용자로 만들고, runner에는 docker/sudo/adm 같은 추가 그룹을 주지 않는다.
3. /opt/home-mcp/app·empty·venv와 /etc/home-mcp/config.json은 root 소유, 일반 사용자 쓰기 불가로 설치한다. 작업장에 실행기 쓰기 권한을 주되 기존 다른 서비스 소유권을 무작정 chown -R/777로 바꾸지 않는다.
4. 작업장의 중첩 마운트·하드링크·외부 공유 쓰기 경로를 점검한다. source_checkout은 심볼릭 링크 없이 실제 디렉토리여야 한다.
5. 최초에만 bootstrap을 실행한다. 재설치로 인증 DB를 지우거나 암호를 바꾸지 않는다. 최초 원문 정보는 root 터미널로만 확인하고 안전한 보관 후 제거한다.
6. 기존 443 프록시 배치를 확인해 /mcp, /oauth/*, /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource*를 연결한다. 기존 도메인의 다른 기능은 보존한다.
7. ChatGPT 연결에 설치 시 발급한 client_id/client_secret을 사용한다. OpenAI API 키는 필요 없다. 콜백은 실제 연결 화면에서 나온 URI와 config 허용 목록을 대조한다. 인증 정보를 이 채팅이나 Git에 보내지 않는다.

## 검증 상태

코드 작성과 Git 반영 확인만 수행했다. 의존성 설치, Python 실행/단위 테스트, 실제 namespace 격리, HTTP/OAuth 교환, ChatGPT 연결, 사용자 홈 서버 명령·파일 수정, 포트 개방은 수행하지 않았다. tests/test_phase1.py는 검증 코드의 추가이지 통과 결과가 아니다.

오프라인 테스트를 실행할 때는 레포에 캐시를 만들지 않는다:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
```

위 명령은 표준 라이브러리 테스트만 수행한다. 실제 설치/서비스 가동 명령은 3단계에서 완성한다.

| 실제 서버 확인 | 기대 결과 | 현재 |
| --- | --- | --- |
| /health | phase 1 alive 응답; 전체 검증 성공 표시 아님 | 미실행 |
| 무토큰 /mcp | 401와 인증 메타데이터 안내 | 미실행 |
| OAuth 연결/교환/갱신/폐기 | 본인 인증, S256, resource·issuer 일치, 재사용 차단 | 미실행 |
| 잘못된 콜백/Origin/과대한 본문 | 요청 거부 | 미실행 |
| workspace_status | 경로와 제한 표시, root false | 미실행 |
| 새 파일 → 읽기 → 정확한 해시로 수정 | 작업장 안에서 수행 | 미실행 |
| 틀린 해시/링크/작업장 밖 쓰기 | 거부 | 미실행 |
| 서버 소스·비밀 파일·Docker 소켓 접근 | 차단 | 미실행 |
| 터미널에서 절대경로·링크로 /etc 쓰기 | OS 경계에서 차단 | 미실행 |
| 터미널의 TCP/UNIX socket 연결 | 차단 | 미실행 |
| sudo/setuid/추가 namespace 생성 | 차단 | 미실행 |
| 명령 시간 초과/연결 취소 | 종료; 이미 적용된 변경은 별도 확인 | 미실행 |
| bwrap/seccomp/namespace 지원 불가 | 실행기 시작 실패, 호스트 셸 fallback 없음 | 미실행 |
| 재부팅 | socket + gateway 자동 시작, 인증 상태 유지 | 3단계 |

## 제한과 후속 작업

이 단계의 60초는 짧은 실행 도구의 상한이다. 장기 빌드/배포는 2단계의 작업 관리 도구로 분리한다. 외부 네트워크를 단순히 켜면 로컬/사설 관리 API에 접근해 파일 정책을 우회할 수 있으므로 명시적으로 설계해야 한다. 임의 root 셸과 docker.sock 직접 노출은 추가하지 않는다.

requirements.txt는 공식 SDK 직접 버전만 고정했다. 하위 의존성 전체 해시 잠금은 아직 아니므로 3단계의 실제 플랫폼 패키징에서 해결한다. OS 런타임 및 bubblewrap/libseccomp 바이너리는 Git에 복사하지 않는다.
