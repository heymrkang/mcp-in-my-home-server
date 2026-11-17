# 2단계 — 긴 작업·Git·관리자 승인

기준 main: 3531dc4. 소스 구현 단계이며 설치·빌드·테스트·실제 MCP 연결·호스트 권한 변경은 아직 실행하지 않았다. 3단계가 설치/업데이트 명령과 사용자 서버 검증 단계다.

## 추가 도구

| 도구 | 기능 |
| --- | --- |
| task_start / task_status / task_list / task_cancel | 오프라인 빌드·테스트 등 긴 작업, 진행 상태·잘린 로그·결과 조회, 중단 |
| git_local | status/diff/log/add/commit/switch. 모든 작업은 동일한 일반 사용자 격리 안에서 실행 |
| admin_catalog | 관리자 설정에 등록한 컨테이너·서비스·외부 파일·통신 대상 조회 |
| admin_request / admin_status | 변경 불가능한 요청과 승인 URL 생성, 상태 조회 |
| admin_execute / admin_cancel | 승인한 요청을 한 번 실행하거나 취소 |

기존 workspace_status/files_list/files_read/files_write/files_mkdir/terminal_run도 유지한다. terminal_run은 짧은 전경 실행이고 연결 해제 시 취소한다. task_start는 사용자가 명시적으로 요청한 별도 작업으로 연결이 끊겨도 실행을 유지한다. 기본 작업 제한은 30분, 관리자 정책의 최대값은 기본 2시간이며 동시 실행 2개다. 상태 DB는 레포 밖에 있으며 서비스 재시작 시 미완료 작업을 UNKNOWN으로 기록하고 자동 재실행하지 않는다.

## 승인 경계

MCP gateway(home-mcp), 일반 실행기(home-mcp-runner), 승인 페이지(home-mcp-owner), root broker(root)를 분리했다. root broker는 UNIX peer UID로 요청자를 판별한다. MCP 계정은 요청/상태/실행/취소만 가능하고 owner_decide/owner_revoke는 호출할 수 없다. 일반 실행기는 broker 소켓과 승인 DB에 접근하지 않는다.

별도 `/approval/` 페이지에는 설치 시 생성한 승인 전용 비밀번호로 로그인한다. OAuth 연결 비밀번호와 별개이며 채팅/MCP로 전달하지 않는다. 승인·항상 허용·철회에는 비밀번호를 재입력한다. 브라우저 세션/CSRF/Origin/Host/요청 크기/시도 횟수를 제한하고, 요청·출력은 HTML escape로 표시한다. 외부 스크립트와 임의 링크를 삽입하지 않는다.

요청은 대상·명령·내용·정책 지문에 묶여 있으며 기본 10분 동안 대기, 승인 후 5분 안에 한 번만 시작할 수 있다. 같은 request_key는 같은 요청을 반환하고 내용이 다르면 거부한다. 실행을 시작한 요청은 실패·취소·UNKNOWN이라도 다시 실행하지 않는다. 새로 시도할 때는 실제 변경 여부를 먼저 확인해야 한다.

'항상 허용'은 (1) 정확히 등록된 파일 한 개를 일반 실행기 사용자 권한으로 쓰는 범위 또는 (2) 동일 명령·작업 폴더·통신 호스트·시간의 비관리자 네트워크 작업에만 제공한다. root 파일 변경·Docker·systemd 작업에는 제공하지 않는다. 허용 철회는 이후 및 미시작 자동승인을 차단하며 이미 적용된 변경을 되돌리지 않는다. root 셸이나 sudo 권한을 MCP 프로세스에 부여하는 기능은 없다.

## 관리자 작업

관리자 정책 `/etc/home-mcp/phase2.json`의 대상 목록은 기본 비어 있다. 임의의 컨테이너/서비스를 자동 등록하지 않는다. 컨테이너는 전체 64자리 ID로 고정하며 inspect(환경변수 제외)/최근 로그/start/stop/restart/remove를 지원한다. remove는 강제 삭제나 볼륨 삭제·prune를 하지 않는다. 서비스는 등록한 정확한 `.service`의 상태/start/stop/restart만 허용한다.

외부 파일은 정확한 경로를 등록한다. read 후 SHA256을 얻고 write 요청에 현재 해시와 새 내용을 넣는다. 파일은 64KiB 이하의 기존 일반 파일이어야 하며 링크/하드링크/특수파일을 거부한다. root 변경은 부모 경로와 파일도 root 소유이고 그룹/다른 사용자 쓰기가 없어야 한다. 비관리자 변경은 실제 Unix 권한도 있어야 하며 없다고 root로 승격하지 않는다. 설정/인증 DB/MCP 코드/SSH 개인키 등 예약 경로는 승인해도 대상에 넣을 수 없다. OS 전체에 임시 쓰기 권한을 푸는 것이 아니라 승인한 파일 동작만 별도 수행한다.

## Git·빌드의 인터넷 통신

일반 셸은 계속 오프라인이다. clone/fetch/push/의존성 설치 등은 `admin_request(action="network.run")`에 명령·cwd·timeout_seconds·hosts를 넣는다. 관리자 allowlist에 등록된 호스트만 지정하며 DNS 결과를 공인 IP로 검사해 요청에 고정한다. 승인된 작업은 별도 일반 사용자 systemd unit에서 실행한다.

그 unit에는 IPAddressDeny=any와 승인된 IP만 IPAddressAllow로 적용한다. **실제 해당 cgroup에 ingress/egress BPF 필터가 붙은 것을 bpftool로 확인한 뒤에만** 실행 gate를 연다. 지원하지 않는 커널/systemd 또는 bpftool 없음은 거부하며 호스트 인터넷으로 fallback하지 않는다. 일반 명령은 기존 bubblewrap 파일 제한을 유지한다. DNS는 고정 /etc/hosts, UNIX/netlink 소켓은 syscall filter로 차단한다.

이는 도메인/URL/443 포트만 허용하는 완전한 HTTP 프록시가 아니라 **공인 IP 허용 목록**이다. 같은 CDN IP의 다른 서비스나 다른 포트를 엄밀히 분리하지 않는다. 승인 화면에 이 차이와 데이터 전송 가능성을 표시한다. 새 의존성/리다이렉트 호스트가 필요하면 명시적으로 정책/요청을 확장해야 하며 자동 개방하지 않는다. 사설 IP/localhost/메타데이터 접근은 허용하지 않는다.

네트워크 작업은 admin_status로 상태 및 종료 결과를 조회한다. 현재 단계에서는 해당 작업의 중간 stdout 실시간 전달은 제공하지 않는다. 로컬 task_status 로그는 제한된 양을 실행 중 조회할 수 있다. 개인 GitHub 인증키·SSH 키를 호스트에서 자동 복사하거나 토큰을 요청 파라미터에 숨겨 넣지 않는다. 사설 저장소 인증은 3단계 설치 설계에서 별도 처리해야 한다.

## 포트·설치

외부 추가 포트 없음. 기존 HTTPS 443의 `/mcp` 등은 127.0.0.1:18790으로, `/approval/`은 127.0.0.1:18791로 연결한다. 둘 다 공유기 포워딩 금지. root broker는 TCP가 아닌 /run/home-mcp-broker.sock을 사용한다. Coolify가 80/443을 사용하면 예제 Caddy를 중복 기동하지 않는다.

새 서비스 계정, home-mcp-control 그룹(게이트웨이/승인 화면만), 상태 폴더 및 phase2.json이 필요하다. systemd 정의와 bootstrap_phase2.py는 포함하지만 실제 생성은 3단계 설치 명령에서 수행한다. 해당 계정/설정 없이 1단계 설치본에 파일만 덮어쓴 뒤 재시작하면 동작하지 않는다. **아직 수동 설치하지 않는다.**

## 사용자 검증 — 모두 미실행

| 확인 | 기대 |
| --- | --- |
| 긴 작업 시작 응답 유실·같은 key 재조회 | 같은 ID, 중복 실행 없음 |
| 연결 종료 후 task_status | 작업 유지, 제한된 로그/최종 결과 확인 |
| 대기·실행 중 취소/서비스 재시작 | 하위 프로세스 종료, 재시작은 UNKNOWN, 자동 재생 없음 |
| 소스·다른 경로 쓰기 및 소켓 접근 | 일반 실행에서 거부 |
| Git status/add/commit, 정상 빌드 | 비관리자 작업 공간에서만 실행 |
| 등록하지 않은 Docker/서비스/파일 | 승인 전 거부 |
| 거부·미승인·만료·다른 내용·중복 실행 | 관리 동작 시작 안 함 |
| 채팅에 '승인', confirmed=true, owner RPC 조작 | 관리자 권한 부여 안 됨 |
| 승인 페이지 로그인/CSRF/요청 HTML | 안전한 문자열 표시, 위조 결정 거부 |
| root 작업 항상 허용 요청 | 거부 |
| 비관리자 파일 특정 경로 반복 허용·철회 | 해당 범위만, 일반 Unix 권한 유지 |
| 외부 파일 해시 변화/링크 교체/하드링크 | 변경 거부, root fallback 없음 |
| 공인 IP 네트워크·로컬 주소·필터 없음 | 승인 IP만, 사설 접근 거부, 필터 미확인은 실행 안 함 |
| root broker 재시작 중 네트워크 작업 | 기존 소유 unit 정리, 결과 UNKNOWN |
| 도메인·80/443 기존 서비스 | 기존 라우팅 유지, 18790/18791 비공개 |

공식 설계 참조: https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html (IPAddressAllow/Deny 및 지원 조건), https://github.com/containers/bubblewrap (격리 옵션), https://modelcontextprotocol.io/specification/2025-06-18/server/tools (도구 annotations는 권한 강제가 아님). 문서 확인과 실행/보안 검증은 다르다.
