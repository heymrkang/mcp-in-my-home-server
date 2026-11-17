# 3단계 — 설치·업데이트·기존 HTTPS 연결

2026-11-18. 기준 main: 229aa31. 이번 변경은 설치 코드·안내·검증 명령의 구현이다. 작성자가 사용자 홈 서버에 접속해 설치/배포하거나 테스트를 실행한 결과가 아니다. 실제 설치·ChatGPT 연결·재부팅·보안 검증은 아래 절차를 사용자가 실행한 결과로만 기록한다.

## 지원 환경과 변경 범위

Linux, systemd, Python 3.11 이상, cgroup v2가 필요하다. 자동 패키지 설치는 Debian/Ubuntu를 대상으로 한다. 다른 배포판은 해당 패키지를 직접 설치하고 --no-packages를 사용해야 하며 그 환경의 동작을 보장하지 않는다. bubblewrap에는 --disable-userns와 --assert-userns-disabled가 있어야 한다. AppArmor/커널이 사용자 namespace를 막으면 설치가 실패한다. 전역 보안 정책을 끄거나 일반 호스트 셸로 fallback하지 않는다.

기본 연결은 실행 중인 Coolify Traefik과 rootful Docker를 사용한다. Docker 사용자 namespace remapping/rootless, Caddy 컨테이너, 프록시를 파일 설정만으로 관리하는 경우에는 자동 연결을 거부한다. 프록시 종류·entrypoint·인증서 resolver를 추측해서 바꾸지 않는다. --proxy host는 호스트 프록시용 예제만 생성하며 그 예제를 기존 프록시에 반영하는 작업은 별도다.

설치기는 Home MCP 사용자 4개, 제어 그룹, /opt/home-mcp, /etc/home-mcp, /var/lib/home-mcp 계열, Home MCP systemd 파일, /usr/local/sbin/home-mcp를 관리한다. 작업장 루트에 home-mcp-runner 쓰기 ACL만 부여한다. 기존 프로젝트 전체의 소유권을 재귀 변경하지 않는다. 이미 있는 프로젝트의 별도 Unix 권한이 필요하면 관리자가 그 프로젝트 범위만 명시적으로 설정한다.

기존 Coolify 80/443 프록시를 재시작하거나 설정 파일을 덮어쓰지 않는다. Agent Hub 경로/서비스/DB는 건드리지 않는다. 서버 방화벽·공유기·DNS도 자동 변경하지 않는다. apt 패키지 설치/외부 다운로드는 초기 설치 명령을 실행한 관리자의 작업이며 일반 MCP 명령에 네트워크를 허용하는 것이 아니다.

## 최초 설치

먼저 이 저장소의 최신 main을 /mnt/storage/dev/server에 받는다. 이미 그 위치에 다른 내용이 있다면 지우지 말고 확인한다. 비공개 저장소인 경우 GitHub 인증은 로컬 터미널에서만 처리하며 토큰을 URL·채팅·MCP 요청·커밋에 넣지 않는다.

```bash
sudo mkdir -p /mnt/storage/dev
sudo git clone https://github.com/heymrkang/mcp-in-my-home-server.git /mnt/storage/dev/server
sudo bash /mnt/storage/dev/server/scripts/install.sh
```

이미 받아 둔 저장소라면 clone 대신 해당 저장소를 갱신한다. reset --hard나 파일 삭제는 하지 않는다.

```bash
sudo git -c safe.directory=/mnt/storage/dev/server -C /mnt/storage/dev/server pull --ff-only
sudo bash /mnt/storage/dev/server/scripts/install.sh
```

설치 전 확인에서 yes를 입력한다. 기본 주소는 https://k9m2x7p4vq3b8z1.12190529.xyz 이다. 도메인은 네 서버의 기존 HTTPS 프록시까지 도달해야 한다. 이 레포의 설치기를 실행한다고 DNS가 자동 생성되지는 않는다.

자동 탐지가 모호하면 실제 기존 프록시 값만 명시한다. 다음은 Coolify 기본 이름을 사용하는 구성의 예시이며 서버에서 확인된 값이 아니다.

```bash
sudo bash /mnt/storage/dev/server/scripts/install.sh \
  --proxy-container coolify-proxy --network coolify \
  --https-entrypoint https --tls-resolver letsencrypt
```

이미 domain을 다른 Coolify 앱에 지정했다면 충돌을 알리고 중단한다. 그 domain 연결만 관리자가 먼저 정리한다. 기존 앱·볼륨을 삭제할 필요는 없다. --tls-resolver none은 이미 유효한 기본 인증서가 있는 경우에만 사용한다.

## 실제 연결 구조

외부 HTTPS 443은 기존 Traefik이 받는다. 설치기가 추가한 home-mcp-edge는 기존 프록시 network에 붙는 비관리자 NGINX 중계 컨테이너다. 이 컨테이너에는 공개 ports, Docker socket, 호스트 데이터, 인증 DB를 마운트하지 않는다.

중계는 /run/home-mcp-http/gateway.sock와 owner.sock만 이용한다. systemd-socket-proxyd가 각각 호스트 127.0.0.1:18790과 127.0.0.1:18791로 전달한다. 컨테이너의 localhost를 호스트 localhost로 착각하는 구성을 쓰지 않는다. /approval/만 승인 웹으로 전달하고 /mcp 및 OAuth·메타데이터 경로는 게이트웨이로 전달한다. /approval 접두사를 제거하지 않는다. **18790/18791을 공유기에 포워딩하지 않는다.**

중계 이미지는 첫 설치 시 공식 nginxinc/nginx-unprivileged:stable을 가져와 실제 RepoDigest를 기록한다. 이후 재시작/업데이트는 그 digest를 사용한다. 별도 Coolify 앱을 만들거나 Persistent Storage를 추가하지 않는다. 중계의 운영 주체는 이 설치기이며, Coolify 프록시의 라벨 감지만 이용한다. Coolify UI에서 별도 앱 리소스로 표시된다고 보장하지 않는다.

## 인증정보와 연결

설치기는 기존 OAuth/승인 비밀번호를 갱신하지 않는다. 최초 생성 시 root만 읽는 아래 파일에 기록한다.

```bash
sudo cat /var/lib/home-mcp/setup-credentials.json
sudo cat /var/lib/home-mcp/phase2-setup-credentials.json
```

첫 파일의 client_id/client_secret은 ChatGPT의 직접 등록 OAuth 클라이언트 입력에 사용한다. owner_password는 이 MCP의 OAuth 동의 화면에서만 입력한다. 둘째 파일의 approval_password는 /approval/에서만 입력한다. ChatGPT 채팅이나 모델 도구 인자에 비밀번호/secret을 보내지 않는다. 비밀번호 관리 도구에 보관한 뒤 초기 원문 파일을 삭제할 수 있지만 private/owner.json이나 인증 DB를 지우면 안 된다.

MCP 주소: https://k9m2x7p4vq3b8z1.12190529.xyz/mcp

ChatGPT에서 제공되는 사용자 MCP 연결 화면에 이 주소를 등록하고 OAuth를 선택한다. 고정 클라이언트를 사용하므로 client_id/client_secret을 연결 설정에 입력한다. 서버의 기본 허용 redirect는 https://chatgpt.com/connector_platform_oauth_redirect 이다. 실제 연결 화면에 표시되는 정확한 redirect가 다르면 /etc/home-mcp/config.json의 oauth_redirect_uris를 관리자 권한으로 수정하고 home-mcp.service만 재시작해야 한다. 와일드카드 redirect를 추가하지 않는다. 서비스·메타데이터 점검 통과와 실제 ChatGPT 인증/도구 호출 성공은 별개다.

## 업데이트·코드 롤백

```bash
sudo home-mcp update
sudo home-mcp status
sudo home-mcp verify --public
```

update는 지정 저장소의 main을 fetch하고 커밋 스냅샷을 새 release 디렉토리에 준비한다. 원래 checkout의 작업 파일을 reset/clean하지 않는다. 따라서 checkout의 HEAD가 설치 커밋과 다를 수 있다. 실제 실행 커밋은 home-mcp status로 확인한다. 소스에 로컬 수정이 있어도 설치에는 커밋된 내용만 포함한다.

현재 Python 플랫폼에 필요한 wheel을 첫 설치 때 해석하고 모든 distribution/version/SHA256을 lock으로 기록한다. 업데이트는 기존 wheel/lock을 검증해 재사용한다. 첫 설치의 하위 의존성 해석 자체를 레포에 미리 검증한 공통 lock이라고 주장하지 않는다. wheel만 허용하며 source distribution 빌드를 실행하지 않는다. Python minor/platform이나 requirements가 바뀌면 새 해석을 명시적으로 허용해야 한다.

```bash
sudo home-mcp update --refresh-dependencies --refresh-image
```

이 명령은 의존성과 중계 이미지도 다시 선택하는 명시적 업데이트다. 일반 업데이트에는 필요 없다. OS 패키지의 완전한 재현성이나 모든 버전 조합의 검증을 보장하지 않는다.

새 실행본과 의존성 준비를 끝낸 다음 Home MCP만 정지해 app/venv 포인터와 해당 unit 파일을 바꾼다. 기존 DB·키·정책·작업장은 보존한다. 기동/로컬 점검/중계 시작 실패 시 이전 코드로 돌아가는 경로가 있다. 실행 중 작업은 중단되거나 UNKNOWN으로 남을 수 있고 외부에서 발생한 변경은 취소되지 않는다. 업데이트 전에 작업을 끝내는 것이 원칙이다. 승인 전용 웹 세션처럼 메모리에 있던 상태는 재로그인이 필요하다.

```bash
sudo home-mcp rollback
```

롤백은 코드·unit·중계 설정만 대상으로 하며 DB를 이전 스냅샷으로 덮어쓰지 않는다. 중간에 전원이 꺼졌으면 pending 기록이 남아 다음 설치를 차단한다. rollback으로 정리한 뒤 재시도한다. 첫 설치라 이전 코드가 없으면 Home MCP를 중지하고 boot activation을 끈 채 인증정보·정책은 보존한다. 명령 래퍼를 아직 만들기 전이면 아래 경로로 실행한다.

```bash
sudo python3 -B /mnt/storage/dev/server/scripts/manage.py rollback
```

이전 release/의존성 파일을 자동 삭제하지 않는다. 장기간 운영 후 정리할 때 current/previous 및 재사용 dependency_bundle을 제외해야 한다.

## 관리 대상 등록

새 설치는 컨테이너·서비스·외부 파일·통신 호스트를 모두 빈 목록으로 시작한다. 예제에 있는 GitHub/npm/PyPI 도메인을 설치만으로 자동 허용하지 않는다.

```bash
sudo cp /etc/home-mcp/phase2.json /root/home-mcp-policy.json
sudo nano /root/home-mcp-policy.json
sudo home-mcp policy /root/home-mcp-policy.json
```

후보 파일은 root 소유의 안전한 경로에 둔다. 등록 schema는 config/phase2.example.json 및 docs/PHASE2.md를 따른다. 컨테이너는 전체 64자리 ID, 서비스는 정확한 .service 이름, 파일은 정확한 경로, 통신은 개별 호스트명이다. policy 명령은 검증 뒤 Home MCP만 재시작하며 대상 작업은 실행하지 않는다. 승인 포트 변경은 이 명령에서 거부한다. 자체 서비스·Coolify·Agent Hub 컨테이너는 관리 대상으로 넣지 않는다.

일반 셸은 오프라인이다. 인터넷이 필요한 작업은 허용 호스트 등록 및 사용자 승인을 거친 network.run으로 요청한다. bpftool/커널 BPF 검증이 안 되면 실행을 거부하며 이를 설치 성공으로 숨기지 않는다.

### 비공개 Git에 대한 경계

이 단계는 설치/업데이트를 위한 로컬 Git 인증을 지원하지만 개인 PAT·SSH 키를 임의 MCP 명령에 주입하지 않는다. 일반 MCP의 무인 비공개 clone/fetch/push용 자격 증명 broker는 구현하지 않았다. 필요한 비공개 레포는 관리자가 로컬 터미널에서 인증해 작업장에 준비하고, MCP는 준비한 파일/로컬 Git/빌드를 처리한다. 원격 private Git 인증 자동화를 원하면 정확한 레포·동작에 묶인 별도 구현이 필요하다. 기존 호스트 ~/.ssh나 credential.helper 파일을 읽기 허용 목록에 넣는 것으로 우회하지 않는다.

## 검증 명령과 기록

설치 명령이 실행되면 서비스 active, loopback-only listener, 로컬 health/OAuth metadata/401 경계, 승인 페이지, 일반 실행기 IPC와 기존 sandbox startup probe를 점검한다. 파일 쓰기·root 관리 작업·유료 API·실제 ChatGPT 로그인을 자동으로 수행하지 않는다.

```bash
sudo home-mcp verify --public
```

이 명령은 추가로 공개 TLS/도메인/OAuth·승인 경로를 확인한다. TLS 검증을 끄지 않으며 인증정보를 읽어 보내지 않는다. 결과에 실제 수행하지 않은 ChatGPT pairing/승인/네트워크 작업/재부팅은 NOT_RUN으로 표시한다. 홈 서버 안에서 수행한 공개 주소 조회이므로 NAT hairpin/DNS 환경에 따라 외부 기기에서는 되는 주소가 내부에서 실패할 수도 있다. 외부 모바일망 확인도 별도로 한다.

| 확인 | 기대 결과 | 현재 기록 |
| --- | --- | --- |
| 최초 install | 역할별 계정/권한/서비스 기동, root-only 최초 인증정보 | 미실행 |
| 기존 Coolify/Agent Hub | 기존 도메인과 컨테이너 유지 | 미실행 |
| public verify | TLS·health·OAuth metadata·인증 없는 MCP 401 | 미실행 |
| ChatGPT OAuth 연결 | 정확한 issuer/redirect/PKCE, 실제 도구 목록 표시 | 미실행 |
| files/terminal/task | 작업장 안에서 실행, source/특수파일/호스트 socket 거부 | 미실행 |
| owner 승인·거부·만료 | 별도 웹 비밀번호, 미승인·중복 관리자 실행 거부 | 미실행 |
| network.run | 승인된 공인 IP 필터 확인, 필터 없으면 실행 거부 | 미실행 |
| update/실패 rollback | DB·정책·인증정보 보존, 진행 작업 자동 재생 없음 | 미실행 |
| 재부팅 | socket/service/relay 복귀, OAuth·승인 페이지 접근 | 미실행 |
| dependency/이미지 재사용 | 같은 wheel hashes/registry digest 사용 | 미실행 |

오프라인 테스트 소스: tests/test_installer.py. 실행 여부와 실제 호스트 검증을 혼동하지 않는다.

## 실패 시

로그는 우선 해당 Home MCP unit만 조회한다. 토큰·비밀번호·연결 코드가 있으면 공유 전에 제거한다.

```bash
sudo journalctl -u home-mcp -u home-mcp-runner -u home-mcp-broker -u home-mcp-owner --since '-10 min' --no-pager
```

AppArmor/namespace 오류는 격리 정책을 제거해서 숨기지 않는다. BPF 미지원은 일반 셸에 인터넷을 열어 해결하지 않는다. 초기 credentials 파일만 만들어지고 owner hash 생성 전 중단된 경우 bootstrap은 덮어쓰지 않고 거부한다. 해당 두 파일 상태를 로컬에서 검토해야 하며 기존 운영 인증 DB를 삭제하면 안 된다.

공식 계약 참고(2026-11-18 열람):
- https://coolify.io/docs/core/networking/proxy/overview
- https://coolify.io/docs/core/networking/proxy/traefik/overview
- https://www.freedesktop.org/software/systemd/man/latest/systemd-socket-proxyd.html
- https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- https://developers.openai.com/plugins/build/auth
- https://pypi.org/project/mcp/1.30.0/
