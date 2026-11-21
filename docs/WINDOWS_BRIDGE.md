# Windows Agent Bridge (Home MCP 단일 등록)

Home MCP에 Windows PC 여러 대를 붙이는 방식. 별도 Windows MCP URL, Cloudflare Tunnel,
포트포워딩, 인바운드 방화벽 규칙이 필요 없다. **기존 Home MCP OAuth와 URL은 유지**한다.
Windows PC가 인터넷으로 **Home MCP의 HTTPS 서버에 먼저 접속**하며 PC마다 등록한 키로 인증한다.

## 구조

ChatGPT/기타 MCP 클라이언트 → 기존 Home MCP /mcp → Windows Bridge → Windows Agent(아웃바운드 HTTPS)

- Windows Agent는 MCP 서버가 아니다. Home MCP만 MCP 서버다.
- 모든 Windows 도구에 device_id가 필수다. 예: home-desktop, home-notebook, office-desktop.
- 장치 인증키는 서버에 SHA-256 해시로 저장되며 원문은 최초 등록 시 한 번만 출력된다.
- Linux Home MCP의 기존 runner, root broker, OAuth 및 승인 UI는 변경하지 않는다.
- Home MCP가 중단되면 Windows PC에 연결할 수 없다.

## 1. Home MCP 업데이트 (홈서버 로컬 터미널에서)

해당 Git 커밋을 홈서버 checkout에 받아 배포해야 새 도구가 나온다.
**GitHub에 커밋한 것만으로 운영 중인 MCP가 자동 업데이트되지는 않는다.**

    cd /mnt/storage/dev/server
    git pull --ff-only
    sudo home-mcp update
    sudo home-mcp status
    sudo home-mcp verify --public

업데이트는 기존 서비스가 재시작될 수 있다. 진행 중인 Home MCP 작업이 있다면 완료 후 수행한다.
이전 운영 키 또는 승인 암호는 재발급하지 않는다.

## 2. Windows PC 등록 (홈서버 로컬 관리자 터미널)

아래 명령의 장치 이름만 바꿔 각각 한 번씩 실행한다.

    sudo sh -c 'cd /opt/home-mcp/app && runuser -u home-mcp -- /opt/home-mcp/venv/bin/python -B -m homemcp.windows_bridge enroll home-desktop'
    sudo sh -c 'cd /opt/home-mcp/app && runuser -u home-mcp -- /opt/home-mcp/venv/bin/python -B -m homemcp.windows_bridge enroll home-notebook'
    sudo sh -c 'cd /opt/home-mcp/app && runuser -u home-mcp -- /opt/home-mcp/venv/bin/python -B -m homemcp.windows_bridge enroll office-desktop'

출력된 DEVICE_ID와 DEVICE_TOKEN을 **해당 Windows PC의 최초 Start.bat 화면에만** 입력한다.
토큰을 채팅, 메신저, GitHub, 공유 ZIP에 올리지 말 것. 분실하면 기존 장치를 폐기하고 재등록한다.

목록 / 폐기:

    sudo sh -c 'cd /opt/home-mcp/app && runuser -u home-mcp -- /opt/home-mcp/venv/bin/python -B -m homemcp.windows_bridge list'
    sudo sh -c 'cd /opt/home-mcp/app && runuser -u home-mcp -- /opt/home-mcp/venv/bin/python -B -m homemcp.windows_bridge revoke home-desktop'

폐기된 장치 이름은 같은 이름으로 다시 enroll하면 새 키로 재등록된다.
동일한 DEVICE_TOKEN을 여러 PC에 복제하지 말 것. PC마다 개별 등록한다.

## 3. Windows Agent 포터블 ZIP 사용

1. Windows 11 PC에 ZIP을 압축 해제한다 (예: C:\Windows-MCP-Agent).
2. Start.bat 실행 → 관리자 권한 승인.
3. 최초에 Home MCP URL(https://... 형식, **/mcp 제외**), DEVICE_ID, DEVICE_TOKEN 입력.
4. "Connected"가 표시되면 계속 켜둔다. 종료는 콘솔에서 Ctrl+C.
5. 자동 실행을 원하면 Settings.bat 실행 → [1] ON.
   ON 등록 시 Windows 부팅 때 SYSTEM 백그라운드 Agent가 실행되고, 로그인하면 GUI 도우미도 실행된다.
   [2] OFF는 자동 시작 해제와 예약작업 종료. 수동 Start.bat에는 영향이 없다.

Windows Agent는 홈서버로 HTTPS POST를 보낸다. 집/회사 PC에서 18792 포트를 열 필요 없다.
회사 PC에서는 보안 정책상 외부 통신과 원격 제어 프로그램 실행이 허용되는지 확인한다.

## 4. ChatGPT / 다른 MCP 도구

**새 MCP를 추가할 필요 없다.** 이미 연결된 Home MCP 하나를 사용한다.
업데이트 후 도구 목록을 새로고침/재연결하면 windows_devices, windows_run,
windows_task_start, windows_screen 등 Windows 도구가 추가된다.

예:
- "windows_devices로 연결된 PC 확인해."
- "home-desktop에서 git --version 실행해."
- "home-desktop에서 프로젝트 빌드한 뒤 windows_screen으로 화면 캡처해."

기존 Home MCP에 아직 연결하지 않은 클라이언트라면
기존 Home MCP의 https://.../mcp URL과 기존 OAuth 설정을 그대로 사용한다.
클라이언트의 MCP 도구 실행 승인 정책은 각 클라이언트마다 다를 수 있다.

## 5. 잠금화면과 관리자 권한

- 백그라운드 Agent(SYSTEM)는 로그인 여부와 무관하게 명령, 파일, 빌드, Git 등을 실행할 수 있다.
- 사용자 세션에 설치된 개발 도구, 개인 계정 Git 자격증명, 사용자별 PATH는 SYSTEM에서
  자동 공유되지 않는다. 필요한 경우 절대 경로와 명시적 환경 설정을 사용한다.
- 화면 캡처·마우스·키보드 조작은 **사용자가 로그인하여 잠금 해제한 세션**이 필요하다.
  Win+L로 잠근 상태에서는 GUI 요청을 거부한다. 잠금을 자동 해제하거나 UAC를 우회하지 않는다.
- 일반 관리자 권한이 Windows의 모든 보안 경계를 우회하는 것은 아니다.

## 6. 상태 확인 / 장애 조치

- ChatGPT에서 windows_devices를 호출해 online 상태를 확인한다. PC가 재시작했으면
  최초 장치 연결에 수십 초가 걸릴 수 있다.
- Windows Agent 콘솔/로그 확인. 회사 프록시가 HTTPS 연결을 차단하면 연결되지 않을 수 있다.
- 오류 DEVICE_UNAUTHORIZED: 장치 이름 또는 토큰 불일치.
- 오류 DEVICE_OFFLINE: Windows Agent가 꺼져 있거나 최근 체크인이 없음.
- 오류 WINDOWS_RESULT_TIMEOUT: 작업 결과가 불명확하다. windows_request_status로 ID를
  확인하고 실제 PC 상태를 조사하라. **삭제·수정·Git push 등을 무작정 재실행하지 마라.**
- 오류 GUI_UNAVAILABLE: Windows에 로그인하여 잠금 해제하고 GUI 도우미를 실행.
- 동일 ZIP을 PC 여러 대에 복제할 때 data/agent.json을 같이 복사하지 않는다.
  별도 등록키를 입력해야 장치가 구분된다.

## 보안/운영 주의

이 Agent는 인증된 Home MCP 사용자에게 Windows 명령·파일·GUI 권한을 제공한다.
클라이언트의 실행 확인 UI만 믿고 명령 승인 서버를 생략한 구조이므로
Home MCP 인증과 장치별 토큰 보관이 매우 중요하다.
토큰은 HTTPS로만 보내고 저장소에 커밋하지 않는다.
서버는 실행 대상을 device_id로 고정하며 일시적인 네트워크 오류로 같은 명령을
다른 PC에 재전송하지 않는다. 서비스/Windows Agent가 도중 재시작되면 결과가
UNKNOWN일 수 있고, 네트워크 끊김으로 이미 발생한 파일 변경이 되돌려지지는 않는다.

**검증 상태:** Home MCP 브리지 소스의 정적/단위 테스트와 Windows Agent
ZIP 제작을 뜻한다. Windows 11 실기기, 회사 네트워크, ChatGPT 실제 연결은
각 PC에서 별도로 검증해야 한다.
