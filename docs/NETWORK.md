# 포트와 도메인

목표 주소: https://k9m2x7p4vq3b8z1.12190529.xyz/mcp

| 구분 | 포트 | 조치 |
| --- | --- | --- |
| 외부 HTTPS | TCP 443 | 직접 접속 방식이면 공유기에서 HTTPS 프록시가 있는 홈 서버로 전달 |
| 인증서 발급/HTTP 리다이렉트 | TCP 80 | 기존 프록시/인증서 방식에 따라 필요. 기존 설정을 그대로 사용하는 경우 추가 개방 불필요 |
| MCP HTTP | 127.0.0.1:18790 | 루프백 전용. 인터넷·공유기 포트포워딩 금지 |
| 실행기 | /run/home-mcp-runner.sock | 로컬 소켓. TCP 포트 없음 |
| SSH/Docker 관리 | 해당 없음 | 이 MCP 때문에 22/2375/2376을 추가로 개방하지 않음 |

443이 이미 Coolify/Traefik 등으로 전달된다면 다른 프로그램으로 443을 뺏지 않는다. 같은 HTTPS 프록시에 위 도메인의 MCP·OAuth·well-known 경로만 추가해야 한다. 기존 도메인의 다른 경로는 유지한다.

중요: 브리지 모드 Docker 컨테이너에서 127.0.0.1은 호스트가 아니다. 동봉한 Caddy 예제는 호스트에서 실행하는 프록시용이며 Coolify 컨테이너에 그대로 넣는 설정이 아니다. 3단계에서 실제 프록시 배치에 맞춰 호스트 연결 경로를 정한다. 편의를 위해 MCP를 무인증 0.0.0.0으로 바꾸거나 새 인터넷 포트를 열지 않는다.

DNS의 A/AAAA 레코드, 라우터 전달, 방화벽, 유효한 HTTPS 인증서는 별도 조건이다. IPv6 AAAA가 있으면 IPv6 경로/방화벽도 맞아야 한다. 현재 도메인의 DNS/인증서/프록시는 조회하거나 변경하지 않았다. Cloudflare Tunnel 같은 아웃바운드 터널을 쓰는 구성이라면 공유기 인바운드 포트포워딩 자체가 필요 없을 수 있다.

프록시는 Host와 Authorization을 유지하고 /mcp 및 OAuth 응답을 캐시하지 않아야 한다. OAuth URL/Authorization/Cookie/POST 본문은 로그로 남기지 않는다. ChatGPT 서버가 MCP에 접근할 때 사용자용 HTML 로그인 페이지를 앞단에서 강제로 삽입하면 MCP 연결이 실패한다. 본 구현은 MCP 자체의 OAuth를 사용한다.

공식 참고:
- https://developers.openai.com/plugins/build/auth
- https://caddyserver.com/docs/automatic-https
