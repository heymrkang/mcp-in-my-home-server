"""Operator-invoked checks. Never edits workspace files or uses OAuth secrets."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from .common import ROOT, ETC, InstallError, need, read_json, run

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        return None


def request(base, path, host):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(base + path, headers={'Host': host, 'Accept': 'application/json, text/event-stream'})
    try: response = client.open(req, timeout=12 if base.startswith('https://') else 3)
    except urllib.error.HTTPError as error: response = error
    with response:
        body = response.read(65537)
        need(len(body) <= 65536, 'HTTP check response too large')
        return response.status, response.headers, body


def http_checks(base, origin):
    host = urlsplit(origin).netloc
    status, _, body = request(base, '/health', host)
    value = json.loads(body)
    need(status == 200 and value.get('application') == 'home-mcp' and value.get('alive') is True, 'Health response mismatch')
    status, _, body = request(base, '/.well-known/oauth-authorization-server', host)
    metadata = json.loads(body)
    need(status == 200 and metadata.get('issuer') == origin + '/' and 'S256' in metadata.get('code_challenge_methods_supported', []), 'OAuth issuer/PKCE metadata mismatch')
    need(metadata.get('token_endpoint') == origin + '/oauth/token' and 'refresh_token' in metadata.get('grant_types_supported', []), 'OAuth endpoint/refresh metadata mismatch')
    status, headers, _ = request(base, '/mcp', host)
    need(status == 401, 'Unauthenticated MCP must return 401, not 200/redirect/challenge page')
    challenge = headers.get('www-authenticate', '')
    match = re.search(r'resource_metadata="([^"]+)"', challenge)
    need(match, 'OAuth resource discovery challenge missing')
    target = urlsplit(match.group(1))
    need(target.scheme == 'https' and target.netloc == host and target.path.startswith('/.well-known/oauth-protected-resource')
         and not target.query and not target.fragment and not target.username, 'Unexpected resource metadata location')
    status, _, body = request(base, target.path, host)
    resource = json.loads(body)
    need(status == 200 and resource.get('resource') == origin + '/mcp' and origin + '/' in resource.get('authorization_servers', []), 'Resource audience/issuer mismatch')
    return True


def verify(public=False):
    config = read_json(ETC / 'config.json'); policy = read_json(ETC / 'phase2.json')
    origin, port, owner_port = config['public_origin'], config['listen_port'], policy['owner_port']
    results = []
    def check(name, operation):
        try: operation(); results.append({'check': name, 'result': 'PASS'})
        except Exception as error:
            # No bodies, cookies, token URLs or stack traces in diagnostics.
            results.append({'check': name, 'result': 'FAIL', 'reason': str(error) if isinstance(error, InstallError) else type(error).__name__})
    def units():
        names = ['home-mcp.service', 'home-mcp-owner.service', 'home-mcp-runner.service', 'home-mcp-broker.service']
        end = time.monotonic() + 20
        while True:
            state = run(['systemctl', 'is-active', *names], capture=True, check=False, timeout=5).stdout.decode().split()
            if len(state) == len(names) and all(value == 'active' for value in state): return
            need(time.monotonic() < end, 'One or more Home MCP services are not active')
            time.sleep(0.5)
    def listener_scope():
        # Type=simple can become active before Uvicorn has completed startup.
        # Wait only for these local listeners, not for application mutations.
        wanted = {f'{port:04X}', f'{owner_port:04X}'}
        end = time.monotonic() + 20
        while True:
            found = set()
            for filename in ['/proc/net/tcp', '/proc/net/tcp6']:
                if not Path(filename).exists(): continue
                for line in Path(filename).read_text().splitlines()[1:]:
                    fields = line.split(); address, selected = fields[1].split(':')
                    if selected not in wanted or fields[3] != '0A': continue
                    need(address == '0100007F', 'MCP/approval HTTP must listen only on IPv4 loopback')
                    found.add(selected)
            if found == wanted: return
            need(time.monotonic() < end, 'Expected loopback listeners not found')
            time.sleep(0.25)
    def owner():
        status, headers, _ = request(f'http://127.0.0.1:{owner_port}', '/approval/', urlsplit(origin).netloc)
        need(status in {200, 302, 303}, 'Approval page unavailable')
        need(headers.get('cache-control') == 'no-store', 'Approval response cache protection missing')
    def runner():
        code = 'import asyncio,json; from homemcp.runner_client import call; print(json.dumps(asyncio.run(asyncio.wait_for(call("workspace_status",{}), 10))))'
        raw = run(['runuser', '-u', 'home-mcp', '--', str(ROOT / 'venv/bin/python'), '-B', '-c', code], cwd=ROOT / 'app', capture=True, timeout=15)
        result = json.loads(raw)
        need(result.get('ok') is True, 'Runner IPC/startup sandbox probe failed')
    check('services', units)
    if results[-1]['result'] == 'FAIL':
        # Downstream HTTP/IPC probes cannot succeed if the units are inactive.
        for name in ['loopback_only', 'local_health_and_oauth_boundary', 'approval_page',
                     'isolated_runner_startup', 'public_tls_routing_and_oauth', 'public_approval_route']:
            if public or not name.startswith('public_'):
                results.append({'check': name, 'result': 'SKIPPED', 'reason': 'services not active'})
        results.extend([{'check': name, 'result': 'NOT_RUN'} for name in
                        ['chatgpt_pairing', 'owner_approval_flow', 'network_job_bpf',
                         'docker_service_mutations', 'reboot']])
        print(json.dumps({'checks': results, 'complete_security_audit': False}, ensure_ascii=False, indent=2))
        return False
    check('loopback_only', listener_scope)
    check('local_health_and_oauth_boundary', lambda: http_checks(f'http://127.0.0.1:{port}', origin))
    check('approval_page', owner)
    check('isolated_runner_startup', runner)
    if public:
        check('public_tls_routing_and_oauth', lambda: http_checks(origin, origin))
        def public_owner():
            status, _, _ = request(origin, '/approval/', urlsplit(origin).netloc)
            need(status in {200, 302, 303}, 'Public approval route unavailable')
        check('public_approval_route', public_owner)
    else: results.append({'check': 'public_tls', 'result': 'NOT_RUN'})
    results.extend([{'check': name, 'result': 'NOT_RUN'} for name in ['chatgpt_pairing', 'owner_approval_flow', 'network_job_bpf', 'docker_service_mutations', 'reboot']])
    print(json.dumps({'checks': results, 'complete_security_audit': False}, ensure_ascii=False, indent=2))
    return not any(item['result'] == 'FAIL' for item in results)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--local', action='store_true'); parser.add_argument('--public', action='store_true')
    args = parser.parse_args()
    try: success = verify(public=args.public)
    except Exception as error:
        print(json.dumps({'result': 'FAIL', 'reason': type(error).__name__})); success = False
    raise SystemExit(0 if success else 1)
