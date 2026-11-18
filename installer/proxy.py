"""Existing Traefik -> unprivileged relay -> UNIX sockets -> loopback HTTP.
No host port publishing, Docker socket in relay, host-gateway exception,
proxy restart, firewall rewrite or changes to another application's labels.
"""
from __future__ import annotations
import json
from pathlib import Path
import pwd
import re
from urllib.parse import urlsplit
from .common import MARKER, InstallError, label, need, run, write, write_json

IMAGE = 'nginxinc/nginx-unprivileged:stable'
CONTAINER = PROJECT = 'home-mcp-edge'
MANAGED = 'io.home-mcp.managed'


def valid_origin(value):
    url = urlsplit(value)
    need(url.scheme == 'https' and not url.username and not url.password and not url.query
         and not url.fragment and url.path == '' and url.port in (None, 443), 'Use an HTTPS origin without a path')
    need(bool(url.hostname) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', url.hostname)
         and '.' in url.hostname and url.netloc == url.hostname, 'Use a lower-case DNS hostname without a port')
    return url.hostname


def inspect_proxy(name, network=None, entrypoint=None, resolver=None):
    label(name)
    result = run(['docker', 'inspect', name], capture=True, check=False)
    need(result.returncode == 0, 'Coolify proxy not found. Use --proxy-container NAME or --proxy host for a separately managed host proxy.')
    record = json.loads(result.stdout)[0]
    need(record['State']['Running'], 'Existing proxy is not running')
    need('traefik' in record.get('Config', {}).get('Image', '').lower(), 'Automatic integration supports Traefik only; Caddy/custom proxies are not replaced')
    args = record.get('Args', []) + (record.get('Config', {}).get('Cmd') or [])
    flags, raw = {}, {}
    for item in args:
        if isinstance(item, str) and item.startswith('--'):
            key, _, value = item[2:].partition('='); flags[key.lower()] = value; raw[key] = value
    need(any(key.startswith('providers.docker') for key in flags) and flags.get('providers.docker') != 'false', 'Cannot confirm Traefik Docker provider from container flags')
    networks = record.get('NetworkSettings', {}).get('Networks', {})
    candidates = [x for x in networks if x not in {'host', 'none', 'bridge'}]
    network = network or ('coolify' if 'coolify' in candidates else candidates[0] if len(candidates) == 1 else None)
    need(network in candidates, 'Specify --network from the existing proxy networks')
    entries = []
    resolvers = set()
    for key, value in raw.items():
        match = re.fullmatch(r'entrypoints\.([^.]+)\.address', key, re.I)
        if match and value in {':443', ':443/tcp', '0.0.0.0:443'}: entries.append(match[1])
        match = re.match(r'certificatesresolvers\.([^.]+)\.acme\.', key, re.I)
        if match: resolvers.add(match[1])
    entries = list(dict.fromkeys(entries))
    entrypoint = entrypoint or (entries[0] if len(entries) == 1 else None)
    need(entrypoint in entries, 'Specify --https-entrypoint matching an existing 443 entrypoint')
    if resolver is None:
        need(len(resolvers) == 1, 'Specify --tls-resolver NAME; none requires a preconfigured valid default certificate')
        resolver = next(iter(resolvers))
    need(resolver == 'none' or resolver in resolvers, 'Resolver not present in proxy flags')
    return {'mode': 'traefik', 'container': name, 'network': label(network), 'entrypoint': label(entrypoint), 'resolver': label(resolver)}


def check_conflicts(host):
    ids = run(['docker', 'ps', '-aq'], capture=True).split()
    for index in range(0, len(ids), 50):
        rows = json.loads(run(['docker', 'inspect', *ids[index:index+50]], capture=True))
        for row in rows:
            name = row.get('Name', '').lstrip('/')
            labels = row.get('Config', {}).get('Labels') or {}
            own = labels.get(MANAGED) == 'true' and name == CONTAINER
            if name == CONTAINER or labels.get('com.docker.compose.project') == PROJECT:
                need(own, 'home-mcp-edge name/project belongs to another resource')
            if not own:
                rules = [value for key, value in labels.items() if key.endswith('.rule') or key in {'caddy', 'caddy_0'}]
                need(not any(host in value for value in rules if isinstance(value, str)), 'Domain already routed by another container; review its domain assignment first')


def resolve_image(previous=None, refresh=False):
    if previous and not refresh:
        image = previous['image']
        need(re.fullmatch(r'(?:docker.io/)?nginxinc/nginx-unprivileged@sha256:[a-f0-9]{64}', image), 'Untrusted cached relay image')
        result = run(['docker', 'image', 'inspect', image], capture=True, check=False)
        if result.returncode: run(['docker', 'pull', image], timeout=600)
        return image
    run(['docker', 'pull', IMAGE], timeout=600)
    digests = json.loads(run(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', IMAGE], capture=True))
    selected = next((value for value in digests if re.fullmatch(r'(?:docker.io/)?nginxinc/nginx-unprivileged@sha256:[a-f0-9]{64}', value)), None)
    need(selected, 'Registry did not return an immutable relay digest')
    return selected


def nginx_config(host):
    valid_origin('https://' + host)
    return '''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/null crit;
events { worker_connections 128; }
http {
  access_log off;
  server_tokens off;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi_temp;
  uwsgi_temp_path /tmp/uwsgi_temp;
  scgi_temp_path /tmp/scgi_temp;
  client_max_body_size 2m;
  client_body_timeout 20s;
  upstream gateway { server unix:/run/home-mcp-http/gateway.sock; }
  upstream owner { server unix:/run/home-mcp-http/owner.sock; }
  server {
    listen 8080 default_server;
    server_name HOSTNAME;
    if ($host != "HOSTNAME") { return 421; }
    proxy_http_version 1.1;
    proxy_set_header Host HOSTNAME;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    proxy_read_timeout 90s;
    proxy_send_timeout 30s;
    location = /approval { return 308 /approval/; }
    location ^~ /approval/ { proxy_pass http://owner; }
    location / { proxy_pass http://gateway; }
  }
}
'''.replace('HOSTNAME', host)


def prepare(release, origin, config, ports):
    host = valid_origin(origin); release = Path(release)
    folder = release / 'proxy'; folder.mkdir(mode=0o755)
    if config['mode'] == 'host':
        write(folder / 'Caddyfile.example', f'''# Merge into an EXISTING host proxy. Do not start a second listener.
{host} {{
    @owner path /approval /approval/*
    handle @owner {{
        reverse_proxy 127.0.0.1:{ports['owner']}
    }}
    handle {{
        reverse_proxy 127.0.0.1:{ports['gateway']}
    }}
}}
''', 0o644)
        return
    proxy_user = pwd.getpwnam('home-mcp-proxy')
    write(folder / 'nginx.conf', nginx_config(host), 0o644)
    labels = {MANAGED: 'true', 'traefik.enable': 'true', 'traefik.docker.network': config['network'],
              'traefik.http.routers.home-mcp-owner-tools.rule': f'Host(`{host}`)',
              'traefik.http.routers.home-mcp-owner-tools.entrypoints': config['entrypoint'],
              'traefik.http.routers.home-mcp-owner-tools.tls': 'true',
              'traefik.http.routers.home-mcp-owner-tools.service': 'home-mcp-owner-tools',
              'traefik.http.services.home-mcp-owner-tools.loadbalancer.server.port': '8080'}
    if config['resolver'] != 'none': labels['traefik.http.routers.home-mcp-owner-tools.tls.certresolver'] = config['resolver']
    compose = {'services': {'edge': {'image': config['image'], 'container_name': CONTAINER,
        'user': f'{proxy_user.pw_uid}:{proxy_user.pw_gid}', 'restart': 'unless-stopped',
        'entrypoint': ['nginx'], 'command': ['-g', 'daemon off;'], 'read_only': True,
        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'tmpfs': ['/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777'],
        'mem_limit': '128m', 'pids_limit': 32, 'cpus': '0.5',
        'volumes': [{'type': 'bind', 'source': str(folder / 'nginx.conf'), 'target': '/etc/nginx/nginx.conf', 'read_only': True, 'bind': {'create_host_path': False}},
                    {'type': 'bind', 'source': '/run/home-mcp-http', 'target': '/run/home-mcp-http', 'read_only': True, 'bind': {'create_host_path': False}}],
        'networks': ['proxy'], 'labels': labels}},
        'networks': {'proxy': {'external': True, 'name': config['network']}}}
    write_json(folder / 'compose.json', compose, 0o644)
    proxyd = next((str(Path(path).resolve()) for path in ['/usr/lib/systemd/systemd-socket-proxyd', '/lib/systemd/systemd-socket-proxyd'] if Path(path).is_file()), None)
    need(proxyd, 'systemd-socket-proxyd missing')
    for kind, service in [('gateway', 'home-mcp.service'), ('owner', 'home-mcp-owner.service')]:
        name = 'home-mcp-http-' + kind
        sock = f'''[Unit]
Description=Home MCP {kind} UNIX HTTP bridge
[Socket]
ListenStream=/run/home-mcp-http/{kind}.sock
SocketUser=root
SocketGroup=home-mcp-proxy
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=true
[Install]
WantedBy=sockets.target
'''
        unit = f'''[Unit]
Description=Home MCP {kind} loopback forwarder
Requires={name}.socket {service}
After={service}
[Service]
User=home-mcp-proxy
Group=home-mcp-proxy
ExecStart={proxyd} 127.0.0.1:{ports[kind]}
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictNamespaces=true
MemoryMax=64M
TasksMax=16
InaccessiblePaths=/mnt/storage/dev /var/lib/home-mcp /var/lib/home-mcp-owner /var/lib/home-mcp-broker -/var/run/docker.sock
'''
        write(release / 'units' / (name + '.socket'), MARKER + sock, 0o644)
        write(release / 'units' / (name + '.service'), MARKER + unit, 0o644)


def compose(release, *arguments):
    return run(['docker', 'compose', '--project-name', PROJECT, '-f', Path(release) / 'proxy/compose.json', *arguments], timeout=180)


def start(release, config):
    if config['mode'] != 'traefik': return
    for name in ['gateway', 'owner']: run(['systemctl', 'enable', '--now', f'home-mcp-http-{name}.socket'])
    compose(release, 'up', '-d', '--no-build', '--pull', 'never')
    run(['docker', 'exec', CONTAINER, 'nginx', '-t'], capture=True)


def stop(release, config):
    if config['mode'] != 'traefik': return
    try:
        result = run(['docker', 'compose', '--project-name', PROJECT, '-f', Path(release) / 'proxy/compose.json', 'stop', '-t', '10'], capture=True, check=False, timeout=30)
        if result.returncode: print('WARNING: relay stop not confirmed; host services will still be stopped before source changes.')
    except Exception:
        # Docker failure must never skip the caller's systemctl stop / rollback.
        print('WARNING: Docker unavailable while stopping relay; host services will still be stopped.')
