"""Typed host operations only: no model-supplied root shell or Docker daemon parameters."""
import json
import pwd
from .config import require
from .phase2_policy import canonical
from .process import run
from .network_executor import execute_network

async def execute(identifier, action, payload):
    if action == "network.run":
        return await execute_network(identifier, payload)
    if action.startswith("docker."):
        identifier_value = payload["container_id"]
        prefix = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", "/opt/home-mcp/empty"]
        if action == "docker.inspect":
            # Explicit projection: never disclose Config.Env, mounts' content or registry credentials.
            template = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}}}'
            argv = prefix + ["container", "inspect", "--format", template, identifier_value]
        elif action == "docker.logs":
            argv = prefix + ["container", "logs", "--tail", str(payload["tail"]), identifier_value]
        elif action == "docker.remove":
            argv = prefix + ["container", "rm", identifier_value]  # No --force, --volumes or prune.
        elif action in {"docker.stop", "docker.restart"}:
            argv = prefix + ["container", action.split(".")[1], "--time", "15", identifier_value]
        else:
            argv = prefix + ["container", "start", identifier_value]
        return await run(argv, timeout=60, limit=65536)
    if action.startswith("service."):
        verb = action.split(".")[1]
        if verb == "status":
            argv = ["/usr/bin/systemctl", "show", "--no-pager", "--property=Id,ActiveState,SubState,Result,MainPID", payload["unit"]]
        else:
            argv = ["/usr/bin/systemctl", "--no-ask-password", verb, "--", payload["unit"]]
        return await run(argv, timeout=60, limit=65536)
    if action in {"file.read", "file.write"}:
        user = pwd.getpwnam("root" if payload["as_root"] else "home-mcp-runner")
        result = await run(["/usr/bin/python3", "-I", "-S", "-B", "/opt/home-mcp/app/homemcp/host_file.py"],
            canonical({"action": action, **payload}).encode(), timeout=15, limit=524288,
            user=user.pw_uid, group=user.pw_gid, extra_groups=[])
        require(result["ok"] and not result["truncated"]["stdout"], "HOST_FILE_RESULT_UNCERTAIN")
        value = json.loads(result["stdout"])
        require(isinstance(value, dict) and type(value.get("ok")) is bool, "HOST_FILE_RESULT_INVALID")
        return value
    require(False, "ADMIN_ACTION_REJECTED")
