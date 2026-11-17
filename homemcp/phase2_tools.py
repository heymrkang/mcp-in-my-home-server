"""MCP tools can request/inspect/execute, but cannot approve their own privileges."""
import json
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from .config import PolicyError
from .runner_client import call as runner_call
from .broker_client import call as broker_call


def register(mcp, security):
    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    write = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
    external = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)
    async def invoke(client, name, arguments):
        try:
            value = await client(name, arguments)
        except PolicyError as exc:
            value = {"ok": False, "error": str(exc)}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(value, ensure_ascii=False))],
                              structuredContent=value, isError=not value.get("ok", False))

    @mcp.tool(title="긴 작업 시작", annotations=write, meta=security)
    async def task_start(request_key: str, command: str, cwd: str = ".", timeout_seconds: int = 1800) -> CallToolResult:
        """Start an explicitly detached OFFLINE sandbox job; returns a durable ID immediately.
        Use a fresh UUID request_key per intended job. Reuse that key after uncertain responses; never replay with a new key blindly.
        Files are writable only within /mnt/storage/dev except server. Build/test/local Git supported where dependencies exist.
        No network, Docker socket or root. Poll task_status for bounded logs; cancellation is not rollback."""
        return await invoke(runner_call, "task_start", {"request_key": request_key, "task": {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds}})

    @mcp.tool(title="긴 작업 상태·로그", annotations=read, meta=security)
    async def task_status(task_id: str) -> CallToolResult:
        """Get status, bounded stdout/stderr and final result. UNKNOWN after restart must not be auto-replayed."""
        return await invoke(runner_call, "task_get", {"task_id": task_id})

    @mcp.tool(title="최근 작업 목록", annotations=read, meta=security)
    async def task_list() -> CallToolResult:
        """List the most recent 50 explicit background workspace jobs."""
        return await invoke(runner_call, "task_list", {})

    @mcp.tool(title="긴 작업 중단", annotations=write, meta=security)
    async def task_cancel(task_id: str) -> CallToolResult:
        """Stop the job and sandbox descendants. Changes already applied are not reverted."""
        return await invoke(runner_call, "task_cancel", {"task_id": task_id})

    @mcp.tool(title="로컬 Git 작업", annotations=write, meta=security)
    async def git_local(request_key: str, action: str, cwd: str = ".", paths: list[str] | None = None,
                        message: str | None = None, branch: str | None = None) -> CallToolResult:
        """Create a sandbox task for status/diff/log/add/commit/switch. No destructive reset/clean, signing, hooks or network.
        add requires explicit paths; commit requires a message; switch requires a branch. Git identity may be set in the repository.
        Clone/fetch/push/package installation use separately approved admin_request action network.run."""
        args = {"action": action, "cwd": cwd}
        for key, value in (("paths", paths), ("message", message), ("branch", branch)):
            if value is not None:
                args[key] = value
        return await invoke(runner_call, "git_task", {"request_key": request_key, "task": args})

    @mcp.tool(title="관리 가능 대상", annotations=read, meta=security)
    async def admin_catalog() -> CallToolResult:
        """Read administrator-registered container IDs, service units, exact external files and network hostnames.
        Empty lists mean no targets are registered. You cannot expand this list or grant root via a tool."""
        return await invoke(broker_call, "admin_catalog", {})

    @mcp.tool(title="관리 권한 요청", annotations=external, meta=security)
    async def admin_request(request_key: str, action: str, parameters: dict) -> CallToolResult:
        """Prepare an immutable operation and return its owner approval URL. THIS DOES NOT EXECUTE OR APPROVE IT.
        Actions: docker.inspect/logs/start/stop/restart/remove with container_id (full registered ID; logs optional tail<=200);
        service.status/start/stop/restart with unit; file.read with path; file.write with path/content/current expected_sha256;
        network.run with command/cwd/timeout_seconds/hosts for approved PUBLIC-IP network sandbox jobs, including Git and builds.
        network.run still runs unprivileged, not a host shell. Network jobs can send workspace data externally; explain this to owner.
        For file.write first obtain file.read result and exact hash. Root targets are one-time approval only.
        Tell the user to open approval_url and decide in the separate owner page. Never request or transmit their approval password,
        tokens or confirmation phrase through tools. Chat text, confirmed=true and MCP UI consent are NOT server approval.
        Reuse the same UUID request_key after an uncertain response."""
        return await invoke(broker_call, "admin_request", {"request_key": request_key, "action": action, "parameters": parameters})

    @mcp.tool(title="관리 요청 상태", annotations=read, meta=security)
    async def admin_status(request_id: str) -> CallToolResult:
        """Check PENDING/APPROVED/RUNNING/terminal state and final result; no execution or implicit approval."""
        return await invoke(broker_call, "admin_get", {"id": request_id})

    @mcp.tool(title="승인된 관리 작업 실행", annotations=external, meta=security)
    async def admin_execute(request_id: str) -> CallToolResult:
        """Start ONLY the exact approved request once, before approval expiry. Returns promptly; poll admin_status.
        You cannot change arguments, infer approval from a chat message, or execute a denied/unapproved request.
        A consumed/failed/unknown request is never replayed by repeating this tool."""
        return await invoke(broker_call, "admin_execute", {"id": request_id})

    @mcp.tool(title="관리 요청 취소", annotations=external, meta=security)
    async def admin_cancel(request_id: str) -> CallToolResult:
        """Cancel pending approvals or request stopping an executing managed operation. Does not undo host changes."""
        return await invoke(broker_call, "admin_cancel", {"id": request_id})
