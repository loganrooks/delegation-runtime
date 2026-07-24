"""Fail-closed Claude native-sandbox policy generation.

Pure with one exception: declared MCP configuration files are hashed, so the builder
reads those paths. It never launches a process, mutates state, or claims that a
requested sandbox policy is the *effective* one — only the runtime can establish that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path


# The exact block the locked contract requires for every Bash-capable profile.
SANDBOX_REQUEST: dict = {
    "enabled": True,
    "failIfUnavailable": True,
    "autoAllowBashIfSandboxed": False,
    "allowUnsandboxedCommands": False,
    "excludedCommands": [],
    "network": {"allowedDomains": [], "deniedDomains": ["*"]},
}

# Flags the installed CLI must advertise before a sandbox-requiring profile may launch.
REQUIRED_SANDBOX_FLAGS: tuple[str, ...] = (
    "--settings",
    "--mcp-config",
    "--strict-mcp-config",
)

SETTING_SOURCES_FLAG = "--setting-sources"

_SANDBOX_MODES = ("verified", "artifact", "implementation")

_PROFILE_POLICY_MODES = {
    "strict-readonly": "strict",
    "verified-review": "verified",
    "artifact-review": "artifact",
    "implementation": "implementation",
    "implementation-auto": "implementation",
}


class PolicyError(ValueError):
    """Raised for any runtime policy that cannot be constructed fail-closed."""


@dataclass(frozen=True)
class RuntimePolicy:
    mode: str
    settings: dict
    cli_args: tuple[str, ...]
    env: dict[str, str]
    requires_native_sandbox: bool
    sandbox_status: str
    settings_sources_suppressed: bool
    mcp_config_hashes: tuple[tuple[str, str], ...]
    mcp_executable_hashes: tuple[tuple[str, str], ...]
    policy_sha256: str
    missing_capabilities: tuple[str, ...] = field(default=())


def policy_mode_for_profile(profile_id: str | None) -> str:
    if profile_id is None:
        return "custom"
    try:
        return _PROFILE_POLICY_MODES[profile_id]
    except KeyError as exc:
        raise PolicyError(f"no runtime policy mode for profile: {profile_id!r}") from exc


def missing_capabilities(help_text: str, *, requires_native_sandbox: bool) -> tuple[str, ...]:
    """Flags the profile needs but the installed CLI does not advertise."""
    if not requires_native_sandbox:
        return ()
    return tuple(flag for flag in REQUIRED_SANDBOX_FLAGS if flag not in (help_text or ""))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_mcp_configs(
    paths: tuple[Path, ...], allowed_tools: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    required_servers = {
        entry[len("mcp__") :].rsplit("__", 1)[0]
        for entry in allowed_tools
        if entry.startswith("mcp__") and "__" in entry[len("mcp__") :]
    }
    configured: dict[str, dict] = {}
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"invalid declared MCP configuration: {path}") from exc
        servers = payload.get("mcpServers") if isinstance(payload, dict) else None
        if not isinstance(servers, dict):
            raise PolicyError(f"MCP configuration has no mcpServers object: {path}")
        for name, definition in servers.items():
            if name in configured:
                raise PolicyError(f"duplicate MCP server declaration: {name!r}")
            if not isinstance(definition, dict):
                raise PolicyError(f"invalid MCP server definition: {name!r}")
            configured[name] = definition

    if set(configured) != required_servers:
        raise PolicyError(
            "declared MCP servers must exactly match allowed MCP tool namespaces: "
            f"required={sorted(required_servers)}, configured={sorted(configured)}"
        )

    executable_hashes: list[tuple[str, str]] = []
    for name, definition in configured.items():
        if definition.get("url") is not None or definition.get("type") not in (None, "stdio"):
            raise PolicyError(f"profiled MCP server must use local stdio: {name!r}")
        if definition.get("args") not in (None, []):
            raise PolicyError(
                f"profiled MCP server arguments are not admitted in this contract: {name!r}"
            )
        if definition.get("env") not in (None, {}):
            raise PolicyError(
                f"profiled MCP server environment overrides are not admitted: {name!r}"
            )
        command = definition.get("command")
        if not isinstance(command, str) or not Path(command).is_absolute():
            raise PolicyError(
                f"profiled MCP server requires an absolute local executable: {name!r}"
            )
        executable = Path(command).resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise PolicyError(
                f"profiled MCP executable is missing or not executable: {executable}"
            )
        executable_hashes.append((name, _file_sha256(executable)))
    return tuple(sorted(executable_hashes))


def _scratch_env(scratch_dir: Path) -> dict[str, str]:
    scratch = str(scratch_dir)
    return {
        "TMPDIR": scratch,
        "TMP": scratch,
        "TEMP": scratch,
        "XDG_CACHE_HOME": str(scratch_dir / "cache"),
        "PYTHONPYCACHEPREFIX": str(scratch_dir / "pycache"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def build_runtime_policy(
    *,
    mode: str,
    permission_mode: str,
    tools: tuple[str, ...],
    allowed_tools: tuple[str, ...],
    denied_tools: tuple[str, ...],
    settings_path: Path,
    mcp_config_paths: tuple[Path, ...] = (),
    scratch_dir: Path | None = None,
    project_root: Path | None = None,
    git_control_paths: tuple[Path, ...] = (),
    help_text: str = "",
) -> RuntimePolicy:
    requires_sandbox = mode in _SANDBOX_MODES

    declared_mcp = tuple(Path(p) for p in mcp_config_paths)
    for path in declared_mcp:
        if not path.is_file():
            raise PolicyError(f"declared --mcp-config path is not a file: {path}")
    if not declared_mcp:
        for entry in allowed_tools:
            if entry.startswith("mcp__"):
                raise PolicyError(
                    "allowed mcp tool has no declared server configuration: "
                    f"{entry!r}; pass --mcp-config"
                )
    mcp_hashes = tuple((str(path), _file_sha256(path)) for path in declared_mcp)
    mcp_executable_hashes = (
        _validate_mcp_configs(declared_mcp, allowed_tools)
        if mode != "custom"
        else ()
    )

    settings: dict = {
        "permissions": {
            "defaultMode": permission_mode,
            "allow": sorted(set(allowed_tools)),
            "deny": sorted(set(denied_tools)),
        }
    }
    if requires_sandbox:
        settings["sandbox"] = json.loads(json.dumps(SANDBOX_REQUEST))
        filesystem: dict[str, list[str]] = {}
        if scratch_dir is not None:
            filesystem["allowWrite"] = [str(Path(scratch_dir).resolve())]
        if project_root is not None:
            protected = [Path(project_root).resolve() / ".git"]
            protected.extend(Path(path) for path in git_control_paths)
            filesystem["denyWrite"] = list(
                dict.fromkeys(str(path.resolve()) for path in protected)
            )
        if filesystem:
            settings["sandbox"]["filesystem"] = filesystem

    cli_args: list[str] = ["--settings", str(settings_path)]
    suppress_sources = SETTING_SOURCES_FLAG in (help_text or "")
    if suppress_sources:
        # An empty source list asks the CLI to skip user, project, and local settings
        # files. Array-valued settings still merge from any managed layer outside our
        # control, so this narrows the surface without proving it is the only one.
        cli_args += [SETTING_SOURCES_FLAG, ""]
    for path in declared_mcp:
        cli_args += ["--mcp-config", str(path)]
    cli_args.append("--strict-mcp-config")

    env: dict[str, str] = {}
    if scratch_dir is not None:
        env = _scratch_env(Path(scratch_dir))

    # The hash binds the authority-bearing shape, not run-local paths, so two
    # equivalent runs in different directories share one comparable policy id.
    policy_sha256 = _canonical_hash(
        {
            "mode": mode,
            "settings": settings,
            "env_keys": sorted(env),
            "mcp_config_hashes": sorted(digest for _, digest in mcp_hashes),
            "mcp_executable_hashes": sorted(mcp_executable_hashes),
            "requires_native_sandbox": requires_sandbox,
            "settings_sources_suppressed": suppress_sources,
            "tools": sorted(set(tools)),
        }
    )

    return RuntimePolicy(
        mode=mode,
        settings=settings,
        cli_args=tuple(cli_args),
        env=env,
        requires_native_sandbox=requires_sandbox,
        sandbox_status="requested-unproven" if requires_sandbox else "not-requested",
        settings_sources_suppressed=suppress_sources,
        mcp_config_hashes=mcp_hashes,
        mcp_executable_hashes=mcp_executable_hashes,
        policy_sha256=policy_sha256,
        missing_capabilities=missing_capabilities(
            help_text, requires_native_sandbox=requires_sandbox
        ),
    )
