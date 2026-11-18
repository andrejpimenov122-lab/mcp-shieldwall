"""Core security rules and static/runtime detectors for MCP Shieldwall."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    rule_id: str
    target: str
    message: str
    evidence: str


RULE_METADATA: dict[str, dict[str, str]] = {
    "MCP-001": {
        "name": "PromptInjectionToolMetadata",
        "severity": "CRITICAL",
        "shortDescription": "Hidden prompt-injection directive inside MCP tool metadata",
    },
    "MCP-002": {
        "name": "SensitiveCredentialAccessDirective",
        "severity": "CRITICAL",
        "shortDescription": "Sensitive credential, SSH, or .env access instruction in tool metadata",
    },
    "MCP-003": {
        "name": "SuspiciousExfiltrationWebhook",
        "severity": "HIGH",
        "shortDescription": "Suspicious outbound exfiltration URL or webhook in tool schema",
    },
    "MCP-004": {
        "name": "Base64ObfuscatedToolPayload",
        "severity": "CRITICAL",
        "shortDescription": "Base64-encoded prompt-injection or malicious payload in tool metadata",
    },
    "MCP-101": {
        "name": "DestructiveShellCommand",
        "severity": "CRITICAL",
        "shortDescription": "Destructive shell command in tool call arguments",
    },
    "MCP-102": {
        "name": "PipeToShellExecution",
        "severity": "CRITICAL",
        "shortDescription": "Pipe-to-shell remote code execution pattern in tool call arguments",
    },
    "MCP-103": {
        "name": "Base64ObfuscatedCallArgument",
        "severity": "CRITICAL",
        "shortDescription": "Base64-encoded destructive or injection payload in tool call arguments",
    },
    "MCP-201": {
        "name": "LeakedSecretRedacted",
        "severity": "HIGH",
        "shortDescription": "API key or token detected and redacted in MCP output",
    },
    "MCP-301": {
        "name": "UnsafeMcpServerFlag",
        "severity": "HIGH",
        "shortDescription": "Unsafe permissive or sandbox-disabling flag in MCP client configuration",
    },
    "MCP-302": {
        "name": "HardcodedConfigSecret",
        "severity": "CRITICAL",
        "shortDescription": "Hardcoded API token or credential in MCP client configuration",
    },
    "MCP-303": {
        "name": "UnpinnedNpxPackage",
        "severity": "HIGH",
        "shortDescription": "Unpinned 'npx -y' package without explicit version in MCP config",
    },
    "MCP-304": {
        "name": "InsecurePlaintextHttpServer",
        "severity": "MEDIUM",
        "shortDescription": "Remote MCP server URL uses unencrypted HTTP instead of HTTPS",
    },
}


INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "MCP-001",
        "Hidden prompt-injection directive inside MCP tool description",
        re.compile(
            r"(ignore\s+(all\s+)?previous\s+instructions|<IMPORTANT>|system\s*override|"
            r"do\s+not\s+mention\s+this\s+to\s+the\s+user|silently\s+(read|send|upload|exfiltrate)|"
            r"before\s+running\s+this\s+tool\s+read)",
            re.IGNORECASE,
        ),
    ),
    (
        "MCP-002",
        "Sensitive credential / SSH / .env file access instruction in tool metadata",
        re.compile(
            r"(~/\.ssh/id_rsa|~/\.aws/credentials|\.env\b|/etc/passwd|keychain|"
            r"ANTHROPIC_API_KEY|OPENAI_API_KEY|id_ed25519)",
            re.IGNORECASE,
        ),
    ),
    (
        "MCP-003",
        "Suspicious outbound exfiltration URL or raw webhook inside tool schema",
        re.compile(
            r"(webhook\.site|ngrok-free\.app|requestbin|burpcollaborator|"
            r"curl\s+(?:-s\s+)?-X\s+POST\s+https?://)",
            re.IGNORECASE,
        ),
    ),
]

DESTRUCTIVE_ARG_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "MCP-101",
        "Destructive shell command in tool call arguments",
        re.compile(r"(rm\s+-rf\s+[/~]|mkfs\.|dd\s+if=|:>\s*/etc/|chmod\s+-R\s+777\s+/)", re.IGNORECASE),
    ),
    (
        "MCP-102",
        "Pipe-to-shell remote code execution pattern",
        re.compile(r"(curl|wget)\s+[^|]+\|\s*(bash|sh|zsh|python)", re.IGNORECASE),
    ),
]

SECRET_REDACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[a-zA-Z0-9\-_]{16,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{20,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("STRIPE_KEY", re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
]

_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*", re.IGNORECASE)
_BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])"
)

UNSAFE_SERVER_FLAGS: set[str] = {
    "--allow-all",
    "--dangerously-skip-permissions",
    "--no-sandbox",
    "--disable-sandbox",
    "--yolo",
    "--trust-all",
    "--disable-auth",
    "--insecure",
    "--privileged",
    "--allow-exec",
    "--allow-shell",
}

_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(TOKEN|SECRET|API_KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|AUTH)",
    re.IGNORECASE,
)

_PLACEHOLDER_PREFIXES = ("$", "<", "YOUR_", "REPLACE_", "CHANGE_ME", "EXAMPLE", "TODO", "DUMMY", "TEST_")
_MUTABLE_NPM_TAGS = {"", "latest", "next", "canary", "beta", "alpha", "rc", "dev", "main", "master", "*"}


def _iter_string_leaves(value: Any) -> list[str]:
    """Recursively collect all string values from nested dicts and lists."""
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            strings.extend(_iter_string_leaves(v))
    elif isinstance(value, list):
        for item in value:
            strings.extend(_iter_string_leaves(item))
    return strings


def _try_decode_base64(token: str) -> str | None:
    """Decode a candidate base64 / base64url string if it yields readable UTF-8 text."""
    if len(token) < 16:
        return None
    # Skip pure hex strings of even length (e.g. SHA-256 digests) to avoid noise
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        return None
    padded = token + ("=" * (-len(token) % 4))
    raw: bytes | None = None
    try:
        if "-" in token or "_" in token:
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        else:
            raw = base64.b64decode(padded.encode("ascii"), validate=True)
    except Exception:
        return None

    if not raw or len(raw) < 8:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    printable_count = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\r\t")
    if printable_count / len(decoded) < 0.85:
        return None
    return decoded


def extract_decoded_base64_payloads(text: str) -> list[tuple[str, str]]:
    """Find and decode readable base64 substrings in text."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _BASE64_CANDIDATE_RE.finditer(text):
        cand = match.group(1)
        if cand in seen:
            continue
        seen.add(cand)
        decoded = _try_decode_base64(cand)
        if decoded is not None:
            results.append((cand, decoded))
    return results


def scan_tool_definitions(tools: list[dict[str, Any]]) -> list[Finding]:
    """Audit MCP `tools/list` definitions for tool poisoning, hidden directives, and base64 payloads."""
    findings: list[Finding] = []
    for tool in tools:
        name = str(tool.get("name", "<unnamed>"))
        schema_str = json.dumps(tool.get("inputSchema", {}), ensure_ascii=False)
        leaf_strings = _iter_string_leaves(tool)
        blob = " ".join([str(tool.get("description", "")), schema_str, *leaf_strings])

        for rule_id, msg, pattern in INJECTION_PATTERNS:
            match = pattern.search(blob)
            if match:
                findings.append(
                    Finding(
                        severity="CRITICAL" if rule_id in {"MCP-001", "MCP-002"} else "HIGH",
                        rule_id=rule_id,
                        target=f"tool:{name}",
                        message=msg,
                        evidence=match.group(0)[:120],
                    )
                )

        # Check for base64-encoded injection or destructive payloads across all metadata fields
        seen_b64_matches: set[tuple[str, str]] = set()
        for text_piece in [str(tool.get("description", "")), *leaf_strings]:
            for encoded, decoded in extract_decoded_base64_payloads(text_piece):
                for inner_rule_id, inner_msg, pattern in [*INJECTION_PATTERNS, *DESTRUCTIVE_ARG_PATTERNS]:
                    match = pattern.search(decoded)
                    if match and (encoded, inner_rule_id) not in seen_b64_matches:
                        seen_b64_matches.add((encoded, inner_rule_id))
                        findings.append(
                            Finding(
                                severity="CRITICAL",
                                rule_id="MCP-004",
                                target=f"tool:{name}",
                                message=f"Base64-obfuscated payload ({inner_rule_id}: {inner_msg})",
                                evidence=f"b64:{encoded[:32]} -> {match.group(0)[:70]}",
                            )
                        )
    return findings


def scan_tool_call(tool_name: str, arguments: dict[str, Any]) -> list[Finding]:
    """Inspect runtime `tools/call` arguments before forwarding to an MCP server."""
    findings: list[Finding] = []
    serialized = json.dumps(arguments, ensure_ascii=False) if isinstance(arguments, (dict, list)) else str(arguments)
    for rule_id, msg, pattern in DESTRUCTIVE_ARG_PATTERNS:
        match = pattern.search(serialized)
        if match:
            findings.append(
                Finding(
                    severity="CRITICAL",
                    rule_id=rule_id,
                    target=f"call:{tool_name}",
                    message=msg,
                    evidence=match.group(0)[:120],
                )
            )

    seen_b64: set[tuple[str, str]] = set()
    for leaf in _iter_string_leaves(arguments):
        for encoded, decoded in extract_decoded_base64_payloads(leaf):
            for inner_rule_id, inner_msg, pattern in [*DESTRUCTIVE_ARG_PATTERNS, *INJECTION_PATTERNS]:
                match = pattern.search(decoded)
                if match and (encoded, inner_rule_id) not in seen_b64:
                    seen_b64.add((encoded, inner_rule_id))
                    findings.append(
                        Finding(
                            severity="CRITICAL",
                            rule_id="MCP-103",
                            target=f"call:{tool_name}",
                            message=f"Base64-obfuscated argument payload ({inner_rule_id}: {inner_msg})",
                            evidence=f"b64:{encoded[:32]} -> {match.group(0)[:70]}",
                        )
                    )
    return findings


def redact_secrets(text: str) -> tuple[str, int]:
    """Redact leaked API keys and tokens from MCP tool outputs before context ingestion."""
    redacted = text
    total = 0
    for label, pattern in SECRET_REDACT_PATTERNS:
        redacted, count = pattern.subn(f"[REDACTED:{label}]", redacted)
        total += count
    return redacted, total


def _is_pinned_npm_package(pkg: str) -> bool:
    """Return True if an npm package specifier has a concrete non-mutable version pin."""
    spec = pkg.strip()
    if spec.startswith("npm:"):
        spec = spec[4:]
    if spec.startswith(("./", "../", "/", "file:")):
        return True
    if spec.startswith("@"):
        if "/" not in spec:
            return False
        _, pkg_part = spec.split("/", 1)
        if "@" not in pkg_part:
            return False
        _, version = pkg_part.rsplit("@", 1)
        return version.lower() not in _MUTABLE_NPM_TAGS
    if "@" not in spec:
        return False
    _, version = spec.rsplit("@", 1)
    return version.lower() not in _MUTABLE_NPM_TAGS


def _command_basename(command: str) -> str:
    """Extract lowercase executable name from a POSIX or Windows path."""
    if "\\" in command:
        return PureWindowsPath(command).name.lower()
    return PurePosixPath(command).name.lower()


def _is_placeholder_secret(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return True
    upper = stripped.upper()
    if upper.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if stripped.startswith("${") and stripped.endswith("}"):
        return True
    if stripped.lower() in {"changeme", "placeholder", "none", "null", "false", "true"}:
        return True
    return False


def audit_mcp_config(config: dict[str, Any]) -> list[Finding]:
    """Audit Claude Desktop / Cursor / VS Code MCP config for unsafe flags, tokens, and unpinned npx."""
    findings: list[Finding] = []
    servers: dict[str, Any] = {}
    for container_key in ("mcpServers", "servers"):
        candidate = config.get(container_key)
        if isinstance(candidate, dict):
            servers.update(candidate)

    for server_name, raw_cfg in servers.items():
        if not isinstance(raw_cfg, dict):
            continue
        target = f"server:{server_name}"
        command = str(raw_cfg.get("command", "") or "").strip()
        raw_args = raw_cfg.get("args") or []
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else [str(raw_args)]
        tokens = ([command] if command else []) + args

        # 1. Unsafe permissive / sandbox-disabling flags (MCP-301)
        safe_cmd_evidence, _ = redact_secrets(" ".join(tokens))
        safe_cmd_evidence = _BEARER_PATTERN.sub("Bearer [REDACTED]", safe_cmd_evidence)
        for tok in tokens:
            flag_name = tok.split("=", 1)[0].strip().lower()
            if flag_name in UNSAFE_SERVER_FLAGS:
                findings.append(
                    Finding(
                        severity="HIGH",
                        rule_id="MCP-301",
                        target=target,
                        message=f"Unsafe permissive flag '{flag_name}' in MCP server command args",
                        evidence=safe_cmd_evidence[:120],
                    )
                )

        # Also catch destructive shell invocations inside command/args
        joined_cmd = " ".join(tokens)
        for _, msg, pattern in DESTRUCTIVE_ARG_PATTERNS:
            match = pattern.search(joined_cmd)
            if match:
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        rule_id="MCP-301",
                        target=target,
                        message=f"Dangerous shell command in MCP server config ({msg})",
                        evidence=match.group(0)[:120],
                    )
                )

        # 2. Hardcoded tokens/secrets in args, command, url, headers, and env (MCP-302)
        seen_secret_evidence: set[str] = set()
        for field_name, val in [
            ("command", command),
            ("args", " ".join(args)),
            ("url", str(raw_cfg.get("url", "") or "")),
            ("headers", json.dumps(raw_cfg.get("headers", {}), ensure_ascii=False)),
        ]:
            if not val:
                continue
            redacted_val, count = redact_secrets(val)
            if count > 0 and field_name not in seen_secret_evidence:
                seen_secret_evidence.add(field_name)
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        rule_id="MCP-302",
                        target=target,
                        message=f"Hardcoded API key or token detected in MCP server '{field_name}'",
                        evidence=redacted_val[:120],
                    )
                )
            elif _BEARER_PATTERN.search(val) and field_name not in seen_secret_evidence:
                seen_secret_evidence.add(field_name)
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        rule_id="MCP-302",
                        target=target,
                        message=f"Hardcoded Bearer token detected in MCP server '{field_name}'",
                        evidence=_BEARER_PATTERN.sub("Bearer [REDACTED]", val)[:120],
                    )
                )

        env_cfg = raw_cfg.get("env")
        if isinstance(env_cfg, dict):
            for env_key, env_val_raw in env_cfg.items():
                env_key_str = str(env_key)
                env_val = str(env_val_raw or "")
                redacted_env, count = redact_secrets(env_val)
                if count > 0:
                    findings.append(
                        Finding(
                            severity="CRITICAL",
                            rule_id="MCP-302",
                            target=target,
                            message=f"Hardcoded secret in MCP server env '{env_key_str}'",
                            evidence=f"{env_key_str}={redacted_env[:60]}",
                        )
                    )
                elif _SENSITIVE_ENV_KEY_RE.search(env_key_str) and not _is_placeholder_secret(env_val):
                    masked = f"{env_val[:3]}***" if len(env_val) > 3 else "***"
                    findings.append(
                        Finding(
                            severity="HIGH",
                            rule_id="MCP-302",
                            target=target,
                            message=f"Literal credential value in env '{env_key_str}'; prefer runtime env injection",
                            evidence=f"{env_key_str}={masked}",
                        )
                    )

        # 3. Unpinned `npx -y` packages without version (MCP-303)
        cmd_base = _command_basename(command)
        is_npx = cmd_base in {"npx", "npx.cmd", "npx.exe"}
        npx_args = args
        if not is_npx and args:
            # Handle `env ... npx -y ...` or `sh -c "npx -y ..."`
            for idx, arg in enumerate(args):
                if _command_basename(arg) in {"npx", "npx.cmd"}:
                    is_npx = True
                    npx_args = args[idx + 1 :]
                    break

        if is_npx:
            has_yes_flag = any(a in {"-y", "--yes"} or a.startswith("-y") and set(a[1:]) <= {"y", "q"} for a in npx_args)
            if has_yes_flag:
                packages_to_check: list[str] = []
                skip_next = False
                for idx, arg in enumerate(npx_args):
                    if skip_next:
                        skip_next = False
                        continue
                    if arg in {"-p", "--package"}:
                        if idx + 1 < len(npx_args):
                            packages_to_check.append(npx_args[idx + 1])
                            skip_next = True
                        continue
                    if arg.startswith("--package="):
                        packages_to_check.append(arg.split("=", 1)[1])
                        continue
                    if arg in {"-c", "--call", "--userconfig", "--cache"}:
                        skip_next = True
                        continue
                    if arg.startswith("-"):
                        continue
                    packages_to_check.append(arg)
                    break

                for pkg in packages_to_check:
                    if not _is_pinned_npm_package(pkg):
                        findings.append(
                            Finding(
                                severity="HIGH",
                                rule_id="MCP-303",
                                target=target,
                                message=f"Unpinned 'npx -y' package '{pkg}' without explicit version",
                                evidence=safe_cmd_evidence[:120],
                            )
                        )

        # 4. Plaintext HTTP for non-local MCP server URLs (MCP-304)
        url_str = str(raw_cfg.get("url", "") or "").strip()
        if url_str.lower().startswith("http://"):
            parsed = urlparse(url_str)
            host = (parsed.hostname or "").lower()
            if host not in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        rule_id="MCP-304",
                        target=target,
                        message="Remote MCP server URL uses unencrypted http:// instead of https://",
                        evidence=url_str[:120],
                    )
                )

    return findings
