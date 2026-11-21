"""Zero-dependency native stdio MCP (Model Context Protocol) JSON-RPC 2.0 server."""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from . import __version__
from .cli import (
    build_config_report,
    build_manifest_report,
    format_markdown_report,
    load_tools_manifest,
    parse_tools_manifest_data,
    verify_lockfile,
)
from .rules import redact_secrets

DEFAULT_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_tools_manifest",
        "description": (
            "Scan an MCP tools/list manifest (inline JSON or file path) for prompt injection "
            "(MCP-001), credential/SSH/.env exfiltration directives (MCP-002), suspicious "
            "webhooks (MCP-003), and Base64-obfuscated injection payloads (MCP-004)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_json": {
                    "anyOf": [{"type": "string"}, {"type": "object"}, {"type": "array"}],
                    "description": "MCP tools manifest as a JSON string, an object with a 'tools' array, or a list of tools.",
                },
                "manifest_path": {
                    "type": "string",
                    "description": "Path to a local MCP tools manifest JSON file.",
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "markdown"],
                    "default": "json",
                    "description": "Output report format ('json' or 'markdown').",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_client_config",
        "description": (
            "Audit an MCP client configuration (claude_desktop_config.json, .mcp.json, Cursor/VS Code mcp.json) "
            "for unsafe flags (MCP-301), hardcoded secrets (MCP-302), unpinned npx -y packages (MCP-303), "
            "and insecure plaintext http:// server URLs (MCP-304)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_json": {
                    "anyOf": [{"type": "string"}, {"type": "object"}],
                    "description": "MCP client config as a JSON string or object containing 'mcpServers' or 'servers'.",
                },
                "config_path": {
                    "type": "string",
                    "description": "Path to a local MCP client config JSON file.",
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "markdown"],
                    "default": "json",
                    "description": "Output report format ('json' or 'markdown').",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_schema_lock",
        "description": (
            "Verify an MCP tools manifest against a .mcp-lock.json lockfile using canonical SHA-256 "
            "tool fingerprints to detect silent rug-pull mutations, additions, or removals."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_path": {
                    "type": "string",
                    "description": "Path to the MCP tools manifest JSON file.",
                },
                "lock_path": {
                    "type": "string",
                    "description": "Path to the .mcp-lock.json lockfile.",
                },
            },
            "required": ["manifest_path", "lock_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "redact_sensitive_text",
        "description": (
            "Scrub leaked API keys and tokens (MCP-201: Anthropic, OpenAI, GitHub, AWS, Slack, Google, Stripe) "
            "from text and return the redacted text along with the redaction count."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Input text to scan and scrub for leaked API keys or tokens.",
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
]


class _TextToBinaryReader:
    """Wrap a TextIO stream so framing logic can read UTF-8 bytes uniformly."""

    def __init__(self, text_stream: TextIO) -> None:
        self._raw = io.BytesIO(text_stream.read().encode("utf-8"))

    def readline(self) -> bytes:
        return self._raw.readline()

    def read(self, size: int = -1) -> bytes:
        return self._raw.read(size)


class _TextToBinaryWriter:
    """Wrap a TextIO stream so framed UTF-8 bytes write cleanly in tests."""

    def __init__(self, text_stream: TextIO) -> None:
        self._text = text_stream

    def write(self, data: bytes) -> int:
        return self._text.write(data.decode("utf-8"))

    def flush(self) -> None:
        self._text.flush()


def _as_binary_reader(stream: Any) -> BinaryIO | _TextToBinaryReader:
    if hasattr(stream, "buffer"):
        return stream.buffer
    if isinstance(stream, io.TextIOBase):
        return _TextToBinaryReader(stream)
    return stream


def _as_binary_writer(stream: Any) -> BinaryIO | _TextToBinaryWriter:
    if hasattr(stream, "buffer"):
        return stream.buffer
    if isinstance(stream, io.TextIOBase):
        return _TextToBinaryWriter(stream)
    return stream


def _read_exact(stream: BinaryIO | _TextToBinaryReader, num_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = num_bytes
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError(f"Unexpected EOF while reading {num_bytes} Content-Length bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_framed_message(stream: BinaryIO | _TextToBinaryReader) -> tuple[str, str] | None:
    """Read a single JSON-RPC message, auto-detecting newline vs Content-Length framing."""
    while True:
        first_line = stream.readline()
        if first_line == b"":
            return None
        stripped = first_line.strip()
        if not stripped:
            continue
        break

    # Standard MCP stdio framing uses newline-delimited JSON objects
    if stripped.startswith((b"{", b"[")):
        return "newline", stripped.decode("utf-8")

    # Header-framed JSON-RPC (e.g., Content-Length: N\r\n\r\n...)
    if b":" in first_line:
        headers: dict[str, str] = {}
        line: bytes = first_line
        while True:
            if line in (b"", b"\r\n", b"\n"):
                break
            if b":" in line:
                key, val = line.decode("ascii", errors="replace").split(":", 1)
                headers[key.strip().lower()] = val.strip()
            line = stream.readline()
            if line == b"":
                break

        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError as exc:
                raise ValueError(f"Invalid Content-Length header: {headers['content-length']!r}") from exc
            if content_length < 0:
                raise ValueError(f"Negative Content-Length header: {content_length}")
            body = _read_exact(stream, content_length)
            return "content-length", body.decode("utf-8")

    # Fallback: pass raw line so JSON parser returns a -32700 Parse error
    return "newline", stripped.decode("utf-8")


def write_framed_message(
    stream: BinaryIO | _TextToBinaryWriter,
    framing: str,
    payload: dict[str, Any],
) -> None:
    """Serialize and write a JSON-RPC 2.0 response in the requested framing."""
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "content-length":
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        stream.write(header + body)
    else:
        stream.write(body + b"\n")
    stream.flush()


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def _render_report(report: dict[str, Any], fmt: str) -> str:
    if fmt == "markdown":
        return format_markdown_report(report)
    if fmt == "json":
        return json.dumps(report, indent=2, ensure_ascii=False)
    raise ValueError(f"Unsupported format {fmt!r}; expected 'json' or 'markdown'.")


def _parse_inline_or_file(
    inline_value: Any,
    file_path: Any,
    inline_key: str,
    path_key: str,
    default_label: str,
) -> tuple[Any, str]:
    if inline_value is not None:
        data = json.loads(inline_value) if isinstance(inline_value, str) else inline_value
        source_label = str(file_path) if isinstance(file_path, str) and file_path else default_label
        return data, source_label
    if isinstance(file_path, str) and file_path.strip():
        path = Path(file_path)
        return json.loads(path.read_text(encoding="utf-8")), str(path)
    raise ValueError(f"Provide either '{inline_key}' or '{path_key}'.")


def _tool_scan_tools_manifest(arguments: dict[str, Any]) -> dict[str, Any]:
    fmt = arguments.get("format", "json")
    if fmt not in ("json", "markdown"):
        raise ValueError(f"Unsupported format {fmt!r}; expected 'json' or 'markdown'.")

    manifest_json = arguments.get("manifest_json")
    manifest_path = arguments.get("manifest_path")
    if manifest_json is not None:
        data, source_label = _parse_inline_or_file(
            manifest_json, manifest_path, "manifest_json", "manifest_path", "<inline-manifest>"
        )
        tools = parse_tools_manifest_data(data, source_label)
    elif isinstance(manifest_path, str) and manifest_path.strip():
        path = Path(manifest_path)
        tools = load_tools_manifest(path)
        source_label = str(path)
    else:
        raise ValueError("Provide either 'manifest_json' or 'manifest_path'.")

    report = build_manifest_report(tools, source_label)
    return _tool_result(_render_report(report, fmt), is_error=False)


def _tool_audit_client_config(arguments: dict[str, Any]) -> dict[str, Any]:
    fmt = arguments.get("format", "json")
    if fmt not in ("json", "markdown"):
        raise ValueError(f"Unsupported format {fmt!r}; expected 'json' or 'markdown'.")

    data, source_label = _parse_inline_or_file(
        arguments.get("config_json"),
        arguments.get("config_path"),
        "config_json",
        "config_path",
        "<inline-config>",
    )
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in MCP config {source_label}")

    report = build_config_report(data, source_label)
    return _tool_result(_render_report(report, fmt), is_error=False)


def _tool_verify_schema_lock(arguments: dict[str, Any]) -> dict[str, Any]:
    manifest_path = arguments.get("manifest_path")
    lock_path = arguments.get("lock_path")
    if not isinstance(manifest_path, str) or not manifest_path.strip():
        raise ValueError("'manifest_path' must be a non-empty string.")
    if not isinstance(lock_path, str) or not lock_path.strip():
        raise ValueError("'lock_path' must be a non-empty string.")

    _, report = verify_lockfile(Path(manifest_path), Path(lock_path))
    return _tool_result(json.dumps(report, indent=2, ensure_ascii=False), is_error=False)


def _tool_redact_sensitive_text(arguments: dict[str, Any]) -> dict[str, Any]:
    text = arguments.get("text")
    if not isinstance(text, str):
        raise ValueError("'text' must be a string.")
    redacted_text, count = redact_secrets(text)
    payload = {
        "redacted_text": redacted_text,
        "redacted_count": count,
        "rule_id": "MCP-201" if count > 0 else None,
    }
    return _tool_result(json.dumps(payload, indent=2, ensure_ascii=False), is_error=False)


_TOOL_HANDLERS = {
    "scan_tools_manifest": _tool_scan_tools_manifest,
    "audit_client_config": _tool_audit_client_config,
    "verify_schema_lock": _tool_verify_schema_lock,
    "redact_sensitive_text": _tool_redact_sensitive_text,
}


def call_tool(name: str, arguments: Any) -> dict[str, Any]:
    """Execute an MCP tool safely and return a standard MCP tool result."""
    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        return _tool_result(f"Unknown tool: {name}", is_error=True)

    if arguments is None:
        parsed_args: dict[str, Any] = {}
    elif isinstance(arguments, dict):
        parsed_args = arguments
    else:
        return _tool_result("Invalid tool arguments: expected a JSON object.", is_error=True)

    try:
        return handler(parsed_args)
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return _tool_result(f"Error executing {name}: {exc}", is_error=True)


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def handle_jsonrpc_message(raw_text: str) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 request/notification and return response dict or None."""
    try:
        msg = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return _jsonrpc_error(None, -32700, f"Parse error: {exc}")

    if not isinstance(msg, dict):
        return _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object")

    has_id = "id" in msg and msg["id"] is not None
    req_id = msg.get("id")
    method = msg.get("method")

    if not isinstance(method, str) or not method:
        if not has_id:
            return None
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing or invalid 'method'")

    # Notifications (no id, or notifications/*) must never produce a response
    if not has_id or method.startswith("notifications/"):
        return None

    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object")

    if method == "initialize":
        requested_version = params.get("protocolVersion")
        negotiated_version = (
            requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        )
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": negotiated_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mcp-shieldwall", "version": __version__},
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": list(MCP_TOOLS)})

    if method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return _jsonrpc_error(req_id, -32602, "Invalid params: 'name' must be a non-empty string")
        return _jsonrpc_result(req_id, call_tool(tool_name, params.get("arguments")))

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def serve_stdio(
    stdin: Any = None,
    stdout: Any = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the MCP Shieldwall JSON-RPC 2.0 server over stdio until EOF."""
    in_stream = _as_binary_reader(sys.stdin if stdin is None else stdin)
    out_stream = _as_binary_writer(sys.stdout if stdout is None else stdout)
    err_stream = sys.stderr if stderr is None else stderr

    err_stream.write(f"[mcp-shieldwall] MCP stdio server v{__version__} listening...\n")
    err_stream.flush()

    while True:
        try:
            framed = read_framed_message(in_stream)
        except (EOFError, ValueError) as exc:
            err_stream.write(f"[mcp-shieldwall] Framing error: {exc}\n")
            err_stream.flush()
            break

        if framed is None:
            break

        framing, raw_text = framed
        response = handle_jsonrpc_message(raw_text)
        if response is not None:
            write_framed_message(out_stream, framing, response)

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entrypoint for the standalone `mcp-shieldwall-server` script."""
    parser = argparse.ArgumentParser(
        prog="mcp-shieldwall-server",
        description="Run MCP Shieldwall as a native stdio MCP JSON-RPC 2.0 server.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args(sys.argv[1:] if argv is None else argv)
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
