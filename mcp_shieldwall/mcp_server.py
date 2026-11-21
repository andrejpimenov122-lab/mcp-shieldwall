"""Zero-dependency native stdio MCP (Model Context Protocol) JSON-RPC 2.0 server."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from . import __version__
from .cli import (
    build_config_report,
    build_manifest_report,
    format_markdown_report,
    parse_tools_manifest_data,
    verify_schema_lock,
)
from .rules import redact_secrets

SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
STRUCTURED_PROTOCOL_VERSIONS = SUPPORTED_PROTOCOL_VERSIONS[:2]
MAX_JSON_BYTES = 2 * 1024 * 1024
READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

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


def _render_report(report: dict[str, Any], fmt: str) -> dict[str, Any]:
    if fmt == "markdown":
        text = format_markdown_report(report)
    elif fmt == "json":
        text = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        raise ValueError("Expected 'json' or 'markdown' output format.")
    return {**_tool_result(text), "structuredContent": report}


def _read_sandboxed_json(value: Any) -> tuple[Any, str]:
    """Load a bounded JSON regular file below the home or working directory."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Expected a non-empty local JSON path.")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value) and not Path(value).drive:
        raise ValueError("File sandbox rejects URL schemes.")
    path = Path(value).expanduser().resolve(strict=True)
    if not any(path.is_relative_to(root.resolve()) for root in (Path.home(), Path.cwd())):
        raise ValueError("File sandbox rejects paths outside the allowed roots (home and working directory).")
    if path.suffix.lower() != ".json":
        raise ValueError("File sandbox requires a .json file.")
    if not path.is_file():
        raise ValueError("File sandbox requires a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("File sandbox requires a regular file.")
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("File sandbox rejects files larger than 2 MiB.")
    return json.loads(raw), str(path)


def _parse_inline_or_file(
    inline_value: Any,
    file_path: Any,
    inline_key: str,
    path_key: str,
    default_label: str,
) -> tuple[Any, str]:
    if (inline_value is None) == (file_path is None):
        raise ValueError(f"Provide exactly one of '{inline_key}' or '{path_key}'.")
    if inline_value is not None:
        data = json.loads(inline_value) if isinstance(inline_value, str) else inline_value
        return data, default_label
    return _read_sandboxed_json(file_path)


def _tool_scan_tools_manifest(arguments: dict[str, Any]) -> dict[str, Any]:
    fmt = arguments.get("format", "json")
    if fmt not in ("json", "markdown"):
        raise ValueError(f"Unsupported format {fmt!r}; expected 'json' or 'markdown'.")

    data, source_label = _parse_inline_or_file(
        arguments.get("manifest_json"), arguments.get("manifest_path"),
        "manifest_json", "manifest_path", "<inline-manifest>",
    )
    tools = parse_tools_manifest_data(data, source_label)
    report = build_manifest_report(tools, source_label)
    return _render_report(report, fmt)


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
    return _render_report(report, fmt)


def _tool_verify_schema_lock(arguments: dict[str, Any]) -> dict[str, Any]:
    data, manifest_path = _read_sandboxed_json(arguments.get("manifest_path"))
    lock, lock_path = _read_sandboxed_json(arguments.get("lock_path"))
    tools = parse_tools_manifest_data(data, manifest_path)
    _, report = verify_schema_lock(tools, lock, manifest_path, lock_path)
    return _render_report(report, "json")


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
    return _render_report(payload, "json")


_TOOL_HANDLERS = {
    "scan_tools_manifest": _tool_scan_tools_manifest,
    "audit_client_config": _tool_audit_client_config,
    "verify_schema_lock": _tool_verify_schema_lock,
    "redact_sensitive_text": _tool_redact_sensitive_text,
}


def call_tool(name: str, arguments: Any, *, structured: bool = False) -> dict[str, Any]:
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

    tool = next(tool for tool in MCP_TOOLS if tool["name"] == name)
    unknown = parsed_args.keys() - tool["inputSchema"]["properties"].keys()
    if unknown:
        return _tool_result("Unexpected argument keys.", is_error=True)
    try:
        result = handler(parsed_args)
    except (OSError, RuntimeError) as exc:
        return _tool_result(f"File sandbox could not read the requested JSON file ({type(exc).__name__}).", is_error=True)
    except (UnicodeError, json.JSONDecodeError):
        return _tool_result("Invalid UTF-8 or JSON input.", is_error=True)
    except (ValueError, TypeError) as exc:
        return _tool_result(f"Error executing {name}: {exc}", is_error=True)
    if not structured:
        result.pop("structuredContent", None)
    return result


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


def handle_jsonrpc_message(
    raw_text: str, session: dict[str, str] | None = None
) -> dict[str, Any] | None:
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
    if msg.get("jsonrpc") != "2.0":
        return _jsonrpc_error(req_id, -32600, "Invalid Request: expected JSON-RPC 2.0")

    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object")

    if method == "initialize":
        if session is not None and "protocol" in session:
            return _jsonrpc_error(req_id, -32600, "Server already initialized")
        requested_version = params.get("protocolVersion")
        negotiated_version = (
            requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        )
        if session is not None:
            session["protocol"] = negotiated_version
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

    if session is not None and "protocol" not in session:
        return _jsonrpc_error(req_id, -32600, "Server not initialized")
    protocol = session.get("protocol") if session is not None else DEFAULT_PROTOCOL_VERSION
    structured = protocol in STRUCTURED_PROTOCOL_VERSIONS
    if method == "tools/list":
        tools = [{**tool, "annotations": READ_ONLY_ANNOTATIONS} for tool in MCP_TOOLS]
        if structured:
            for tool in tools:
                tool["outputSchema"] = {"type": "object"}
        return _jsonrpc_result(req_id, {"tools": tools})

    if method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or tool_name not in _TOOL_HANDLERS:
            return _jsonrpc_error(req_id, -32602, "Invalid params: unknown tool")
        return _jsonrpc_result(req_id, call_tool(tool_name, params.get("arguments"), structured=structured))

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
    session: dict[str, str] = {}

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
        response = handle_jsonrpc_message(raw_text, session)
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
