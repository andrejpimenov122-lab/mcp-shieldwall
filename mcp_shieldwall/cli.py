"""CLI, lockfile verification, config auditor, and JSON-RPC firewall for MCP Shieldwall."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .rules import (
    RULE_METADATA,
    audit_mcp_config,
    redact_secrets,
    scan_tool_call,
    scan_tool_definitions,
)

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _canonical_sha256(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_schema_pin(tools: list[dict[str, Any]]) -> str:
    """Compute a deterministic SHA-256 fingerprint to detect MCP rug-pull updates."""
    canonical = json.dumps(sorted(tools, key=lambda t: str(t.get("name", ""))), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_tools_manifest(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [t for t in data if isinstance(t, dict)]
    if isinstance(data, dict):
        if ("mcpServers" in data or "servers" in data) and "tools" not in data:
            raise ValueError(
                f"{path} is an MCP client config (mcpServers/servers), not a tools/list manifest. "
                f"Run `mcp-shieldwall audit-config {path}` instead (refusing false-clean pass)."
            )
        if "tools" in data and isinstance(data["tools"], list):
            return [t for t in data["tools"] if isinstance(t, dict)]
    raise ValueError(f"Unsupported MCP tools manifest structure in {path}")


def audit_manifest_file(path: Path) -> tuple[int, dict[str, Any]]:
    tools = load_tools_manifest(path)
    findings = scan_tool_definitions(tools)
    report = {
        "file": str(path),
        "tools_scanned": len(tools),
        "schema_sha256": compute_schema_pin(tools),
        "findings": [f.__dict__ for f in findings],
        "passed": len(findings) == 0,
    }
    return (0 if not findings else 2), report


def format_sarif_report(report: dict[str, Any]) -> dict[str, Any]:
    """Convert an audit report into SARIF v2.1.0 format for CI and code scanning."""
    findings = report.get("findings", [])
    artifact_uri = str(report.get("file", "manifest.json"))

    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("rule_id", "MCP-000"))
        severity = str(finding.get("severity", "HIGH")).upper()
        level = _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")

        if rule_id not in seen_rules:
            meta = RULE_METADATA.get(rule_id, {})
            seen_rules[rule_id] = {
                "id": rule_id,
                "name": meta.get("name", rule_id),
                "shortDescription": {"text": meta.get("shortDescription", str(finding.get("message", rule_id)))},
                "defaultConfiguration": {"level": level},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{finding.get('message', '')} (target={finding.get('target', '')}, evidence={finding.get('evidence', '')})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                        }
                    }
                ],
                "properties": {
                    "severity": severity,
                    "target": finding.get("target", ""),
                    "evidence": finding.get("evidence", ""),
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-shieldwall",
                        "version": __version__,
                        "informationUri": "https://pypi.org/project/mcp-shieldwall/",
                        "rules": [seen_rules[k] for k in sorted(seen_rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def _build_tool_fingerprints(tools: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    fingerprints: dict[str, dict[str, str]] = {}
    for tool in sorted(tools, key=lambda t: str(t.get("name", ""))):
        name = str(tool.get("name", "<unnamed>"))
        fingerprints[name] = {
            "sha256": _canonical_sha256(tool),
            "description_sha256": _canonical_sha256(str(tool.get("description", ""))),
            "input_schema_sha256": _canonical_sha256(tool.get("inputSchema", {})),
        }
    return fingerprints


def create_lockfile(manifest_path: Path, out_path: Path) -> dict[str, Any]:
    """Generate a deterministic .mcp-lock.json fingerprint for an MCP tools manifest."""
    tools = load_tools_manifest(manifest_path)
    lock_payload = {
        "lockfile_version": 1,
        "shieldwall_version": __version__,
        "source_manifest": str(manifest_path),
        "tool_count": len(tools),
        "manifest_sha256": compute_schema_pin(tools),
        "tools": _build_tool_fingerprints(tools),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(lock_payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return lock_payload


def verify_lockfile(manifest_path: Path, lock_path: Path) -> tuple[int, dict[str, Any]]:
    """Verify an MCP tools manifest against a committed lockfile to catch rug-pull changes."""
    tools = load_tools_manifest(manifest_path)
    lock_data = json.loads(lock_path.read_text(encoding="utf-8"))

    expected_sha = str(lock_data.get("manifest_sha256", ""))
    actual_sha = compute_schema_pin(tools)
    expected_tools = lock_data.get("tools", {})
    if not isinstance(expected_tools, dict):
        expected_tools = {}
    actual_tools = _build_tool_fingerprints(tools)

    added = sorted(name for name in actual_tools if name not in expected_tools)
    removed = sorted(name for name in expected_tools if name not in actual_tools)
    modified: list[dict[str, Any]] = []

    for name in sorted(set(actual_tools) & set(expected_tools)):
        exp_entry = expected_tools[name]
        act_entry = actual_tools[name]
        if act_entry.get("sha256") != exp_entry.get("sha256"):
            changed_fields: list[str] = []
            if act_entry.get("description_sha256") != exp_entry.get("description_sha256"):
                changed_fields.append("description")
            if act_entry.get("input_schema_sha256") != exp_entry.get("input_schema_sha256"):
                changed_fields.append("inputSchema")
            if not changed_fields:
                changed_fields.append("metadata")
            modified.append(
                {
                    "tool": name,
                    "changed_fields": changed_fields,
                    "expected_sha256": exp_entry.get("sha256"),
                    "actual_sha256": act_entry.get("sha256"),
                }
            )

    passed = (actual_sha == expected_sha) and not added and not removed and not modified
    report = {
        "manifest": str(manifest_path),
        "lockfile": str(lock_path),
        "passed": passed,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "added": added,
        "removed": removed,
        "modified": modified,
    }
    return (0 if passed else 2), report


def audit_config_file(path: Path) -> tuple[int, dict[str, Any]]:
    """Audit a Claude Desktop / Cursor / VS Code MCP client config file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in MCP config {path}")

    server_count = 0
    for key in ("mcpServers", "servers"):
        section = data.get(key)
        if isinstance(section, dict):
            server_count += len(section)

    findings = audit_mcp_config(data)
    report = {
        "file": str(path),
        "servers_audited": server_count,
        "findings": [f.__dict__ for f in findings],
        "passed": len(findings) == 0,
    }
    return (0 if not findings else 2), report


def inspect_rpc_message(raw_line: str) -> tuple[bool, str, list[dict[str, Any]]]:
    """Inspect a single JSON-RPC 2.0 MCP message; block poisoned calls and redact secrets."""
    msg = json.loads(raw_line)
    alerts: list[dict[str, Any]] = []

    if msg.get("method") == "tools/call":
        params = msg.get("params", {})
        findings = scan_tool_call(str(params.get("name", "")), params.get("arguments", {}))
        if findings:
            return False, raw_line, [f.__dict__ for f in findings]

    result = msg.get("result")
    if isinstance(result, dict) and "tools" in result and isinstance(result["tools"], list):
        findings = scan_tool_definitions(result["tools"])
        if findings:
            alerts.extend(f.__dict__ for f in findings)

    serialized = json.dumps(msg, ensure_ascii=False)
    redacted_str, count = redact_secrets(serialized)
    if count > 0:
        alerts.append({"severity": "HIGH", "rule_id": "MCP-201", "redacted_secrets": count})
    return True, redacted_str, alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-shieldwall",
        description="Zero-dependency security firewall, lockfile verifier & config auditor for MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Audit an MCP tools JSON manifest for tool poisoning")
    scan_p.add_argument("manifest", type=Path, help="Path to JSON file containing MCP tools")
    scan_p.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Output format (default: json)",
    )

    lock_p = sub.add_parser("lock", help="Pin MCP tool definitions to a deterministic lockfile")
    lock_p.add_argument("manifest", type=Path, help="Path to JSON file containing MCP tools")
    lock_p.add_argument(
        "--out",
        "-o",
        type=Path,
        default=Path(".mcp-lock.json"),
        help="Output lockfile path (default: .mcp-lock.json)",
    )

    verify_p = sub.add_parser("verify-lock", help="Verify MCP tools manifest against a lockfile in CI")
    verify_p.add_argument("manifest", type=Path, help="Path to JSON file containing MCP tools")
    verify_p.add_argument(
        "--lock",
        "-l",
        type=Path,
        default=Path(".mcp-lock.json"),
        help="Path to existing lockfile (default: .mcp-lock.json)",
    )

    cfg_p = sub.add_parser(
        "audit-config",
        help="Audit claude_desktop_config.json or cursor mcp.json for unsafe flags, hardcoded tokens, and unpinned npx",
    )
    cfg_p.add_argument("config", type=Path, help="Path to MCP client configuration JSON")
    cfg_p.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Output format (default: json)",
    )

    redact_p = sub.add_parser("redact", help="Redact leaked secrets from stdin or a text file")
    redact_p.add_argument("file", nargs="?", type=Path, help="Optional file path (defaults to stdin)")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "scan":
            code, report = audit_manifest_file(args.manifest)
            output = format_sarif_report(report) if args.format == "sarif" else report
            print(json.dumps(output, indent=2, ensure_ascii=False))
            return code

        if args.cmd == "lock":
            lock_payload = create_lockfile(args.manifest, args.out)
            summary = {
                "status": "locked",
                "lockfile": str(args.out),
                "tool_count": lock_payload["tool_count"],
                "manifest_sha256": lock_payload["manifest_sha256"],
            }
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "verify-lock":
            code, report = verify_lockfile(args.manifest, args.lock)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return code

        if args.cmd == "audit-config":
            code, report = audit_config_file(args.config)
            output = format_sarif_report(report) if args.format == "sarif" else report
            print(json.dumps(output, indent=2, ensure_ascii=False))
            return code

        if args.cmd == "redact":
            text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
            cleaned, count = redact_secrets(text)
            print(cleaned)
            sys.stderr.write(f"[mcp-shieldwall] Redacted {count} secret(s).\n")
            return 0
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        sys.stderr.write(f"[mcp-shieldwall] Error: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
