"""GuardianShield MCP Server -- Model Context Protocol interface.

Exposes GuardianShield as an MCP tool server over stdin/stdout JSON-RPC,
allowing any MCP-compatible AI tool (Claude Code, VS Code, Cursor, Windsurf,
OpenSpek, Claude Desktop, etc.) to use security scanning, PII detection,
prompt injection defense, secret detection, and audit logging as first-class
MCP tools.

This module uses **only the Python standard library** (json, sys, logging)
so it introduces zero additional dependencies.

Configuration via environment variables:

    GUARDIANSHIELD_PROFILE      Default safety profile (default: "general").
    GUARDIANSHIELD_AUDIT_PATH   Path to the SQLite audit database.
    GUARDIANSHIELD_DEBUG        Set to "1" for debug logging.

Usage::

    # Run directly:
    python -m guardianshield.mcp_server

    # Or via the installed entry point:
    guardianshield-mcp
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from .core import GuardianShield
from .osv import Dependency
from .profiles import list_profiles

# ---------------------------------------------------------------------------
# Logging -- all output goes to stderr so stdout stays clean for JSON-RPC
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("GUARDIANSHIELD_DEBUG") else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("guardianshield.mcp_server")

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {
    "name": "guardianshield",
    "version": "0.2.0",
}

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_MESSAGE_SIZE = 2_000_000  # 2 MB
MAX_BATCH_SIZE = 50

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_code",
        "description": (
            "Scan source code for security vulnerabilities (SQL injection, XSS, "
            "command injection, path traversal) and hardcoded secrets/credentials. "
            "Returns a list of findings with severity, type, and remediation guidance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The source code to scan.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional file path for context in findings.",
                },
                "language": {
                    "type": "string",
                    "description": "Optional programming language hint.",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "scan_input",
        "description": (
            "Check user or agent input for prompt injection attempts. "
            "Detects instruction override, role hijacking, system prompt "
            "extraction, delimiter abuse, ChatML injection, jailbreak "
            "keywords, and encoding evasion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The input text to check for injection attempts.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "scan_output",
        "description": (
            "Check AI-generated output for PII leaks (email, SSN, credit card, "
            "phone, IP) and content policy violations (violence, self-harm, "
            "illegal activity). PII is automatically redacted in findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The AI output text to scan.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "check_secrets",
        "description": (
            "Dedicated secret and credential detection. Scans text for AWS keys, "
            "GitHub tokens, Stripe keys, private keys, JWTs, Slack tokens, "
            "passwords, connection strings, Google API keys, and more. "
            "All matched secrets are redacted in findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to scan for secrets.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional file path for context.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "get_profile",
        "description": (
            "Get the current safety profile configuration including "
            "scanner settings and blocked content categories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "set_profile",
        "description": (
            "Switch to a different safety profile. Available profiles: "
            "general, education, healthcare, finance, children. "
            "Each profile adjusts scanner sensitivity and blocked categories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Profile name to activate.",
                    "enum": ["general", "education", "healthcare", "finance", "children"],
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "audit_log",
        "description": (
            "Query the security audit log. Returns recent scan events "
            "with timestamps, scan types, finding counts, and input hashes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_type": {
                    "type": "string",
                    "description": "Filter by scan type: code, input, output, secrets.",
                    "enum": ["code", "input", "output", "secrets"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of entries to return (default 50).",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
        },
    },
    {
        "name": "get_findings",
        "description": (
            "Retrieve past security findings from the audit database "
            "with optional filters by type, severity, or audit ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "audit_id": {
                    "type": "integer",
                    "description": "Filter findings by audit log entry ID.",
                },
                "finding_type": {
                    "type": "string",
                    "description": "Filter by finding type (e.g. secret, sql_injection, pii_leak).",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity level.",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum findings to return (default 100).",
                    "minimum": 1,
                    "maximum": 1000,
                },
            },
        },
    },
    {
        "name": "shield_status",
        "description": (
            "Get GuardianShield health and configuration status including "
            "active profile, enabled scanners, and audit statistics."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "scan_file",
        "description": (
            "Scan a single source file for vulnerabilities and secrets. "
            "Auto-detects language from file extension. Returns findings "
            "with line numbers, severity, CWE IDs, and remediation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                },
                "language": {
                    "type": "string",
                    "description": "Optional language hint (auto-detected from extension).",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_directory",
        "description": (
            "Recursively scan a directory for vulnerabilities and secrets. "
            "Supports extension filtering, exclude patterns, and reports "
            "progress. Returns all findings across all scanned files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory to scan.",
                },
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": 'File extensions to include (e.g. [".py", ".js"]).',
                },
                "exclude": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": 'Glob patterns to skip (e.g. ["node_modules/*"]).',
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "test_pattern",
        "description": (
            "Test a regex pattern against sample code. Returns match "
            "details including positions and matched text. Useful for "
            "developing and debugging custom vulnerability patterns."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "regex": {
                    "type": "string",
                    "description": "The regex pattern to test.",
                },
                "sample": {
                    "type": "string",
                    "description": "Sample code to test against.",
                },
                "language": {
                    "type": "string",
                    "description": "Optional language context for the pattern.",
                },
            },
            "required": ["regex", "sample"],
        },
    },
    {
        "name": "check_dependencies",
        "description": (
            "Check package dependencies for known vulnerabilities using "
            "the OSV.dev database. Provide a list of packages with names, "
            "versions, and ecosystems (PyPI or npm)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dependencies": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "version": {"type": "string"},
                            "ecosystem": {
                                "type": "string",
                                "enum": ["PyPI", "npm"],
                                "default": "PyPI",
                            },
                        },
                        "required": ["name", "version"],
                    },
                    "description": "List of dependencies to check.",
                },
            },
            "required": ["dependencies"],
        },
    },
    {
        "name": "sync_vulnerabilities",
        "description": (
            "Sync the local OSV vulnerability database for a given "
            "ecosystem. Call this to update the cache before checking "
            "dependencies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "description": "Ecosystem to sync (PyPI or npm).",
                    "enum": ["PyPI", "npm"],
                },
                "packages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of package names to sync.",
                },
            },
            "required": ["ecosystem"],
        },
    },
]

# ---------------------------------------------------------------------------
# Resource definitions
# ---------------------------------------------------------------------------

RESOURCES: list[dict[str, Any]] = [
    {
        "uri": "guardianshield://profiles",
        "name": "Safety Profiles",
        "description": "List of available safety profiles and their configurations.",
        "mimeType": "application/json",
    },
    {
        "uri": "guardianshield://findings",
        "name": "Recent Findings",
        "description": "Recent security findings from the audit database.",
        "mimeType": "application/json",
    },
    {
        "uri": "guardianshield://config",
        "name": "Current Configuration",
        "description": "Current GuardianShield configuration and status.",
        "mimeType": "application/json",
    },
]

# ---------------------------------------------------------------------------
# Prompt definitions
# ---------------------------------------------------------------------------

PROMPTS: list[dict[str, Any]] = [
    {
        "name": "security-review",
        "description": (
            "Perform a comprehensive security review of code. "
            "Scans for vulnerabilities, secrets, and provides remediation guidance."
        ),
        "arguments": [
            {
                "name": "code",
                "description": "The source code to review.",
                "required": True,
            },
            {
                "name": "file_path",
                "description": "Optional file path for context.",
                "required": False,
            },
        ],
    },
    {
        "name": "compliance-check",
        "description": (
            "Check text for compliance with the active safety profile. "
            "Scans for PII, content violations, and policy adherence."
        ),
        "arguments": [
            {
                "name": "text",
                "description": "The text to check for compliance.",
                "required": True,
            },
        ],
    },
]

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------


class GuardianShieldMCPServer:
    """MCP server wrapping a GuardianShield instance.

    Reads JSON-RPC messages from stdin and writes responses to stdout,
    following the Model Context Protocol specification.
    """

    def __init__(
        self,
        shield: GuardianShield | None = None,
        redact_responses: bool = False,
    ) -> None:
        self._shield: GuardianShield | None = shield
        self._redact = redact_responses
        self._initialized = False
        logger.info("GuardianShieldMCPServer created (shield=%r)", self._shield)

    # ------------------------------------------------------------------
    # Message loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the server's main read-dispatch-write loop."""
        logger.info("MCP server starting, reading from stdin...")

        for raw_line in sys.stdin:
            line = raw_line.strip()
            if len(line) > MAX_MESSAGE_SIZE:
                self._send_error(None, -32600, "Message too large.")
                continue
            if not line:
                continue

            logger.debug("Received: %s", line[:200])

            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                self._send_error(None, -32700, f"Parse error: {exc}")
                continue

            if isinstance(message, list):
                if len(message) > MAX_BATCH_SIZE:
                    self._send_error(
                        None, -32600, f"Batch too large (max {MAX_BATCH_SIZE})."
                    )
                    continue
                for msg in message:
                    self._handle_message(msg)
            else:
                self._handle_message(message)

        logger.info("stdin closed, shutting down.")
        if self._shield is not None:
            self._shield.close()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _handle_message(self, message: dict[str, Any]) -> None:
        if not isinstance(message, dict):
            self._send_error(None, -32600, "Invalid request: expected JSON object.")
            return

        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params", {})

        if method is None:
            self._send_error(msg_id, -32600, "Invalid request: missing 'method'.")
            return

        logger.debug("Dispatching method=%r id=%r", method, msg_id)

        handler = self._get_handler(method)
        if handler is None:
            if msg_id is not None:
                self._send_error(msg_id, -32601, f"Method not found: {method}")
            return

        try:
            result = handler(params)
        except Exception:
            logger.exception("Error handling %s", method)
            self._send_error(msg_id, -32603, "Internal server error.")
            return

        if msg_id is not None:
            self._send_result(msg_id, result)

    def _get_handler(self, method: str) -> Any:
        handlers: dict[str, Any] = {
            "initialize": self._handle_initialize,
            "initialized": self._handle_initialized,
            "notifications/initialized": self._handle_initialized,
            "ping": self._handle_ping,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": self._handle_resources_list,
            "resources/read": self._handle_resources_read,
            "prompts/list": self._handle_prompts_list,
            "prompts/get": self._handle_prompts_get,
        }
        return handlers.get(method)

    # ------------------------------------------------------------------
    # Protocol handlers
    # ------------------------------------------------------------------

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        self._initialized = True

        client_name = params.get("clientInfo", {}).get("name", "unknown")
        logger.info("Client initialized: %s", client_name)

        # Create shield instance from env config.
        if self._shield is not None:
            self._shield.close()

        profile = os.environ.get("GUARDIANSHIELD_PROFILE", "general")
        audit_path = os.environ.get("GUARDIANSHIELD_AUDIT_PATH")
        self._shield = GuardianShield(profile=profile, audit_path=audit_path)

        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {},
            },
            "serverInfo": SERVER_INFO,
        }

    def _handle_initialized(self, params: dict[str, Any]) -> dict[str, Any]:
        logger.debug("Client sent 'initialized' notification.")
        return {}

    def _handle_ping(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _handle_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": TOOLS}

    def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self._initialized:
            return self._tool_error("Server not initialized.")
        if self._shield is None:
            return self._tool_error("GuardianShield not available.")

        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        logger.info("Tool call: %s", tool_name)

        tool_handlers: dict[str, Any] = {
            "scan_code": self._tool_scan_code,
            "scan_input": self._tool_scan_input,
            "scan_output": self._tool_scan_output,
            "check_secrets": self._tool_check_secrets,
            "get_profile": self._tool_get_profile,
            "set_profile": self._tool_set_profile,
            "audit_log": self._tool_audit_log,
            "get_findings": self._tool_get_findings,
            "shield_status": self._tool_shield_status,
            "scan_file": self._tool_scan_file,
            "scan_directory": self._tool_scan_directory,
            "test_pattern": self._tool_test_pattern,
            "check_dependencies": self._tool_check_dependencies,
            "sync_vulnerabilities": self._tool_sync_vulnerabilities,
        }

        handler = tool_handlers.get(tool_name)
        if handler is None:
            return self._tool_error(f"Unknown tool: {tool_name}")

        try:
            return handler(arguments)
        except Exception:
            logger.exception("Tool %s raised an exception", tool_name)
            return self._tool_error(f"Tool '{tool_name}' encountered an error.")

    # ------------------------------------------------------------------
    # Resource handlers
    # ------------------------------------------------------------------

    def _handle_resources_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"resources": RESOURCES}

    def _handle_resources_read(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri", "")

        if uri == "guardianshield://profiles":
            from .profiles import load_profile
            profiles_data = {}
            for name in list_profiles():
                p = load_profile(name)
                profiles_data[name] = p.to_dict()
            content = json.dumps(profiles_data, indent=2)

        elif uri == "guardianshield://findings":
            if self._shield:
                findings = self._shield.get_findings(limit=50)
                content = json.dumps(findings, indent=2)
            else:
                content = json.dumps([])

        elif uri == "guardianshield://config":
            if self._shield:
                content = json.dumps(self._shield.status(), indent=2)
            else:
                content = json.dumps({"error": "Not initialized"})

        else:
            return {
                "error": {
                    "code": -32602,
                    "message": f"Unknown resource: {uri}",
                },
            }

        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": content,
                }
            ],
        }

    # ------------------------------------------------------------------
    # Prompt handlers
    # ------------------------------------------------------------------

    def _handle_prompts_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"prompts": PROMPTS}

    def _handle_prompts_get(self, params: dict[str, Any]) -> dict[str, Any]:
        prompt_name = params.get("name")
        arguments = params.get("arguments", {})

        if prompt_name == "security-review":
            code = arguments.get("code", "")
            file_path = arguments.get("file_path")

            instructions = (
                "Perform a comprehensive security review of the following code. "
                "Use the scan_code tool to detect vulnerabilities and secrets, "
                "then provide a summary with remediation guidance.\n\n"
            )
            if file_path:
                instructions += f"File: {file_path}\n\n"
            instructions += f"```\n{code}\n```"

            return {
                "description": "Comprehensive security review",
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": instructions},
                    }
                ],
            }

        elif prompt_name == "compliance-check":
            text = arguments.get("text", "")
            instructions = (
                "Check the following text for compliance with the active "
                "safety profile. Use scan_output to detect PII leaks and "
                "content violations, then summarize findings.\n\n"
                f"Text to check:\n{text}"
            )
            return {
                "description": "Compliance check against active safety profile",
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": instructions},
                    }
                ],
            }

        else:
            return {
                "error": {
                    "code": -32602,
                    "message": f"Unknown prompt: {prompt_name}",
                },
            }

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def _tool_scan_code(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        code = args.get("code")
        if not code or not isinstance(code, str):
            return self._tool_error("'code' is required.")

        file_path = args.get("file_path")
        language = args.get("language")

        findings = self._shield.scan_code(code, file_path=file_path, language=language)
        result = {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_scan_input(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        text = args.get("text")
        if not text or not isinstance(text, str):
            return self._tool_error("'text' is required.")

        findings = self._shield.scan_input(text)
        result = {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_scan_output(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        text = args.get("text")
        if not text or not isinstance(text, str):
            return self._tool_error("'text' is required.")

        findings = self._shield.scan_output(text)
        result = {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_check_secrets(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        text = args.get("text")
        if not text or not isinstance(text, str):
            return self._tool_error("'text' is required.")

        file_path = args.get("file_path")
        findings = self._shield.check_secrets(text, file_path=file_path)
        result = {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_get_profile(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        profile = self._shield.profile
        result = {
            "profile": profile.to_dict(),
            "available_profiles": list_profiles(),
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_set_profile(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        name = args.get("name")
        if not name or not isinstance(name, str):
            return self._tool_error("'name' is required.")

        try:
            profile = self._shield.set_profile(name)
        except ValueError as exc:
            return self._tool_error(str(exc))

        result = {
            "message": f"Profile switched to '{name}'.",
            "profile": profile.to_dict(),
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_audit_log(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        scan_type = args.get("scan_type")
        limit = args.get("limit", 50)

        entries = self._shield.get_audit_log(scan_type=scan_type, limit=limit)
        result = {
            "count": len(entries),
            "entries": entries,
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_get_findings(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        audit_id = args.get("audit_id")
        finding_type = args.get("finding_type")
        severity = args.get("severity")
        limit = args.get("limit", 100)

        findings = self._shield.get_findings(
            audit_id=audit_id,
            finding_type=finding_type,
            severity=severity,
            limit=limit,
        )
        result = {
            "count": len(findings),
            "findings": findings,
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_shield_status(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        status = self._shield.status()
        status["version"] = SERVER_INFO["version"]
        # Include OSV cache stats if available.
        if self._shield._osv_cache is not None:
            try:
                status["osv_cache"] = self._shield.osv_cache.stats()
            except Exception:
                status["osv_cache"] = {"error": "unavailable"}
        status["capabilities"] = [
            "scan_code", "scan_input", "scan_output", "check_secrets",
            "scan_file", "scan_directory", "test_pattern",
            "check_dependencies", "sync_vulnerabilities",
        ]
        return self._tool_success(json.dumps(status, indent=2))

    def _tool_scan_file(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        path = args.get("path")
        if not path or not isinstance(path, str):
            return self._tool_error("'path' is required.")

        language = args.get("language")
        try:
            findings = self._shield.scan_file(path, language=language)
        except FileNotFoundError:
            return self._tool_error(f"File not found: {path}")
        except IsADirectoryError:
            return self._tool_error(f"Path is a directory: {path}")

        result = {
            "file": path,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_scan_directory(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        path = args.get("path")
        if not path or not isinstance(path, str):
            return self._tool_error("'path' is required.")

        extensions = args.get("extensions")
        exclude = args.get("exclude")

        def _on_progress(fpath: str, done: int, total: int) -> None:
            self._send_notification(
                "guardianshield/scanProgress",
                {"file": fpath, "done": done, "total": total},
            )

        def _on_finding(f: Any) -> None:
            self._send_notification(
                "guardianshield/finding",
                {"finding": f.to_dict()},
            )

        try:
            findings = self._shield.scan_directory(
                path,
                extensions=extensions,
                exclude=exclude,
                on_progress=_on_progress,
                on_finding=_on_finding,
            )
        except NotADirectoryError:
            return self._tool_error(f"Not a directory: {path}")

        result = {
            "directory": path,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_test_pattern(self, args: dict[str, Any]) -> dict[str, Any]:
        import re as _re

        regex = args.get("regex")
        sample = args.get("sample")
        if not regex or not isinstance(regex, str):
            return self._tool_error("'regex' is required.")
        if not sample or not isinstance(sample, str):
            return self._tool_error("'sample' is required.")

        language = args.get("language", "")

        try:
            compiled = _re.compile(regex)
        except _re.error as exc:
            return self._tool_error(f"Invalid regex: {exc}")

        matches = []
        for line_number, line in enumerate(sample.splitlines(), start=1):
            for m in compiled.finditer(line):
                matches.append({
                    "line": line_number,
                    "start": m.start(),
                    "end": m.end(),
                    "text": m.group(0),
                    "groups": list(m.groups()),
                })

        result = {
            "regex": regex,
            "language": language,
            "match_count": len(matches),
            "matches": matches,
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_check_dependencies(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        deps_raw = args.get("dependencies")
        if not deps_raw or not isinstance(deps_raw, list):
            return self._tool_error("'dependencies' is required.")

        deps = []
        for d in deps_raw:
            name = d.get("name")
            version = d.get("version")
            if not name or not version:
                return self._tool_error("Each dependency needs 'name' and 'version'.")
            ecosystem = d.get("ecosystem", "PyPI")
            deps.append(Dependency(name=name, version=version, ecosystem=ecosystem))

        findings = self._shield.check_dependencies(deps)
        result = {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in self._maybe_redact(findings)],
        }
        return self._tool_success(json.dumps(result, indent=2))

    def _tool_sync_vulnerabilities(self, args: dict[str, Any]) -> dict[str, Any]:
        assert self._shield is not None
        ecosystem = args.get("ecosystem")
        if not ecosystem or not isinstance(ecosystem, str):
            return self._tool_error("'ecosystem' is required.")

        packages = args.get("packages")
        cache = self._shield.osv_cache

        try:
            cache.sync(
                ecosystem=ecosystem,
                packages=packages,
            )
        except Exception as exc:
            return self._tool_error(f"Sync failed: {exc}")

        stats = cache.stats()
        result = {
            "message": f"Synced {ecosystem} vulnerabilities.",
            "stats": stats,
        }
        return self._tool_success(json.dumps(result, indent=2))

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------

    def _maybe_redact(self, findings: list) -> list:
        """Optionally redact matched_text in findings."""
        if not self._redact:
            return findings
        import hashlib as _hl
        for f in findings:
            if f.matched_text:
                h = _hl.sha256(f.matched_text.encode("utf-8")).hexdigest()[:12]
                f.matched_text = f"[REDACTED:{h}]"
        return findings

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tool_success(text: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": text}],
        }

    @staticmethod
    def _tool_error(message: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": message})}],
            "isError": True,
        }

    def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        notification = {
            "jsonrpc": JSONRPC_VERSION,
            "method": method,
            "params": params,
        }
        self._write_message(notification)

    def _send_result(self, msg_id: Any, result: Any) -> None:
        response = {
            "jsonrpc": JSONRPC_VERSION,
            "id": msg_id,
            "result": result,
        }
        self._write_message(response)

    def _send_error(
        self, msg_id: Any, code: int, message: str, data: Any = None
    ) -> None:
        error_obj: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error_obj["data"] = data
        response: dict[str, Any] = {
            "jsonrpc": JSONRPC_VERSION,
            "id": msg_id,
            "error": error_obj,
        }
        self._write_message(response)

    @staticmethod
    def _write_message(message: dict[str, Any]) -> None:
        line = json.dumps(message, ensure_ascii=False)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the GuardianShield MCP server."""
    logger.info("Starting GuardianShield MCP server...")
    logger.info(
        "Config: GUARDIANSHIELD_PROFILE=%r",
        os.environ.get("GUARDIANSHIELD_PROFILE", "general"),
    )

    try:
        server = GuardianShieldMCPServer()
        server.run()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user.")
        sys.exit(0)
    except Exception:
        logger.exception("Fatal error in MCP server.")
        sys.exit(1)


if __name__ == "__main__":
    main()
