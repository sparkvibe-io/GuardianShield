"""Core orchestrator for GuardianShield.

Ties together all scanner modules, profiles, and the audit log into a
single :class:`GuardianShield` façade.  Each scan method checks the
active profile configuration, calls the relevant scanner(s), logs results
to the audit database, and returns a list of findings.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from .audit import AuditLog
from .content import check_content
from .findings import Finding
from .injection import check_injection
from .pii import check_pii
from .profiles import SafetyProfile, load_profile, list_profiles
from .scanner import scan_code as _scan_code
from .secrets import check_secrets


class GuardianShield:
    """Main orchestrator that delegates to individual scanners.

    Args:
        profile: Name of the safety profile to activate (default ``"general"``).
        audit_path: Path to the SQLite audit database.  ``None`` uses the
            default ``~/.guardianshield/audit.db``.
    """

    def __init__(
        self,
        profile: str = "general",
        audit_path: Optional[str] = None,
    ) -> None:
        self._profile = load_profile(profile)
        self._audit = AuditLog(db_path=audit_path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_input(text: str) -> str:
        """Return a truncated SHA-256 hex digest of *text*.

        Only the first 16 characters are kept so the audit log never
        stores raw user input.
        """
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _log(
        self,
        scan_type: str,
        text: str,
        findings: list[Finding],
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Persist a scan event to the audit log."""
        self._audit.log_scan(
            scan_type=scan_type,
            profile=self._profile.name,
            input_hash=self._hash_input(text),
            findings=findings,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @property
    def profile(self) -> SafetyProfile:
        """Return the active safety profile."""
        return self._profile

    def set_profile(self, name: str) -> SafetyProfile:
        """Switch to a different safety profile.

        Args:
            name: One of the built-in profile names or a custom YAML profile.

        Returns:
            The newly-activated :class:`SafetyProfile`.

        Raises:
            ValueError: If the profile is unknown.
        """
        self._profile = load_profile(name)
        return self._profile

    # ------------------------------------------------------------------
    # Scan methods
    # ------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> list[Finding]:
        """Scan source code for vulnerabilities and hardcoded secrets.

        Combines the code vulnerability scanner and the secret detector.
        """
        findings: list[Finding] = []

        cfg = self._profile.code_scanner
        if cfg.enabled:
            findings.extend(
                _scan_code(
                    code,
                    sensitivity=cfg.sensitivity,
                    file_path=file_path,
                    language=language,
                )
            )

        sec_cfg = self._profile.secret_scanner
        if sec_cfg.enabled:
            findings.extend(
                check_secrets(
                    code,
                    sensitivity=sec_cfg.sensitivity,
                    file_path=file_path,
                )
            )

        self._log("code", code, findings, {"file_path": file_path})
        return findings

    def scan_input(self, text: str) -> list[Finding]:
        """Check user/agent input for prompt injection attempts."""
        findings: list[Finding] = []

        cfg = self._profile.injection_detector
        if cfg.enabled:
            findings.extend(
                check_injection(text, sensitivity=cfg.sensitivity)
            )

        self._log("input", text, findings)
        return findings

    def scan_output(self, text: str) -> list[Finding]:
        """Check AI output for PII leaks and content violations."""
        findings: list[Finding] = []

        pii_cfg = self._profile.pii_detector
        if pii_cfg.enabled:
            findings.extend(
                check_pii(text, sensitivity=pii_cfg.sensitivity)
            )

        content_cfg = self._profile.content_moderator
        if content_cfg.enabled:
            findings.extend(
                check_content(
                    text,
                    sensitivity=content_cfg.sensitivity,
                    blocked_categories=self._profile.blocked_categories or None,
                )
            )

        self._log("output", text, findings)
        return findings

    def check_secrets(
        self,
        text: str,
        file_path: Optional[str] = None,
    ) -> list[Finding]:
        """Dedicated secret detection scan."""
        findings: list[Finding] = []

        cfg = self._profile.secret_scanner
        if cfg.enabled:
            findings.extend(
                check_secrets(
                    text,
                    sensitivity=cfg.sensitivity,
                    file_path=file_path,
                )
            )

        self._log("secrets", text, findings, {"file_path": file_path})
        return findings

    # ------------------------------------------------------------------
    # Audit / status
    # ------------------------------------------------------------------

    def get_audit_log(
        self,
        scan_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query the audit log."""
        return self._audit.query_log(
            scan_type=scan_type, limit=limit, offset=offset
        )

    def get_findings(
        self,
        audit_id: Optional[int] = None,
        finding_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve past findings from the audit database."""
        return self._audit.get_findings(
            audit_id=audit_id,
            finding_type=finding_type,
            severity=severity,
            limit=limit,
        )

    def status(self) -> dict[str, Any]:
        """Return health / configuration information."""
        stats = self._audit.stats()
        return {
            "version": "0.1.0",
            "profile": self._profile.name,
            "available_profiles": list_profiles(),
            "scanners": {
                "code_scanner": self._profile.code_scanner.enabled,
                "secret_scanner": self._profile.secret_scanner.enabled,
                "injection_detector": self._profile.injection_detector.enabled,
                "pii_detector": self._profile.pii_detector.enabled,
                "content_moderator": self._profile.content_moderator.enabled,
            },
            "audit": stats,
        }

    def close(self) -> None:
        """Close the audit database connection."""
        self._audit.close()
