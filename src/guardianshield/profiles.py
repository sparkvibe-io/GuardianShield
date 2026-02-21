"""Safety profiles for GuardianShield.

Defines :class:`ScannerConfig` and :class:`SafetyProfile` dataclasses, five
built-in profiles, and helpers for loading profiles from YAML files or the
built-in registry.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

# PyYAML is optional -- fall back gracefully when unavailable.
try:
    import yaml  # type: ignore[import-untyped]

    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False

# Directory that contains the bundled YAML profile files.
_PROFILES_DIR = Path(__file__).resolve().parent / "profiles"


# ---------------------------------------------------------------------------
# ScannerConfig
# ---------------------------------------------------------------------------


@dataclass
class ScannerConfig:
    """Configuration for an individual scanner.

    Attributes:
        enabled: Whether the scanner is active.
        sensitivity: Detection sensitivity -- ``"low"``, ``"medium"``, or ``"high"``.
        custom_patterns: Extra regex patterns the scanner should check.
    """

    enabled: bool = True
    sensitivity: str = "medium"
    custom_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "enabled": self.enabled,
            "sensitivity": self.sensitivity,
            "custom_patterns": list(self.custom_patterns),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScannerConfig":
        """Deserialize from a plain dict."""
        return cls(
            enabled=data.get("enabled", True),
            sensitivity=data.get("sensitivity", "medium"),
            custom_patterns=list(data.get("custom_patterns", [])),
        )


# ---------------------------------------------------------------------------
# SafetyProfile
# ---------------------------------------------------------------------------


@dataclass
class SafetyProfile:
    """A named bundle of scanner configurations and content policies.

    Attributes:
        name: Short identifier for the profile.
        description: Human-readable description of the profile's purpose.
        code_scanner: Configuration for the code scanner.
        secret_scanner: Configuration for the secret scanner.
        injection_detector: Configuration for the prompt-injection detector.
        pii_detector: Configuration for the PII detector.
        content_moderator: Configuration for the content moderator.
        blocked_categories: Content categories that should be blocked outright.
    """

    name: str
    description: str
    code_scanner: ScannerConfig = field(default_factory=ScannerConfig)
    secret_scanner: ScannerConfig = field(default_factory=ScannerConfig)
    injection_detector: ScannerConfig = field(default_factory=ScannerConfig)
    pii_detector: ScannerConfig = field(default_factory=ScannerConfig)
    content_moderator: ScannerConfig = field(default_factory=ScannerConfig)
    blocked_categories: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "name": self.name,
            "description": self.description,
            "code_scanner": self.code_scanner.to_dict(),
            "secret_scanner": self.secret_scanner.to_dict(),
            "injection_detector": self.injection_detector.to_dict(),
            "pii_detector": self.pii_detector.to_dict(),
            "content_moderator": self.content_moderator.to_dict(),
            "blocked_categories": list(self.blocked_categories),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SafetyProfile":
        """Deserialize from a plain dict."""
        return cls(
            name=data["name"],
            description=data["description"],
            code_scanner=ScannerConfig.from_dict(data.get("code_scanner", {})),
            secret_scanner=ScannerConfig.from_dict(data.get("secret_scanner", {})),
            injection_detector=ScannerConfig.from_dict(data.get("injection_detector", {})),
            pii_detector=ScannerConfig.from_dict(data.get("pii_detector", {})),
            content_moderator=ScannerConfig.from_dict(data.get("content_moderator", {})),
            blocked_categories=list(data.get("blocked_categories", [])),
        )


# ---------------------------------------------------------------------------
# Built-in profiles (plain dicts)
# ---------------------------------------------------------------------------

BUILTIN_PROFILES: Dict[str, Dict[str, Any]] = {
    "general": {
        "name": "general",
        "description": "General-purpose safety profile with medium sensitivity across all scanners.",
        "code_scanner": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "secret_scanner": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "injection_detector": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "pii_detector": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "content_moderator": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "blocked_categories": [],
    },
    "education": {
        "name": "education",
        "description": "Safety profile for educational platforms, blocking violence and self-harm content.",
        "code_scanner": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "secret_scanner": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "injection_detector": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "pii_detector": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "content_moderator": {"enabled": True, "sensitivity": "medium", "custom_patterns": []},
        "blocked_categories": ["violence", "self_harm"],
    },
    "healthcare": {
        "name": "healthcare",
        "description": "Safety profile for healthcare applications with high sensitivity on all scanners and strict PII protection.",
        "code_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "secret_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "injection_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "pii_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "content_moderator": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "blocked_categories": ["violence"],
    },
    "finance": {
        "name": "finance",
        "description": "Safety profile for financial applications with high sensitivity and critical secret detection.",
        "code_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "secret_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "injection_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "pii_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "content_moderator": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "blocked_categories": ["illegal_activity"],
    },
    "children": {
        "name": "children",
        "description": "Safety profile for child-facing applications with maximum sensitivity and broad content blocking.",
        "code_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "secret_scanner": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "injection_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "pii_detector": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "content_moderator": {"enabled": True, "sensitivity": "high", "custom_patterns": []},
        "blocked_categories": ["violence", "self_harm", "illegal_activity"],
    },
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def load_profile(name: str) -> SafetyProfile:
    """Load a safety profile by *name*.

    Resolution order:

    1. If PyYAML is available, look for ``<name>.yaml`` in the bundled
       ``profiles/`` directory.
    2. Fall back to the :data:`BUILTIN_PROFILES` dict.

    Raises:
        ValueError: If *name* is not a known profile.
    """
    # Try YAML file first.
    if _HAS_YAML:
        yaml_path = _PROFILES_DIR / f"{name}.yaml"
        if yaml_path.is_file():
            with open(yaml_path, "r", encoding="utf-8") as fh:
                data: Dict[str, Any] = yaml.safe_load(fh)
            return SafetyProfile.from_dict(data)

    # Fall back to built-in dict.
    if name in BUILTIN_PROFILES:
        return SafetyProfile.from_dict(BUILTIN_PROFILES[name])

    available = ", ".join(sorted(list_profiles()))
    raise ValueError(
        f"Unknown safety profile {name!r}. Available profiles: {available}"
    )


def list_profiles() -> List[str]:
    """Return a sorted list of all available profile names.

    Merges names found in the YAML ``profiles/`` directory (if readable)
    with the built-in profile keys.
    """
    names: set[str] = set(BUILTIN_PROFILES.keys())

    if _PROFILES_DIR.is_dir():
        for entry in os.listdir(_PROFILES_DIR):
            if entry.endswith(".yaml"):
                names.add(entry.removesuffix(".yaml"))

    return sorted(names)
