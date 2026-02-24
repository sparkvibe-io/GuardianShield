"""Project configuration discovery.

Discovers and loads ``.guardianshield.json`` or ``.guardianshield.yaml`` files
from the project directory tree, allowing per-project scanner customization.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProjectConfig:
    """Per-project GuardianShield configuration.

    Attributes:
        profile: Name of the safety profile to use.
        severity_overrides: Map of pattern_name -> severity override.
        exclude_paths: Glob patterns for paths to exclude from scanning.
        custom_patterns: List of custom pattern definitions.
        config_path: Path to the config file that was loaded (None if defaults).
    """

    profile: Optional[str] = None
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    exclude_paths: List[str] = field(default_factory=list)
    custom_patterns: List[Dict[str, Any]] = field(default_factory=list)
    config_path: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.profile:
            d["profile"] = self.profile
        if self.severity_overrides:
            d["severity_overrides"] = dict(self.severity_overrides)
        if self.exclude_paths:
            d["exclude_paths"] = list(self.exclude_paths)
        if self.custom_patterns:
            d["custom_patterns"] = list(self.custom_patterns)
        if self.config_path:
            d["config_path"] = self.config_path
        return d

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], config_path: Optional[str] = None
    ) -> "ProjectConfig":
        return cls(
            profile=data.get("profile"),
            severity_overrides=data.get("severity_overrides", {}),
            exclude_paths=data.get("exclude_paths", []),
            custom_patterns=data.get("custom_patterns", []),
            config_path=config_path,
        )


def _load_json(path: str) -> dict[str, Any]:
    """Load a JSON config file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path: str) -> dict[str, Any]:
    """Load a YAML config file. Requires PyYAML."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "PyYAML is required to load .guardianshield.yaml files. "
            "Install it with: pip install pyyaml"
        )
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Config file names in priority order
_CONFIG_FILENAMES = [
    ".guardianshield.json",
    ".guardianshield.yaml",
    ".guardianshield.yml",
]


def discover_config(
    start_dir: Optional[str] = None,
    max_depth: int = 10,
) -> Optional[ProjectConfig]:
    """Walk up the directory tree looking for a GuardianShield config file.

    Args:
        start_dir: Directory to start searching from (defaults to cwd).
        max_depth: Maximum number of parent directories to traverse.

    Returns:
        A ProjectConfig if a config file is found, otherwise None.
    """
    if start_dir is None:
        start_dir = os.getcwd()

    current = os.path.abspath(start_dir)

    for _ in range(max_depth):
        for filename in _CONFIG_FILENAMES:
            config_path = os.path.join(current, filename)
            if os.path.isfile(config_path):
                return load_config(config_path)

        parent = os.path.dirname(current)
        if parent == current:
            # Reached filesystem root
            break
        current = parent

    return None


def load_config(config_path: str) -> ProjectConfig:
    """Load a config file (JSON or YAML) and return a ProjectConfig.

    Args:
        config_path: Path to the config file.

    Returns:
        A ProjectConfig instance.

    Raises:
        ValueError: If the file format is not supported.
        FileNotFoundError: If the file doesn't exist.
        json.JSONDecodeError: If JSON parsing fails.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    ext = os.path.splitext(config_path)[1].lower()
    if ext == ".json":
        data = _load_json(config_path)
    elif ext in (".yaml", ".yml"):
        data = _load_yaml(config_path)
    else:
        raise ValueError(f"Unsupported config format: {ext}")

    return ProjectConfig.from_dict(data, config_path=config_path)
