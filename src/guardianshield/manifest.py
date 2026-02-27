"""Manifest file parser for common dependency formats.

Parses requirements.txt, package.json, and pyproject.toml files into
lists of :class:`Dependency` objects suitable for vulnerability checking
via :func:`check_dependencies`.

Supports:
    - **requirements.txt**: pinned (``==``), compatible (``~=``), minimum
      (``>=``), and exact versions; extras, comments, blank lines, and
      environment markers are handled gracefully.
    - **package.json**: ``dependencies`` and ``devDependencies`` with npm
      version prefixes (``^``, ``~``, ``>=``, etc.) stripped to base version.
    - **pyproject.toml**: PEP 621 ``[project.dependencies]`` and
      ``[project.optional-dependencies]`` sections. Uses :mod:`tomllib`
      on Python 3.11+ with a lightweight string-based fallback for 3.9/3.10.

All parsers are **stdlib-only** — zero external dependencies.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import List

from .osv import Dependency

logger = logging.getLogger("guardianshield.manifest")

# ---------------------------------------------------------------------------
# requirements.txt parser
# ---------------------------------------------------------------------------

# Matches: package[extras]<operator>version ;markers
# Groups: (1) package name, (2) version operator, (3) version string
_REQ_RE = re.compile(
    r"^"
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(?:\[[^\]]*\])?"                                   # optional extras
    r"\s*"
    r"(===|==|~=|>=|<=|!=|>|<)"                           # version operator
    r"\s*"
    r"([^\s;,]+)"                                        # version string
)


def parse_requirements_txt(text: str) -> List[Dependency]:
    """Parse a pip requirements.txt file into Dependency objects.

    Handles pinned versions (``==``), compatible releases (``~=``), minimum
    versions (``>=``), extras (``[dev]``), comments (``#``), blank lines,
    ``-r``/``-c`` include directives (skipped), and environment markers
    (``;``).  Only entries with an extractable version are returned.

    Args:
        text: Contents of a requirements.txt file.

    Returns:
        List of Dependency objects with ecosystem="PyPI".
    """
    deps: List[Dependency] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue

        # Skip pip options (-r, -c, --index-url, etc.)
        if line.startswith("-"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        # Strip environment markers (everything after ";")
        if ";" in line:
            line = line[: line.index(";")].strip()

        m = _REQ_RE.match(line)
        if m:
            name = m.group(1)
            version = m.group(3)
            deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))

    return deps


# ---------------------------------------------------------------------------
# package.json parser
# ---------------------------------------------------------------------------

# Strips common npm version prefixes to extract the base semver
_NPM_VERSION_PREFIX_RE = re.compile(r"^[~^>=<!\s]+")


def parse_package_json(text: str) -> List[Dependency]:
    """Parse an npm package.json file into Dependency objects.

    Reads both ``dependencies`` and ``devDependencies``. Version prefixes
    (``^``, ``~``, ``>=``, etc.) are stripped to extract the base semver
    version.  Entries without a parseable version (e.g. ``"*"``,
    ``"latest"``, git URLs) are skipped.

    Args:
        text: Contents of a package.json file.

    Returns:
        List of Dependency objects with ecosystem="npm".
    """
    deps: List[Dependency] = []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse package.json")
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("dependencies", "devDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue

        for name, version_spec in entries.items():
            if not isinstance(version_spec, str):
                continue

            # Strip prefixes like ^, ~, >=, etc.
            version = _NPM_VERSION_PREFIX_RE.sub("", version_spec).strip()

            # Skip non-version specifiers (*, latest, git URLs, file paths)
            if not version or not version[0].isdigit():
                continue

            deps.append(Dependency(name=name, version=version, ecosystem="npm"))

    return deps


# ---------------------------------------------------------------------------
# pyproject.toml parser
# ---------------------------------------------------------------------------

# Reuse the requirements-style regex for PEP 508 dependency strings
_PEP508_RE = _REQ_RE


def _parse_toml_stdlib(text: str) -> dict:
    """Parse TOML using stdlib tomllib (Python 3.11+)."""
    import tomllib  # type: ignore[import-not-found]
    return tomllib.loads(text)


def _parse_toml_fallback(text: str) -> dict:
    """Minimal TOML parser for pyproject.toml dependency extraction.

    Handles the subset of TOML needed to extract ``[project]`` dependencies:
    tables, key-value pairs with string/array values.  This is NOT a
    general-purpose TOML parser — just enough for 3.9/3.10 compat.
    """
    result: dict = {}
    current_table: dict = result
    current_path: List[str] = []

    lines = text.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        i += 1

        # Skip blanks and comments
        if not line or line.startswith("#"):
            continue

        # Table header: [section] or [section.subsection]
        table_match = re.match(r"^\[([^\[\]]+)\]\s*(?:#.*)?$", line)
        if table_match:
            path = [p.strip().strip('"').strip("'")
                    for p in table_match.group(1).split(".")]
            current_path = path
            # Navigate/create nested dicts
            current_table = result
            for key in path:
                if key not in current_table:
                    current_table[key] = {}
                current_table = current_table[key]
            continue

        # Key = value
        kv_match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*(.+)$', line)
        if not kv_match:
            continue

        key = kv_match.group(1).strip()
        value_str = kv_match.group(2).strip()

        # String value
        if value_str.startswith('"') and value_str.endswith('"'):
            current_table[key] = value_str[1:-1]
            continue
        if value_str.startswith("'") and value_str.endswith("'"):
            current_table[key] = value_str[1:-1]
            continue

        # Single-line array
        if value_str.startswith("[") and value_str.endswith("]"):
            current_table[key] = _parse_toml_array(value_str)
            continue

        # Multi-line array
        if value_str.startswith("[") and not value_str.endswith("]"):
            array_text = value_str
            while i < len(lines):
                next_line = lines[i]
                i += 1
                array_text += "\n" + next_line
                if next_line.strip().endswith("]"):
                    break
            current_table[key] = _parse_toml_array(array_text)
            continue

        # Boolean / number (store as string — we only need dep strings)
        current_table[key] = value_str

    return result


def _parse_toml_array(text: str) -> List[str]:
    """Extract string items from a TOML array literal."""
    items: List[str] = []
    # Find all quoted strings
    for m in re.finditer(r'"([^"]*)"', text):
        items.append(m.group(1))
    if not items:
        for m in re.finditer(r"'([^']*)'", text):
            items.append(m.group(1))
    return items


def _parse_toml(text: str) -> dict:
    """Parse TOML text, using stdlib on 3.11+ or fallback on 3.9/3.10."""
    if sys.version_info >= (3, 11):
        try:
            return _parse_toml_stdlib(text)
        except Exception:
            logger.debug("tomllib failed, trying fallback parser")
    return _parse_toml_fallback(text)


def parse_pyproject_toml(text: str) -> List[Dependency]:
    """Parse a PEP 621 pyproject.toml into Dependency objects.

    Reads ``[project.dependencies]`` and all groups under
    ``[project.optional-dependencies]``.  Version specifiers follow PEP 508
    format (same as requirements.txt entries).

    Args:
        text: Contents of a pyproject.toml file.

    Returns:
        List of Dependency objects with ecosystem="PyPI".
    """
    deps: List[Dependency] = []

    try:
        data = _parse_toml(text)
    except Exception:
        logger.warning("Failed to parse pyproject.toml")
        return deps

    project = data.get("project", {})
    if not isinstance(project, dict):
        return deps

    # [project.dependencies]
    dep_list = project.get("dependencies", [])
    if isinstance(dep_list, list):
        for entry in dep_list:
            if isinstance(entry, str):
                _add_pep508_dep(entry, deps)

    # [project.optional-dependencies]
    opt_deps = project.get("optional-dependencies", {})
    if isinstance(opt_deps, dict):
        for group_deps in opt_deps.values():
            if isinstance(group_deps, list):
                for entry in group_deps:
                    if isinstance(entry, str):
                        _add_pep508_dep(entry, deps)

    return deps


def _add_pep508_dep(spec: str, deps: List[Dependency]) -> None:
    """Parse a PEP 508 dependency specifier and append to deps if versioned."""
    # Strip environment markers
    clean = spec.split(";")[0].strip()
    m = _PEP508_RE.match(clean)
    if m:
        name = m.group(1)
        version = m.group(3)
        deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))


# ---------------------------------------------------------------------------
# Auto-detect and dispatch
# ---------------------------------------------------------------------------

# Map filenames to parser functions
_FILENAME_MAP = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject_toml,
}

# Also match patterns like requirements-dev.txt, requirements_test.txt
_REQUIREMENTS_RE = re.compile(r"^requirements[-_]?\w*\.txt$", re.IGNORECASE)


def parse_manifest(text: str, filename: str) -> List[Dependency]:
    """Auto-detect manifest format from filename and parse dependencies.

    Supported filenames:
        - ``requirements.txt`` (and variants like ``requirements-dev.txt``)
        - ``package.json``
        - ``pyproject.toml``

    Args:
        text: Contents of the manifest file.
        filename: Name of the file (used for format detection).

    Returns:
        List of Dependency objects.

    Raises:
        ValueError: If the filename is not recognized.
    """
    # Normalize to basename
    basename = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    # Exact match
    parser = _FILENAME_MAP.get(basename)
    if parser is not None:
        return parser(text)

    # Pattern match for requirements variants
    if _REQUIREMENTS_RE.match(basename):
        return parse_requirements_txt(text)

    raise ValueError(
        f"Unrecognized manifest filename: {filename!r}. "
        f"Supported: requirements.txt, package.json, pyproject.toml"
    )
