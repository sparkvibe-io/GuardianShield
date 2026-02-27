"""Manifest file parser for common dependency formats.

Parses requirements.txt, package.json, pyproject.toml, lockfiles
(package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock),
and Go/PHP manifests (go.mod, go.sum, composer.json, composer.lock)
into lists of :class:`Dependency` objects suitable for vulnerability
checking via :func:`check_dependencies`.

Supports:
    - **requirements.txt**: pinned (``==``), compatible (``~=``), minimum
      (``>=``), and exact versions; extras, comments, blank lines, and
      environment markers are handled gracefully.
    - **package.json**: ``dependencies`` and ``devDependencies`` with npm
      version prefixes (``^``, ``~``, ``>=``, etc.) stripped to base version.
    - **pyproject.toml**: PEP 621 ``[project.dependencies]`` and
      ``[project.optional-dependencies]`` sections. Uses :mod:`tomllib`
      on Python 3.11+ with a lightweight string-based fallback for 3.9/3.10.
    - **package-lock.json**: npm lockfile v1/v2/v3 formats.
    - **yarn.lock**: Yarn v1 lockfile format.
    - **pnpm-lock.yaml**: pnpm lockfile (string-parsed, no YAML lib).
    - **Pipfile.lock**: Pipenv lockfile (JSON format).
    - **go.mod**: Go module file ``require`` blocks.
    - **go.sum**: Go checksum database (deduplicated).
    - **composer.json**: PHP Composer manifest.
    - **composer.lock**: PHP Composer lockfile.

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
# package-lock.json parser (npm lockfile v1/v2/v3)
# ---------------------------------------------------------------------------


def parse_package_lock_json(text: str) -> List[Dependency]:
    """Parse an npm package-lock.json into Dependency objects.

    Supports lockfileVersion 2 and 3 (``packages`` dict) with fallback
    to lockfileVersion 1 (``dependencies`` dict).

    Args:
        text: Contents of a package-lock.json file.

    Returns:
        List of Dependency objects with ecosystem="npm".
    """
    deps: List[Dependency] = []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse package-lock.json")
        return deps

    if not isinstance(data, dict):
        return deps

    # v2/v3: packages dict — keys are paths like "node_modules/lodash"
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            # Skip the root package (empty string key)
            if not key:
                continue
            version = info.get("version")
            if not isinstance(version, str) or not version:
                continue
            # Extract package name from path: "node_modules/@scope/pkg" -> "@scope/pkg"
            # Handle nested: "node_modules/a/node_modules/b" -> "b"
            parts = key.split("node_modules/")
            name = parts[-1] if parts else key
            if not name:
                continue
            deps.append(Dependency(name=name, version=version, ecosystem="npm"))
        return deps

    # v1 fallback: flat dependencies dict
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _collect_lock_v1_deps(dependencies, deps)

    return deps


def _collect_lock_v1_deps(
    dependencies: dict, deps: List[Dependency]
) -> None:
    """Recursively collect dependencies from lockfileVersion 1 format."""
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if isinstance(version, str) and version:
            deps.append(Dependency(name=name, version=version, ecosystem="npm"))
        # v1 can have nested "dependencies" for deduped packages
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _collect_lock_v1_deps(nested, deps)


# ---------------------------------------------------------------------------
# yarn.lock parser (v1 format)
# ---------------------------------------------------------------------------

# Matches entry headers like: lodash@^4.17.21:  or  @scope/pkg@^1.0.0, @scope/pkg@^1.2.0:
_YARN_ENTRY_RE = re.compile(
    r'^"?(@?[^@\s"][^@]*?)@[^:\n]+:?\s*$'
)
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')


def parse_yarn_lock(text: str) -> List[Dependency]:
    """Parse a yarn.lock (v1 format) into Dependency objects.

    Yarn v1 lockfiles use an indented key-value format where each entry
    starts with the package specifier(s) and contains a ``version`` field.

    Args:
        text: Contents of a yarn.lock file.

    Returns:
        List of Dependency objects with ecosystem="npm".
    """
    deps: List[Dependency] = []
    seen: set = set()
    current_name: str | None = None

    for line in text.splitlines():
        # Skip comments and blank lines
        if not line or line.startswith("#"):
            current_name = None
            continue

        # Check for entry header (not indented)
        if not line[0].isspace():
            current_name = None
            # Parse the entry header to extract package name
            # Handle: "lodash@^4.17.21:" or "@scope/pkg@^1.0.0:"
            # or: "lodash@^4.17.21, lodash@^4.17.0:"
            # Strip trailing colon and quotes
            header = line.rstrip().rstrip(":")
            # Take the first specifier if comma-separated
            first_spec = header.split(",")[0].strip().strip('"')
            # Extract name: everything before the last @ (but not the first @ for scoped)
            if first_spec.startswith("@"):
                # Scoped package: @scope/name@version
                at_idx = first_spec.index("@", 1)
                current_name = first_spec[:at_idx]
            else:
                at_idx = first_spec.index("@") if "@" in first_spec else -1
                current_name = first_spec[:at_idx] if at_idx > 0 else first_spec
            continue

        # Check for version line (indented)
        if current_name is not None:
            m = _YARN_VERSION_RE.match(line)
            if m:
                version = m.group(1)
                key = (current_name, version)
                if key not in seen:
                    seen.add(key)
                    deps.append(
                        Dependency(name=current_name, version=version, ecosystem="npm")
                    )
                current_name = None

    return deps


# ---------------------------------------------------------------------------
# pnpm-lock.yaml parser (string-based, no YAML library)
# ---------------------------------------------------------------------------

# Matches package keys like: /lodash@4.17.21: or lodash@4.17.21:
# Also handles: /@scope/pkg@1.0.0: or @scope/pkg@1.0.0:
_PNPM_PKG_RE = re.compile(
    r"^\s+/?(@?[^@\s(][^@(]*?)@(\d[^:\s(]*)(?:\([^)]*\))?:"
)


def parse_pnpm_lock_yaml(text: str) -> List[Dependency]:
    """Parse a pnpm-lock.yaml into Dependency objects.

    Uses simple string parsing (no YAML library) to extract package names
    and versions from the ``packages`` section. Handles both ``/pkg@ver``
    and ``pkg@ver`` key formats.

    Args:
        text: Contents of a pnpm-lock.yaml file.

    Returns:
        List of Dependency objects with ecosystem="npm".
    """
    deps: List[Dependency] = []
    seen: set = set()
    in_packages = False

    for line in text.splitlines():
        stripped = line.strip()

        # Detect the packages: section
        if stripped == "packages:" or stripped == "packages: ~":
            in_packages = True
            continue

        # Detect a new top-level section (not indented)
        if not line.startswith(" ") and not line.startswith("\t") and stripped.endswith(":"):
            if in_packages:
                in_packages = False
            continue

        if not in_packages:
            continue

        # Try to match a package entry
        m = _PNPM_PKG_RE.match(line)
        if m:
            name = m.group(1)
            version = m.group(2)
            key = (name, version)
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(name=name, version=version, ecosystem="npm"))

    return deps


# ---------------------------------------------------------------------------
# Pipfile.lock parser (JSON format)
# ---------------------------------------------------------------------------


def parse_pipfile_lock(text: str) -> List[Dependency]:
    """Parse a Pipfile.lock into Dependency objects.

    Reads both ``default`` and ``develop`` sections. Strips ``==`` prefix
    from version strings.

    Args:
        text: Contents of a Pipfile.lock file.

    Returns:
        List of Dependency objects with ecosystem="PyPI".
    """
    deps: List[Dependency] = []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse Pipfile.lock")
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("default", "develop"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue

        for name, info in entries.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if not isinstance(version, str) or not version:
                continue
            # Strip == prefix: "==1.2.3" -> "1.2.3"
            clean_version = version.lstrip("=").strip()
            if not clean_version:
                continue
            deps.append(
                Dependency(name=name, version=clean_version, ecosystem="PyPI")
            )

    return deps


# ---------------------------------------------------------------------------
# go.mod parser
# ---------------------------------------------------------------------------

# Matches: module/path v1.2.3 (with optional // indirect comment)
_GO_REQUIRE_RE = re.compile(
    r"^\s+(\S+)\s+(v\S+)"
)


def parse_go_mod(text: str) -> List[Dependency]:
    """Parse a go.mod file into Dependency objects.

    Reads ``require`` blocks (both parenthesized and single-line forms).
    Skips ``replace`` and ``exclude`` directives.

    Args:
        text: Contents of a go.mod file.

    Returns:
        List of Dependency objects with ecosystem="Go".
    """
    deps: List[Dependency] = []
    in_require = False
    in_block = False

    for line in text.splitlines():
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("//"):
            continue

        # Single-line require: require module/path v1.2.3
        if stripped.startswith("require ") and "(" not in stripped:
            parts = stripped.split()
            if len(parts) >= 3:
                name = parts[1]
                version = parts[2]
                deps.append(Dependency(name=name, version=version, ecosystem="Go"))
            continue

        # Block start: require (
        if stripped.startswith("require") and "(" in stripped:
            in_require = True
            in_block = True
            continue

        # End of block
        if in_block and stripped == ")":
            in_require = False
            in_block = False
            continue

        # Other block starts (replace, exclude) — skip them
        if not in_require and stripped.rstrip().endswith("("):
            in_block = True
            continue
        if in_block and not in_require:
            if stripped == ")":
                in_block = False
            continue

        # Inside require block
        if in_require:
            m = _GO_REQUIRE_RE.match(line)
            if m:
                name = m.group(1)
                version = m.group(2)
                deps.append(Dependency(name=name, version=version, ecosystem="Go"))

    return deps


# ---------------------------------------------------------------------------
# go.sum parser
# ---------------------------------------------------------------------------


def parse_go_sum(text: str) -> List[Dependency]:
    """Parse a go.sum file into Dependency objects.

    Each line has the format: ``module/path v1.2.3 h1:hash=`` or
    ``module/path v1.2.3/go.mod h1:hash=``. Extracts unique
    (name, version) pairs, preferring the base entry over ``/go.mod``.

    Args:
        text: Contents of a go.sum file.

    Returns:
        List of Dependency objects with ecosystem="Go".
    """
    deps: List[Dependency] = []
    seen: set = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue

        name = parts[0]
        version_part = parts[1]

        # Strip /go.mod suffix from version
        version = version_part.replace("/go.mod", "")

        key = (name, version)
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(name=name, version=version, ecosystem="Go"))

    return deps


# ---------------------------------------------------------------------------
# composer.json parser (PHP)
# ---------------------------------------------------------------------------

# Strips common Composer version prefixes
_COMPOSER_VERSION_PREFIX_RE = re.compile(r"^[~^>=<!\s|]+")


def parse_composer_json(text: str) -> List[Dependency]:
    """Parse a PHP composer.json into Dependency objects.

    Reads ``require`` and ``require-dev`` sections. Skips ``php`` and
    ``ext-*`` platform requirements. Strips version prefixes
    (``^``, ``~``, ``>=``, etc.).

    Args:
        text: Contents of a composer.json file.

    Returns:
        List of Dependency objects with ecosystem="Packagist".
    """
    deps: List[Dependency] = []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse composer.json")
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("require", "require-dev"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue

        for name, version_spec in entries.items():
            if not isinstance(version_spec, str):
                continue
            # Skip platform requirements
            if name == "php" or name.startswith("ext-"):
                continue
            # Strip prefixes
            version = _COMPOSER_VERSION_PREFIX_RE.sub("", version_spec).strip()
            # Skip non-version specifiers (*, dev-master, etc.)
            if not version or not version[0].isdigit():
                continue
            deps.append(
                Dependency(name=name, version=version, ecosystem="Packagist")
            )

    return deps


# ---------------------------------------------------------------------------
# composer.lock parser (PHP)
# ---------------------------------------------------------------------------


def parse_composer_lock(text: str) -> List[Dependency]:
    """Parse a PHP composer.lock into Dependency objects.

    Reads ``packages`` and ``packages-dev`` arrays. Strips leading ``v``
    prefix from version strings.

    Args:
        text: Contents of a composer.lock file.

    Returns:
        List of Dependency objects with ecosystem="Packagist".
    """
    deps: List[Dependency] = []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse composer.lock")
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("packages", "packages-dev"):
        packages = data.get(section)
        if not isinstance(packages, list):
            continue

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            if not name or not version:
                continue
            # Strip leading 'v' prefix: "v1.2.3" -> "1.2.3"
            if version.startswith("v"):
                version = version[1:]
            deps.append(
                Dependency(name=name, version=version, ecosystem="Packagist")
            )

    return deps


# ---------------------------------------------------------------------------
# Auto-detect and dispatch
# ---------------------------------------------------------------------------

# Map filenames to parser functions
_FILENAME_MAP = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject_toml,
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock_yaml,
    "Pipfile.lock": parse_pipfile_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "composer.json": parse_composer_json,
    "composer.lock": parse_composer_lock,
}

# Also match patterns like requirements-dev.txt, requirements_test.txt
_REQUIREMENTS_RE = re.compile(r"^requirements[-_]?\w*\.txt$", re.IGNORECASE)


def parse_manifest(text: str, filename: str) -> List[Dependency]:
    """Auto-detect manifest format from filename and parse dependencies.

    Supported filenames:
        - ``requirements.txt`` (and variants like ``requirements-dev.txt``)
        - ``package.json``
        - ``pyproject.toml``
        - ``package-lock.json``
        - ``yarn.lock``
        - ``pnpm-lock.yaml``
        - ``Pipfile.lock``
        - ``go.mod``
        - ``go.sum``
        - ``composer.json``
        - ``composer.lock``

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

    supported = ", ".join(sorted(_FILENAME_MAP.keys()))
    raise ValueError(
        f"Unrecognized manifest filename: {filename!r}. "
        f"Supported: {supported}"
    )
