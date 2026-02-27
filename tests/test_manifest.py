"""Tests for manifest file parser (requirements.txt, package.json, pyproject.toml)."""

import json

import pytest

from guardianshield.manifest import (
    parse_manifest,
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from guardianshield.osv import Dependency


# =======================================================================
# requirements.txt
# =======================================================================


class TestParseRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_pinned_version(self):
        text = "requests==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"
        assert deps[0].ecosystem == "PyPI"

    def test_multiple_pinned(self):
        text = "flask==2.3.0\nrequests==2.28.0\nnumpy==1.24.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 3
        assert deps[0].name == "flask"
        assert deps[1].name == "requests"
        assert deps[2].name == "numpy"

    def test_compatible_release(self):
        text = "requests~=2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_minimum_version(self):
        text = "requests>=2.20.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.20.0"

    def test_less_than(self):
        text = "requests<3.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "3.0.0"

    def test_less_than_equal(self):
        text = "requests<=2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_not_equal(self):
        text = "requests!=2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_arbitrary_equality(self):
        text = "requests===2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_comments_skipped(self):
        text = "# This is a comment\nrequests==2.28.0\n# Another comment\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_blank_lines_skipped(self):
        text = "\n\nrequests==2.28.0\n\n\nflask==2.3.0\n\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 2

    def test_inline_comments(self):
        text = "requests==2.28.0  # pinned for stability\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_extras_stripped(self):
        text = "requests[security]==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_multiple_extras(self):
        text = "celery[redis,msgpack]==5.3.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "celery"
        assert deps[0].version == "5.3.0"

    def test_environment_markers(self):
        text = 'pywin32==306 ; sys_platform == "win32"\n'
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "pywin32"
        assert deps[0].version == "306"

    def test_r_include_skipped(self):
        text = "-r base.txt\nrequests==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_c_constraint_skipped(self):
        text = "-c constraints.txt\nrequests==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1

    def test_pip_options_skipped(self):
        text = "--index-url https://pypi.org/simple\nrequests==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1

    def test_no_version_skipped(self):
        text = "requests\nflask==2.3.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_empty_file(self):
        deps = parse_requirements_txt("")
        assert deps == []

    def test_only_comments(self):
        text = "# comment 1\n# comment 2\n"
        deps = parse_requirements_txt(text)
        assert deps == []

    def test_hyphenated_package_name(self):
        text = "my-package==1.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "my-package"

    def test_underscored_package_name(self):
        text = "my_package==1.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "my_package"

    def test_dotted_package_name(self):
        text = "zope.interface==5.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "zope.interface"

    def test_version_with_pre_release(self):
        text = "flask==2.3.0rc1\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.3.0rc1"

    def test_spaces_around_operator(self):
        text = "requests == 2.28.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_returns_dependency_instances(self):
        text = "requests==2.28.0\n"
        deps = parse_requirements_txt(text)
        assert isinstance(deps[0], Dependency)


# =======================================================================
# package.json
# =======================================================================


class TestParsePackageJson:
    """Tests for package.json parsing."""

    def test_simple_dependencies(self):
        data = {
            "dependencies": {
                "express": "4.18.2",
                "lodash": "4.17.21",
            }
        }
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"express", "lodash"}
        for d in deps:
            assert d.ecosystem == "npm"

    def test_caret_prefix_stripped(self):
        data = {"dependencies": {"express": "^4.18.2"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].version == "4.18.2"

    def test_tilde_prefix_stripped(self):
        data = {"dependencies": {"express": "~4.18.2"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].version == "4.18.2"

    def test_gte_prefix_stripped(self):
        data = {"dependencies": {"express": ">=4.18.2"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].version == "4.18.2"

    def test_exact_version(self):
        data = {"dependencies": {"express": "4.18.2"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].version == "4.18.2"

    def test_dev_dependencies(self):
        data = {
            "devDependencies": {
                "jest": "29.5.0",
                "eslint": "8.40.0",
            }
        }
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"jest", "eslint"}

    def test_both_dep_types(self):
        data = {
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"jest": "^29.5.0"},
        }
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 2

    def test_star_version_skipped(self):
        data = {"dependencies": {"express": "*"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 0

    def test_latest_version_skipped(self):
        data = {"dependencies": {"express": "latest"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 0

    def test_git_url_skipped(self):
        data = {"dependencies": {"mylib": "git+https://github.com/user/repo.git"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 0

    def test_file_path_skipped(self):
        data = {"dependencies": {"mylib": "file:../mylib"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 0

    def test_empty_dependencies(self):
        data = {"dependencies": {}}
        deps = parse_package_json(json.dumps(data))
        assert deps == []

    def test_no_dependencies_key(self):
        data = {"name": "myapp", "version": "1.0.0"}
        deps = parse_package_json(json.dumps(data))
        assert deps == []

    def test_empty_file(self):
        deps = parse_package_json("{}")
        assert deps == []

    def test_invalid_json(self):
        deps = parse_package_json("not json at all")
        assert deps == []

    def test_non_string_version_skipped(self):
        data = {"dependencies": {"express": 123}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 0

    def test_scoped_package(self):
        data = {"dependencies": {"@types/node": "18.16.0"}}
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "@types/node"

    def test_returns_dependency_instances(self):
        data = {"dependencies": {"express": "4.18.2"}}
        deps = parse_package_json(json.dumps(data))
        assert isinstance(deps[0], Dependency)

    def test_non_dict_top_level(self):
        deps = parse_package_json(json.dumps([1, 2, 3]))
        assert deps == []

    def test_non_dict_dependencies_value(self):
        data = {"dependencies": "not-a-dict"}
        deps = parse_package_json(json.dumps(data))
        assert deps == []


# =======================================================================
# pyproject.toml
# =======================================================================


class TestParsePyprojectToml:
    """Tests for pyproject.toml PEP 621 parsing."""

    def test_simple_dependencies(self):
        text = """
[project]
name = "myapp"
version = "1.0.0"
dependencies = [
    "flask==2.3.0",
    "requests==2.28.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 2
        assert deps[0].name == "flask"
        assert deps[0].version == "2.3.0"
        assert deps[1].name == "requests"
        assert deps[1].version == "2.28.0"
        for d in deps:
            assert d.ecosystem == "PyPI"

    def test_optional_dependencies(self):
        text = """
[project]
name = "myapp"
dependencies = []

[project.optional-dependencies]
dev = [
    "pytest==7.4.0",
    "ruff==0.1.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 2
        assert deps[0].name == "pytest"
        assert deps[1].name == "ruff"

    def test_both_regular_and_optional(self):
        text = """
[project]
name = "myapp"
dependencies = [
    "flask==2.3.0",
]

[project.optional-dependencies]
dev = [
    "pytest==7.4.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"flask", "pytest"}

    def test_compatible_release_version(self):
        text = """
[project]
dependencies = [
    "requests~=2.28.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_minimum_version(self):
        text = """
[project]
dependencies = [
    "requests>=2.20.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 1
        assert deps[0].version == "2.20.0"

    def test_environment_markers_stripped(self):
        text = """
[project]
dependencies = [
    "pywin32==306; sys_platform == 'win32'",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 1
        assert deps[0].name == "pywin32"
        assert deps[0].version == "306"

    def test_no_version_skipped(self):
        text = """
[project]
dependencies = [
    "requests",
    "flask==2.3.0",
]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_empty_dependencies(self):
        text = """
[project]
name = "myapp"
dependencies = []
"""
        deps = parse_pyproject_toml(text)
        assert deps == []

    def test_no_project_section(self):
        text = """
[tool.ruff]
line-length = 88
"""
        deps = parse_pyproject_toml(text)
        assert deps == []

    def test_empty_file(self):
        deps = parse_pyproject_toml("")
        assert deps == []

    def test_single_line_array(self):
        text = '[project]\ndependencies = ["flask==2.3.0", "requests==2.28.0"]\n'
        deps = parse_pyproject_toml(text)
        assert len(deps) == 2

    def test_multiple_optional_groups(self):
        text = """
[project]
dependencies = []

[project.optional-dependencies]
dev = ["pytest==7.4.0"]
docs = ["mkdocs==1.5.0"]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"pytest", "mkdocs"}

    def test_returns_dependency_instances(self):
        text = """
[project]
dependencies = ["flask==2.3.0"]
"""
        deps = parse_pyproject_toml(text)
        assert isinstance(deps[0], Dependency)


# =======================================================================
# parse_manifest (auto-detection)
# =======================================================================


class TestParseManifest:
    """Tests for auto-detection via parse_manifest()."""

    def test_requirements_txt(self):
        text = "requests==2.28.0\nflask==2.3.0\n"
        deps = parse_manifest(text, "requirements.txt")
        assert len(deps) == 2
        assert all(d.ecosystem == "PyPI" for d in deps)

    def test_package_json(self):
        data = {"dependencies": {"express": "4.18.2"}}
        deps = parse_manifest(json.dumps(data), "package.json")
        assert len(deps) == 1
        assert deps[0].ecosystem == "npm"

    def test_pyproject_toml(self):
        text = '[project]\ndependencies = ["flask==2.3.0"]\n'
        deps = parse_manifest(text, "pyproject.toml")
        assert len(deps) == 1
        assert deps[0].ecosystem == "PyPI"

    def test_requirements_dev_txt(self):
        text = "pytest==7.4.0\n"
        deps = parse_manifest(text, "requirements-dev.txt")
        assert len(deps) == 1

    def test_requirements_test_txt(self):
        text = "pytest==7.4.0\n"
        deps = parse_manifest(text, "requirements_test.txt")
        assert len(deps) == 1

    def test_full_path_filename(self):
        text = "requests==2.28.0\n"
        deps = parse_manifest(text, "/home/user/project/requirements.txt")
        assert len(deps) == 1

    def test_windows_path_filename(self):
        text = "requests==2.28.0\n"
        deps = parse_manifest(text, "C:\\Users\\project\\requirements.txt")
        assert len(deps) == 1

    def test_unknown_filename_raises(self):
        with pytest.raises(ValueError, match="Unrecognized manifest filename"):
            parse_manifest("", "unknown.yaml")

    def test_unknown_extension_raises(self):
        with pytest.raises(ValueError):
            parse_manifest("", "setup.cfg")

    def test_empty_content(self):
        deps = parse_manifest("", "requirements.txt")
        assert deps == []

    def test_case_insensitive_requirements_variant(self):
        text = "requests==2.28.0\n"
        deps = parse_manifest(text, "Requirements.txt")
        assert len(deps) == 1


# =======================================================================
# Edge cases
# =======================================================================


class TestEdgeCases:
    """Edge cases across all parsers."""

    def test_requirements_with_version_range(self):
        # Only the first operator/version is captured
        text = "requests>=2.20.0,<3.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.20.0"

    def test_requirements_windows_line_endings(self):
        text = "requests==2.28.0\r\nflask==2.3.0\r\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 2

    def test_package_json_with_extra_fields(self):
        data = {
            "name": "myapp",
            "version": "1.0.0",
            "description": "Test app",
            "dependencies": {"express": "4.18.2"},
            "scripts": {"test": "jest"},
        }
        deps = parse_package_json(json.dumps(data))
        assert len(deps) == 1

    def test_package_json_empty_string(self):
        deps = parse_package_json("")
        assert deps == []

    def test_pyproject_with_build_system(self):
        text = """
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "myapp"
dependencies = ["flask==2.3.0"]
"""
        deps = parse_pyproject_toml(text)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_requirements_greater_than(self):
        text = "requests>2.0.0\n"
        deps = parse_requirements_txt(text)
        assert len(deps) == 1
        assert deps[0].version == "2.0.0"

    def test_package_json_complex_range_skipped(self):
        # Ranges like ">=1.0.0 <2.0.0" — the prefix stripping gets "1.0.0"
        data = {"dependencies": {"express": ">=1.0.0 <2.0.0"}}
        deps = parse_package_json(json.dumps(data))
        # Should extract 1.0.0 from ">=1.0.0 <2.0.0" after stripping prefix
        assert len(deps) == 1
        assert deps[0].version.startswith("1.0.0")

    def test_all_parsers_return_lists(self):
        assert isinstance(parse_requirements_txt(""), list)
        assert isinstance(parse_package_json("{}"), list)
        assert isinstance(parse_pyproject_toml(""), list)
