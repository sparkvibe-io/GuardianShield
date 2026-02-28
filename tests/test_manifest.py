"""Tests for manifest file parser (all supported formats)."""

import json

import pytest

from guardianshield.manifest import (
    parse_composer_json,
    parse_composer_lock,
    parse_go_mod,
    parse_go_sum,
    parse_manifest,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_pnpm_lock_yaml,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_yarn_lock,
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


# =======================================================================
# package-lock.json
# =======================================================================


class TestParsePackageLockJson:
    """Tests for package-lock.json parsing."""

    def test_v2_packages_format(self):
        data = {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "myapp", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}
        assert all(d.ecosystem == "npm" for d in deps)

    def test_v3_packages_format(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp", "version": "1.0.0"},
                "node_modules/axios": {"version": "1.4.0"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "axios"
        assert deps[0].version == "1.4.0"

    def test_v1_dependencies_format(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {"version": "4.18.2"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}

    def test_v1_nested_dependencies(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": {"version": "1.3.8"},
                    },
                },
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"express", "accepts"}

    def test_scoped_packages(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp"},
                "node_modules/@types/node": {"version": "18.16.0"},
                "node_modules/@babel/core": {"version": "7.22.0"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"@types/node", "@babel/core"}

    def test_nested_node_modules(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/a/node_modules/b": {"version": "2.0.0"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        versions = {d.name: d.version for d in deps}
        assert versions["a"] == "1.0.0"
        assert versions["b"] == "2.0.0"

    def test_empty_packages(self):
        data = {"lockfileVersion": 3, "packages": {}}
        deps = parse_package_lock_json(json.dumps(data))
        assert deps == []

    def test_root_only(self):
        data = {"lockfileVersion": 3, "packages": {"": {"name": "myapp", "version": "1.0.0"}}}
        deps = parse_package_lock_json(json.dumps(data))
        assert deps == []

    def test_invalid_json(self):
        deps = parse_package_lock_json("not json")
        assert deps == []

    def test_empty_file(self):
        deps = parse_package_lock_json("{}")
        assert deps == []

    def test_non_dict_top_level(self):
        deps = parse_package_lock_json(json.dumps([1, 2, 3]))
        assert deps == []

    def test_missing_version_skipped(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/broken": {},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "lodash"

    def test_returns_dependency_instances(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        deps = parse_package_lock_json(json.dumps(data))
        assert isinstance(deps[0], Dependency)


# =======================================================================
# yarn.lock
# =======================================================================


class TestParseYarnLock:
    """Tests for yarn.lock (v1) parsing."""

    def test_simple_package(self):
        text = """\
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-abc123
"""
        deps = parse_yarn_lock(text)
        assert len(deps) == 1
        assert deps[0].name == "lodash"
        assert deps[0].version == "4.17.21"
        assert deps[0].ecosystem == "npm"

    def test_multiple_packages(self):
        text = """\
lodash@^4.17.21:
  version "4.17.21"

express@^4.18.0:
  version "4.18.2"
"""
        deps = parse_yarn_lock(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}

    def test_scoped_package(self):
        text = """\
"@types/node@^18.0.0":
  version "18.16.0"
"""
        deps = parse_yarn_lock(text)
        assert len(deps) == 1
        assert deps[0].name == "@types/node"
        assert deps[0].version == "18.16.0"

    def test_multiple_version_ranges(self):
        text = """\
"lodash@^4.17.0, lodash@^4.17.21":
  version "4.17.21"
"""
        deps = parse_yarn_lock(text)
        assert len(deps) == 1
        assert deps[0].name == "lodash"
        assert deps[0].version == "4.17.21"

    def test_deduplication(self):
        # Same package with same resolved version should only appear once
        text = """\
lodash@^4.17.0:
  version "4.17.21"

lodash@^4.17.21:
  version "4.17.21"
"""
        deps = parse_yarn_lock(text)
        assert len(deps) == 1
        assert deps[0].name == "lodash"

    def test_empty_file(self):
        deps = parse_yarn_lock("")
        assert deps == []

    def test_comments_only(self):
        text = "# yarn lockfile v1\n\n"
        deps = parse_yarn_lock(text)
        assert deps == []

    def test_returns_dependency_instances(self):
        text = """\
lodash@^4.17.21:
  version "4.17.21"
"""
        deps = parse_yarn_lock(text)
        assert isinstance(deps[0], Dependency)


# =======================================================================
# pnpm-lock.yaml
# =======================================================================


class TestParsePnpmLockYaml:
    """Tests for pnpm-lock.yaml parsing."""

    def test_slash_prefix_format(self):
        text = """\
lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
    dev: false

  /express@4.18.2:
    resolution: {integrity: sha512-def}
    dev: false
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}
        assert all(d.ecosystem == "npm" for d in deps)

    def test_no_slash_prefix_format(self):
        text = """\
lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  express@4.18.2:
    resolution: {integrity: sha512-def}
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}

    def test_scoped_package(self):
        text = """\
packages:

  /@types/node@18.16.0:
    resolution: {integrity: sha512-abc}
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 1
        assert deps[0].name == "@types/node"
        assert deps[0].version == "18.16.0"

    def test_scoped_no_slash(self):
        text = """\
packages:

  @babel/core@7.22.0:
    resolution: {integrity: sha512-abc}
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 1
        assert deps[0].name == "@babel/core"
        assert deps[0].version == "7.22.0"

    def test_deduplication(self):
        text = """\
packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 1

    def test_empty_packages(self):
        text = """\
lockfileVersion: '6.0'

packages:
"""
        deps = parse_pnpm_lock_yaml(text)
        assert deps == []

    def test_empty_file(self):
        deps = parse_pnpm_lock_yaml("")
        assert deps == []

    def test_only_header(self):
        text = "lockfileVersion: '6.0'\n"
        deps = parse_pnpm_lock_yaml(text)
        assert deps == []

    def test_returns_dependency_instances(self):
        text = """\
packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
"""
        deps = parse_pnpm_lock_yaml(text)
        assert isinstance(deps[0], Dependency)

    def test_stops_at_next_section(self):
        text = """\
packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}

settings:
  autoInstallPeers: true
"""
        deps = parse_pnpm_lock_yaml(text)
        assert len(deps) == 1
        assert deps[0].name == "lodash"


# =======================================================================
# Pipfile.lock
# =======================================================================


class TestParsePipfileLock:
    """Tests for Pipfile.lock parsing."""

    def test_default_section(self):
        data = {
            "_meta": {"hash": {"sha256": "abc"}},
            "default": {
                "requests": {"version": "==2.28.0"},
                "flask": {"version": "==2.3.0"},
            },
            "develop": {},
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"requests", "flask"}
        assert all(d.ecosystem == "PyPI" for d in deps)

    def test_develop_section(self):
        data = {
            "_meta": {},
            "default": {},
            "develop": {
                "pytest": {"version": "==7.4.0"},
                "ruff": {"version": "==0.1.0"},
            },
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"pytest", "ruff"}

    def test_both_sections(self):
        data = {
            "_meta": {},
            "default": {"flask": {"version": "==2.3.0"}},
            "develop": {"pytest": {"version": "==7.4.0"}},
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"flask", "pytest"}

    def test_version_prefix_stripped(self):
        data = {
            "_meta": {},
            "default": {"requests": {"version": "==2.28.0"}},
            "develop": {},
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert deps[0].version == "2.28.0"

    def test_missing_version_skipped(self):
        data = {
            "_meta": {},
            "default": {
                "requests": {"hashes": ["sha256:abc"]},
                "flask": {"version": "==2.3.0"},
            },
            "develop": {},
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_empty_sections(self):
        data = {"_meta": {}, "default": {}, "develop": {}}
        deps = parse_pipfile_lock(json.dumps(data))
        assert deps == []

    def test_invalid_json(self):
        deps = parse_pipfile_lock("not json")
        assert deps == []

    def test_empty_file(self):
        deps = parse_pipfile_lock("{}")
        assert deps == []

    def test_non_dict_top_level(self):
        deps = parse_pipfile_lock(json.dumps([1, 2, 3]))
        assert deps == []

    def test_returns_dependency_instances(self):
        data = {
            "_meta": {},
            "default": {"requests": {"version": "==2.28.0"}},
            "develop": {},
        }
        deps = parse_pipfile_lock(json.dumps(data))
        assert isinstance(deps[0], Dependency)


# =======================================================================
# go.mod
# =======================================================================


class TestParseGoMod:
    """Tests for go.mod parsing."""

    def test_require_block(self):
        text = """\
module github.com/myorg/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/go-sql-driver/mysql v1.7.1
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 2
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "v1.9.1"
        assert deps[0].ecosystem == "Go"
        assert deps[1].name == "github.com/go-sql-driver/mysql"
        assert deps[1].version == "v1.7.1"

    def test_single_require(self):
        text = """\
module github.com/myorg/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"""
        deps = parse_go_mod(text)
        assert len(deps) == 1
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "v1.9.1"

    def test_multiple_require_blocks(self):
        text = """\
module github.com/myorg/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
)

require (
\tgithub.com/go-sql-driver/mysql v1.7.1
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 2

    def test_indirect_dependencies(self):
        text = """\
module github.com/myorg/myapp

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/bytedance/sonic v1.9.1 // indirect
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 2
        # Both direct and indirect should be parsed

    def test_replace_directives_skipped(self):
        text = """\
module github.com/myorg/myapp

require (
\tgithub.com/gin-gonic/gin v1.9.1
)

replace (
\tgithub.com/gin-gonic/gin => ../gin
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 1
        assert deps[0].name == "github.com/gin-gonic/gin"

    def test_exclude_directives_skipped(self):
        text = """\
module github.com/myorg/myapp

require (
\tgithub.com/gin-gonic/gin v1.9.1
)

exclude (
\tgithub.com/gin-gonic/gin v1.9.0
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 1

    def test_empty_file(self):
        text = "module github.com/myorg/myapp\n\ngo 1.21\n"
        deps = parse_go_mod(text)
        assert deps == []

    def test_empty_string(self):
        deps = parse_go_mod("")
        assert deps == []

    def test_comments_skipped(self):
        text = """\
module github.com/myorg/myapp

// This is a comment
require (
\t// another comment
\tgithub.com/gin-gonic/gin v1.9.1
)
"""
        deps = parse_go_mod(text)
        assert len(deps) == 1

    def test_returns_dependency_instances(self):
        text = """\
module github.com/myorg/myapp

require github.com/gin-gonic/gin v1.9.1
"""
        deps = parse_go_mod(text)
        assert isinstance(deps[0], Dependency)


# =======================================================================
# go.sum
# =======================================================================


class TestParseGoSum:
    """Tests for go.sum parsing."""

    def test_simple_entries(self):
        text = """\
github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
github.com/go-sql-driver/mysql v1.7.1 h1:ghi=
github.com/go-sql-driver/mysql v1.7.1/go.mod h1:jkl=
"""
        deps = parse_go_sum(text)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"github.com/gin-gonic/gin", "github.com/go-sql-driver/mysql"}

    def test_deduplication_of_go_mod_entries(self):
        text = """\
github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
"""
        deps = parse_go_sum(text)
        assert len(deps) == 1
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "v1.9.1"
        assert deps[0].ecosystem == "Go"

    def test_multiple_versions(self):
        text = """\
github.com/gin-gonic/gin v1.9.0 h1:abc=
github.com/gin-gonic/gin v1.9.0/go.mod h1:def=
github.com/gin-gonic/gin v1.9.1 h1:ghi=
github.com/gin-gonic/gin v1.9.1/go.mod h1:jkl=
"""
        deps = parse_go_sum(text)
        assert len(deps) == 2
        versions = {d.version for d in deps}
        assert versions == {"v1.9.0", "v1.9.1"}

    def test_go_mod_only_entry(self):
        # Some entries only have /go.mod line without the base entry
        text = """\
github.com/stretchr/testify v1.8.4/go.mod h1:abc=
"""
        deps = parse_go_sum(text)
        assert len(deps) == 1
        assert deps[0].name == "github.com/stretchr/testify"
        assert deps[0].version == "v1.8.4"

    def test_empty_file(self):
        deps = parse_go_sum("")
        assert deps == []

    def test_blank_lines_handled(self):
        text = """\

github.com/gin-gonic/gin v1.9.1 h1:abc=

github.com/go-sql-driver/mysql v1.7.1 h1:ghi=

"""
        deps = parse_go_sum(text)
        assert len(deps) == 2

    def test_returns_dependency_instances(self):
        text = "github.com/gin-gonic/gin v1.9.1 h1:abc=\n"
        deps = parse_go_sum(text)
        assert isinstance(deps[0], Dependency)


# =======================================================================
# composer.json
# =======================================================================


class TestParseComposerJson:
    """Tests for PHP composer.json parsing."""

    def test_require_section(self):
        data = {
            "require": {
                "php": "^8.1",
                "laravel/framework": "^10.0",
                "guzzlehttp/guzzle": "^7.2",
            }
        }
        deps = parse_composer_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"laravel/framework", "guzzlehttp/guzzle"}
        assert all(d.ecosystem == "Packagist" for d in deps)

    def test_require_dev_section(self):
        data = {
            "require-dev": {
                "phpunit/phpunit": "^10.0",
                "laravel/pint": "^1.0",
            }
        }
        deps = parse_composer_json(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"phpunit/phpunit", "laravel/pint"}

    def test_both_sections(self):
        data = {
            "require": {
                "laravel/framework": "^10.0",
            },
            "require-dev": {
                "phpunit/phpunit": "^10.0",
            },
        }
        deps = parse_composer_json(json.dumps(data))
        assert len(deps) == 2

    def test_php_skipped(self):
        data = {"require": {"php": ">=8.1"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps == []

    def test_ext_skipped(self):
        data = {
            "require": {
                "ext-json": "*",
                "ext-mbstring": "*",
                "laravel/framework": "^10.0",
            }
        }
        deps = parse_composer_json(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "laravel/framework"

    def test_version_prefix_stripped(self):
        data = {"require": {"guzzlehttp/guzzle": "^7.2.0"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps[0].version == "7.2.0"

    def test_tilde_prefix_stripped(self):
        data = {"require": {"guzzlehttp/guzzle": "~7.2"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps[0].version == "7.2"

    def test_gte_prefix_stripped(self):
        data = {"require": {"guzzlehttp/guzzle": ">=7.2.0"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps[0].version == "7.2.0"

    def test_star_version_skipped(self):
        data = {"require": {"ext-json": "*"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps == []

    def test_dev_version_skipped(self):
        data = {"require": {"myvendor/mypackage": "dev-master"}}
        deps = parse_composer_json(json.dumps(data))
        assert deps == []

    def test_empty_require(self):
        data = {"require": {}}
        deps = parse_composer_json(json.dumps(data))
        assert deps == []

    def test_invalid_json(self):
        deps = parse_composer_json("not json")
        assert deps == []

    def test_empty_file(self):
        deps = parse_composer_json("{}")
        assert deps == []

    def test_non_dict_top_level(self):
        deps = parse_composer_json(json.dumps([1, 2, 3]))
        assert deps == []

    def test_returns_dependency_instances(self):
        data = {"require": {"laravel/framework": "^10.0"}}
        deps = parse_composer_json(json.dumps(data))
        assert isinstance(deps[0], Dependency)


# =======================================================================
# composer.lock
# =======================================================================


class TestParseComposerLock:
    """Tests for PHP composer.lock parsing."""

    def test_packages_section(self):
        data = {
            "packages": [
                {"name": "laravel/framework", "version": "v10.0.0"},
                {"name": "guzzlehttp/guzzle", "version": "7.5.0"},
            ],
            "packages-dev": [],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"laravel/framework", "guzzlehttp/guzzle"}
        assert all(d.ecosystem == "Packagist" for d in deps)

    def test_packages_dev_section(self):
        data = {
            "packages": [],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "10.2.0"},
                {"name": "laravel/pint", "version": "1.10.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"phpunit/phpunit", "laravel/pint"}

    def test_both_sections(self):
        data = {
            "packages": [
                {"name": "laravel/framework", "version": "v10.0.0"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "10.2.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert len(deps) == 2

    def test_v_prefix_stripped(self):
        data = {
            "packages": [
                {"name": "laravel/framework", "version": "v10.0.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert deps[0].version == "10.0.0"

    def test_no_v_prefix(self):
        data = {
            "packages": [
                {"name": "guzzlehttp/guzzle", "version": "7.5.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert deps[0].version == "7.5.0"

    def test_empty_packages(self):
        data = {"packages": [], "packages-dev": []}
        deps = parse_composer_lock(json.dumps(data))
        assert deps == []

    def test_missing_name_skipped(self):
        data = {
            "packages": [
                {"version": "1.0.0"},
                {"name": "valid/package", "version": "1.0.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "valid/package"

    def test_missing_version_skipped(self):
        data = {
            "packages": [
                {"name": "broken/package"},
                {"name": "valid/package", "version": "1.0.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert len(deps) == 1
        assert deps[0].name == "valid/package"

    def test_invalid_json(self):
        deps = parse_composer_lock("not json")
        assert deps == []

    def test_empty_file(self):
        deps = parse_composer_lock("{}")
        assert deps == []

    def test_non_dict_top_level(self):
        deps = parse_composer_lock(json.dumps([1, 2, 3]))
        assert deps == []

    def test_returns_dependency_instances(self):
        data = {
            "packages": [
                {"name": "laravel/framework", "version": "v10.0.0"},
            ],
        }
        deps = parse_composer_lock(json.dumps(data))
        assert isinstance(deps[0], Dependency)


# =======================================================================
# parse_manifest auto-detection (new formats)
# =======================================================================


class TestParseManifestNewFormats:
    """Tests for auto-detection of new manifest formats."""

    def test_package_lock_json(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        deps = parse_manifest(json.dumps(data), "package-lock.json")
        assert len(deps) == 1
        assert deps[0].ecosystem == "npm"

    def test_yarn_lock(self):
        text = 'lodash@^4.17.21:\n  version "4.17.21"\n'
        deps = parse_manifest(text, "yarn.lock")
        assert len(deps) == 1
        assert deps[0].ecosystem == "npm"

    def test_pnpm_lock_yaml(self):
        text = "packages:\n\n  /lodash@4.17.21:\n    resolution: {}\n"
        deps = parse_manifest(text, "pnpm-lock.yaml")
        assert len(deps) == 1
        assert deps[0].ecosystem == "npm"

    def test_pipfile_lock(self):
        data = {
            "_meta": {},
            "default": {"flask": {"version": "==2.3.0"}},
            "develop": {},
        }
        deps = parse_manifest(json.dumps(data), "Pipfile.lock")
        assert len(deps) == 1
        assert deps[0].ecosystem == "PyPI"

    def test_go_mod(self):
        text = "module myapp\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
        deps = parse_manifest(text, "go.mod")
        assert len(deps) == 1
        assert deps[0].ecosystem == "Go"

    def test_go_sum(self):
        text = "github.com/gin-gonic/gin v1.9.1 h1:abc=\n"
        deps = parse_manifest(text, "go.sum")
        assert len(deps) == 1
        assert deps[0].ecosystem == "Go"

    def test_composer_json(self):
        data = {"require": {"laravel/framework": "^10.0"}}
        deps = parse_manifest(json.dumps(data), "composer.json")
        assert len(deps) == 1
        assert deps[0].ecosystem == "Packagist"

    def test_composer_lock(self):
        data = {"packages": [{"name": "laravel/framework", "version": "v10.0.0"}]}
        deps = parse_manifest(json.dumps(data), "composer.lock")
        assert len(deps) == 1
        assert deps[0].ecosystem == "Packagist"

    def test_package_lock_json_full_path(self):
        data = {
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}},
        }
        deps = parse_manifest(json.dumps(data), "/home/user/project/package-lock.json")
        assert len(deps) == 1

    def test_go_mod_windows_path(self):
        text = "module myapp\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
        deps = parse_manifest(text, "C:\\Users\\project\\go.mod")
        assert len(deps) == 1

    def test_all_new_parsers_return_lists(self):
        assert isinstance(parse_package_lock_json("{}"), list)
        assert isinstance(parse_yarn_lock(""), list)
        assert isinstance(parse_pnpm_lock_yaml(""), list)
        assert isinstance(parse_pipfile_lock("{}"), list)
        assert isinstance(parse_go_mod(""), list)
        assert isinstance(parse_go_sum(""), list)
        assert isinstance(parse_composer_json("{}"), list)
        assert isinstance(parse_composer_lock("{}"), list)
