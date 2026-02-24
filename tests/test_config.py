"""Tests for project configuration discovery."""

import json
import os

import pytest

from guardianshield.config import ProjectConfig, discover_config, load_config
from guardianshield.core import GuardianShield


# -- ProjectConfig dataclass --------------------------------------------------


class TestProjectConfigDefaults:
    def test_defaults(self):
        cfg = ProjectConfig()
        assert cfg.profile is None
        assert cfg.severity_overrides == {}
        assert cfg.exclude_paths == []
        assert cfg.custom_patterns == []
        assert cfg.config_path is None

    def test_to_dict_empty(self):
        cfg = ProjectConfig()
        assert cfg.to_dict() == {}

    def test_to_dict_all_fields(self):
        cfg = ProjectConfig(
            profile="finance",
            severity_overrides={"sql_injection": "critical"},
            exclude_paths=["vendor/*"],
            custom_patterns=[{"name": "custom1", "pattern": "xyz"}],
            config_path="/tmp/test.json",
        )
        d = cfg.to_dict()
        assert d["profile"] == "finance"
        assert d["severity_overrides"] == {"sql_injection": "critical"}
        assert d["exclude_paths"] == ["vendor/*"]
        assert d["custom_patterns"] == [{"name": "custom1", "pattern": "xyz"}]
        assert d["config_path"] == "/tmp/test.json"

    def test_from_dict_all_fields(self):
        data = {
            "profile": "healthcare",
            "severity_overrides": {"xss": "high"},
            "exclude_paths": ["build/*", "dist/*"],
            "custom_patterns": [{"name": "p1"}],
        }
        cfg = ProjectConfig.from_dict(data, config_path="/some/path.json")
        assert cfg.profile == "healthcare"
        assert cfg.severity_overrides == {"xss": "high"}
        assert cfg.exclude_paths == ["build/*", "dist/*"]
        assert cfg.custom_patterns == [{"name": "p1"}]
        assert cfg.config_path == "/some/path.json"

    def test_from_dict_empty(self):
        cfg = ProjectConfig.from_dict({})
        assert cfg.profile is None
        assert cfg.severity_overrides == {}
        assert cfg.exclude_paths == []
        assert cfg.custom_patterns == []
        assert cfg.config_path is None


# -- load_config --------------------------------------------------------------


class TestLoadConfig:
    def test_load_json(self, tmp_path):
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text(
            json.dumps({"profile": "finance", "exclude_paths": ["vendor/*"]})
        )
        cfg = load_config(str(config_file))
        assert cfg.profile == "finance"
        assert cfg.exclude_paths == ["vendor/*"]
        assert cfg.config_path == str(config_file)

    def test_load_json_invalid(self, tmp_path):
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text("{invalid json")
        with pytest.raises(json.JSONDecodeError):
            load_config(str(config_file))

    def test_load_missing_file(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        with pytest.raises(FileNotFoundError):
            load_config(path)

    def test_load_unsupported_extension(self, tmp_path):
        config_file = tmp_path / ".guardianshield.toml"
        config_file.write_text("")
        with pytest.raises(ValueError, match="Unsupported config format"):
            load_config(str(config_file))

    def test_load_yaml(self, tmp_path):
        """YAML loading works when PyYAML is available."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        config_file = tmp_path / ".guardianshield.yaml"
        config_file.write_text("profile: education\nexclude_paths:\n  - tests/*\n")
        cfg = load_config(str(config_file))
        assert cfg.profile == "education"
        assert cfg.exclude_paths == ["tests/*"]

    def test_load_yml_extension(self, tmp_path):
        """Also supports .yml extension."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        config_file = tmp_path / ".guardianshield.yml"
        config_file.write_text("profile: children\n")
        cfg = load_config(str(config_file))
        assert cfg.profile == "children"


# -- discover_config ----------------------------------------------------------


class TestDiscoverConfig:
    def test_finds_config_in_current_dir(self, tmp_path):
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text(json.dumps({"profile": "finance"}))
        cfg = discover_config(start_dir=str(tmp_path))
        assert cfg is not None
        assert cfg.profile == "finance"

    def test_finds_config_in_parent_dir(self, tmp_path):
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text(json.dumps({"profile": "healthcare"}))
        child = tmp_path / "subdir"
        child.mkdir()
        cfg = discover_config(start_dir=str(child))
        assert cfg is not None
        assert cfg.profile == "healthcare"

    def test_returns_none_when_no_config(self, tmp_path):
        cfg = discover_config(start_dir=str(tmp_path), max_depth=1)
        assert cfg is None

    def test_json_takes_priority_over_yaml(self, tmp_path):
        """JSON config is found before YAML when both exist."""
        json_file = tmp_path / ".guardianshield.json"
        json_file.write_text(json.dumps({"profile": "finance"}))

        try:
            import yaml

            yaml_file = tmp_path / ".guardianshield.yaml"
            yaml_file.write_text("profile: education\n")
        except ImportError:
            pass  # Only JSON present, still tests priority

        cfg = discover_config(start_dir=str(tmp_path))
        assert cfg is not None
        assert cfg.profile == "finance"

    def test_respects_max_depth(self, tmp_path):
        """Config in a grandparent should not be found with max_depth=1."""
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text(json.dumps({"profile": "finance"}))

        child = tmp_path / "a"
        child.mkdir()
        grandchild = child / "b"
        grandchild.mkdir()

        # max_depth=1 means: check grandchild, then check child, stop.
        # The config is in tmp_path (2 levels up), so it should not be found.
        cfg = discover_config(start_dir=str(grandchild), max_depth=2)
        assert cfg is None

    def test_finds_config_at_exact_max_depth(self, tmp_path):
        """Config should be found when it's exactly at max_depth levels up."""
        config_file = tmp_path / ".guardianshield.json"
        config_file.write_text(json.dumps({"profile": "education"}))

        child = tmp_path / "level1"
        child.mkdir()

        cfg = discover_config(start_dir=str(child), max_depth=2)
        assert cfg is not None
        assert cfg.profile == "education"

    def test_stops_at_filesystem_root(self, tmp_path):
        """Should not error when traversal hits filesystem root."""
        cfg = discover_config(start_dir=str(tmp_path), max_depth=1000)
        # May or may not find a config depending on the machine, but must not crash.
        # We just check it returns None or a ProjectConfig.
        assert cfg is None or isinstance(cfg, ProjectConfig)


# -- Core integration ---------------------------------------------------------


class TestCoreIntegration:
    def test_shield_uses_project_config_profile(self, tmp_path):
        db = str(tmp_path / "audit.db")
        pc = ProjectConfig(profile="healthcare")
        s = GuardianShield(audit_path=db, project_config=pc)
        assert s.profile.name == "healthcare"
        s.close()

    def test_explicit_profile_overrides_config(self, tmp_path):
        db = str(tmp_path / "audit.db")
        pc = ProjectConfig(profile="healthcare")
        s = GuardianShield(profile="finance", audit_path=db, project_config=pc)
        assert s.profile.name == "finance"
        s.close()

    def test_shield_without_project_config(self, tmp_path):
        db = str(tmp_path / "audit.db")
        s = GuardianShield(audit_path=db)
        assert s.project_config is None
        s.close()

    def test_status_includes_project_config(self, tmp_path):
        db = str(tmp_path / "audit.db")
        pc = ProjectConfig(
            profile="finance",
            exclude_paths=["vendor/*"],
        )
        s = GuardianShield(audit_path=db, project_config=pc)
        status = s.status()
        assert "project_config" in status
        assert status["project_config"]["profile"] == "finance"
        assert status["project_config"]["exclude_paths"] == ["vendor/*"]
        s.close()

    def test_status_omits_project_config_when_none(self, tmp_path):
        db = str(tmp_path / "audit.db")
        s = GuardianShield(audit_path=db)
        status = s.status()
        assert "project_config" not in status
        s.close()

    def test_project_config_property(self, tmp_path):
        db = str(tmp_path / "audit.db")
        pc = ProjectConfig(profile="education", exclude_paths=["dist/*"])
        s = GuardianShield(audit_path=db, project_config=pc)
        assert s.project_config is pc
        assert s.project_config.exclude_paths == ["dist/*"]
        s.close()
