"""Tests for safety profiles."""

import pytest

from guardianshield.profiles import (
    BUILTIN_PROFILES,
    SafetyProfile,
    ScannerConfig,
    list_profiles,
    load_profile,
)


# ---------------------------------------------------------------------------
# ScannerConfig defaults
# ---------------------------------------------------------------------------


class TestScannerConfigDefaults:
    def test_enabled_default(self) -> None:
        cfg = ScannerConfig()
        assert cfg.enabled is True

    def test_sensitivity_default(self) -> None:
        cfg = ScannerConfig()
        assert cfg.sensitivity == "medium"

    def test_custom_patterns_default(self) -> None:
        cfg = ScannerConfig()
        assert cfg.custom_patterns == []

    def test_custom_patterns_independent(self) -> None:
        """Each instance should get its own list."""
        a = ScannerConfig()
        b = ScannerConfig()
        a.custom_patterns.append("foo")
        assert b.custom_patterns == []


# ---------------------------------------------------------------------------
# Load each built-in profile
# ---------------------------------------------------------------------------


class TestLoadBuiltinProfiles:
    @pytest.mark.parametrize("name", ["general", "education", "healthcare", "finance", "children"])
    def test_load_profile(self, name: str) -> None:
        profile = load_profile(name)
        assert isinstance(profile, SafetyProfile)
        assert profile.name == name

    def test_general_profile(self) -> None:
        p = load_profile("general")
        assert p.code_scanner.sensitivity == "medium"
        assert p.secret_scanner.sensitivity == "medium"
        assert p.blocked_categories == []

    def test_education_profile(self) -> None:
        p = load_profile("education")
        assert p.code_scanner.sensitivity == "medium"
        assert "violence" in p.blocked_categories
        assert "self_harm" in p.blocked_categories

    def test_healthcare_profile(self) -> None:
        p = load_profile("healthcare")
        assert p.code_scanner.sensitivity == "high"
        assert p.pii_detector.sensitivity == "high"
        assert "violence" in p.blocked_categories

    def test_finance_profile(self) -> None:
        p = load_profile("finance")
        assert p.secret_scanner.sensitivity == "high"
        assert "illegal_activity" in p.blocked_categories

    def test_children_profile(self) -> None:
        p = load_profile("children")
        assert p.content_moderator.sensitivity == "high"
        assert set(p.blocked_categories) == {"violence", "self_harm", "illegal_activity"}


# ---------------------------------------------------------------------------
# from_dict / to_dict round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_scanner_config_round_trip(self) -> None:
        original = ScannerConfig(enabled=False, sensitivity="high", custom_patterns=["abc"])
        restored = ScannerConfig.from_dict(original.to_dict())
        assert restored.enabled == original.enabled
        assert restored.sensitivity == original.sensitivity
        assert restored.custom_patterns == original.custom_patterns

    def test_safety_profile_round_trip(self) -> None:
        original = load_profile("healthcare")
        d = original.to_dict()
        restored = SafetyProfile.from_dict(d)
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.code_scanner.sensitivity == original.code_scanner.sensitivity
        assert restored.secret_scanner.sensitivity == original.secret_scanner.sensitivity
        assert restored.injection_detector.sensitivity == original.injection_detector.sensitivity
        assert restored.pii_detector.sensitivity == original.pii_detector.sensitivity
        assert restored.content_moderator.sensitivity == original.content_moderator.sensitivity
        assert restored.blocked_categories == original.blocked_categories

    def test_round_trip_all_profiles(self) -> None:
        for name in BUILTIN_PROFILES:
            profile = load_profile(name)
            d = profile.to_dict()
            restored = SafetyProfile.from_dict(d)
            assert restored.to_dict() == d


# ---------------------------------------------------------------------------
# Unknown profile raises ValueError
# ---------------------------------------------------------------------------


class TestUnknownProfile:
    def test_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown safety profile"):
            load_profile("nonexistent_profile")

    def test_error_message_contains_name(self) -> None:
        with pytest.raises(ValueError, match="nonexistent_profile"):
            load_profile("nonexistent_profile")


# ---------------------------------------------------------------------------
# list_profiles returns all 5
# ---------------------------------------------------------------------------


class TestListProfiles:
    def test_returns_all_five(self) -> None:
        names = list_profiles()
        assert len(names) >= 5
        for expected in ("general", "education", "healthcare", "finance", "children"):
            assert expected in names

    def test_sorted(self) -> None:
        names = list_profiles()
        assert names == sorted(names)

    def test_returns_list_of_strings(self) -> None:
        names = list_profiles()
        assert isinstance(names, list)
        for n in names:
            assert isinstance(n, str)
