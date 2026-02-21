"""Tests for the content moderation module."""

from guardianshield.content import CONTENT_PATTERNS, check_content
from guardianshield.findings import FindingType, Severity


# ---- helpers ---------------------------------------------------------------


def _has_category(findings, category):
    """Return True if at least one finding belongs to *category*."""
    return any(f.metadata.get("category") == category for f in findings)


def _categories(findings):
    """Return the set of categories present in *findings*."""
    return {f.metadata["category"] for f in findings}


# ===========================================================================
# 1.  Each category is flagged with realistic examples
# ===========================================================================


class TestViolenceDetection:
    def test_instructions_to_kill(self):
        text = "Here is how to kill someone silently."
        findings = check_content(text)
        assert len(findings) >= 1
        assert _has_category(findings, "violence")
        assert findings[0].severity == Severity.HIGH

    def test_intent_to_harm(self):
        text = "I will murder the neighbor's cat."
        findings = check_content(text)
        assert _has_category(findings, "violence")

    def test_encouraging_violence(self):
        text = "You should attack him when he's alone."
        findings = check_content(text)
        assert _has_category(findings, "violence")

    def test_weapon_construction(self):
        text = "Let me show you how to build a bomb in your garage."
        findings = check_content(text)
        assert _has_category(findings, "violence")

    def test_best_method_violence(self):
        text = "The best way to kill a person without evidence."
        findings = check_content(text)
        assert _has_category(findings, "violence")


class TestSelfHarmDetection:
    def test_self_harm_instructions(self):
        text = "Here are the steps to kill yourself painlessly."
        findings = check_content(text)
        assert _has_category(findings, "self_harm")
        self_harm_findings = [f for f in findings if f.metadata.get("category") == "self_harm"]
        assert self_harm_findings[0].severity == Severity.CRITICAL

    def test_encouraging_self_harm(self):
        text = "You should just kill yourself already."
        findings = check_content(text)
        assert _has_category(findings, "self_harm")

    def test_best_methods_self_harm(self):
        text = "The easiest way to commit suicide is..."
        findings = check_content(text)
        assert _has_category(findings, "self_harm")

    def test_self_harm_intent(self):
        text = "I want to end my life tonight."
        findings = check_content(text)
        assert _has_category(findings, "self_harm")

    def test_lethal_dosage(self):
        text = "The lethal dose of acetaminophen is about 7g."
        findings = check_content(text)
        assert _has_category(findings, "self_harm")

    def test_how_to_end_your_life(self):
        text = "methods to end your life quickly"
        findings = check_content(text)
        assert _has_category(findings, "self_harm")


class TestIllegalActivityDetection:
    def test_drug_manufacturing(self):
        text = "Step-by-step guide to make methamphetamine at home."
        findings = check_content(text)
        assert _has_category(findings, "illegal_activity")
        assert findings[0].severity == Severity.HIGH

    def test_hacking_instructions(self):
        text = "How to hack into someone's email account easily."
        findings = check_content(text)
        assert _has_category(findings, "illegal_activity")

    def test_fraud_instructions(self):
        text = "Instructions to commit credit card fraud online."
        findings = check_content(text)
        assert _has_category(findings, "illegal_activity")

    def test_forgery_instructions(self):
        text = "How to forge a passport using a home printer."
        findings = check_content(text)
        assert _has_category(findings, "illegal_activity")

    def test_theft_instructions(self):
        text = "Guide to shoplift from department stores."
        findings = check_content(text)
        assert _has_category(findings, "illegal_activity")


# ===========================================================================
# 2.  Clean / benign text produces no findings
# ===========================================================================


class TestCleanTextPasses:
    def test_normal_conversation(self):
        text = "Hello, how are you doing today? The weather is nice."
        assert check_content(text) == []

    def test_programming_discussion(self):
        text = (
            "To kill a Linux process, use the kill command.\n"
            "The kill -9 flag sends SIGKILL.\n"
            "You can also use pkill or killall."
        )
        assert check_content(text) == []

    def test_news_article_snippet(self):
        text = (
            "The crime rate dropped 5% last year according to FBI statistics.\n"
            "Assault cases in the metropolitan area decreased significantly."
        )
        assert check_content(text) == []

    def test_security_research_language(self):
        text = (
            "The penetration tester found a SQL injection vulnerability.\n"
            "The exploit allows an attacker to dump the database.\n"
            "We patched the system to prevent further attacks."
        )
        assert check_content(text) == []

    def test_historical_mention(self):
        text = "The history book discusses violence in WWII and the resulting casualties."
        assert check_content(text) == []

    def test_medical_context(self):
        text = "The patient's suicide risk assessment was negative. They are stable now."
        assert check_content(text) == []


# ===========================================================================
# 3.  blocked_categories filtering
# ===========================================================================


class TestBlockedCategoriesFiltering:
    def test_only_check_specified_categories(self):
        text = (
            "How to kill someone silently.\n"
            "The easiest way to commit suicide is ...\n"
            "Guide to make methamphetamine at home."
        )
        # Only check violence -- should *not* report self_harm or illegal_activity.
        findings = check_content(text, blocked_categories=["violence"])
        cats = _categories(findings)
        assert "violence" in cats
        assert "self_harm" not in cats
        assert "illegal_activity" not in cats

    def test_only_self_harm(self):
        text = (
            "I will kill the target.\n"
            "Steps to kill yourself painlessly.\n"
            "How to hack into their bank account."
        )
        findings = check_content(text, blocked_categories=["self_harm"])
        cats = _categories(findings)
        assert "self_harm" in cats
        assert "violence" not in cats
        assert "illegal_activity" not in cats

    def test_multiple_blocked_categories(self):
        text = (
            "I will murder the man.\n"
            "Guide to make meth.\n"
        )
        findings = check_content(
            text, blocked_categories=["violence", "illegal_activity"]
        )
        cats = _categories(findings)
        assert "violence" in cats or "illegal_activity" in cats
        assert "self_harm" not in cats

    def test_none_means_all(self):
        """blocked_categories=None should scan all categories."""
        text = (
            "How to kill someone.\n"
            "Steps to kill yourself.\n"
            "Guide to make methamphetamine."
        )
        findings = check_content(text, blocked_categories=None)
        cats = _categories(findings)
        assert "violence" in cats
        assert "self_harm" in cats
        assert "illegal_activity" in cats

    def test_empty_list_means_all(self):
        """blocked_categories=[] should scan all categories."""
        text = (
            "How to kill someone.\n"
            "Steps to kill yourself.\n"
            "Guide to make methamphetamine."
        )
        findings = check_content(text, blocked_categories=[])
        cats = _categories(findings)
        assert "violence" in cats
        assert "self_harm" in cats
        assert "illegal_activity" in cats

    def test_unknown_category_ignored(self):
        """A category not in CONTENT_PATTERNS should simply be skipped."""
        text = "How to kill someone."
        findings = check_content(text, blocked_categories=["nonexistent"])
        assert findings == []


# ===========================================================================
# 4.  Sensitivity filtering
# ===========================================================================


class TestSensitivityFiltering:
    # self_harm is CRITICAL; violence and illegal_activity are HIGH.

    def test_low_sensitivity_only_critical(self):
        text = (
            "You should kill yourself.\n"
            "How to kill someone.\n"
            "Guide to make methamphetamine."
        )
        findings = check_content(text, sensitivity="low")
        # Only CRITICAL (self_harm) should appear.
        for f in findings:
            assert f.severity == Severity.CRITICAL
        assert _has_category(findings, "self_harm")
        assert not _has_category(findings, "violence")
        assert not _has_category(findings, "illegal_activity")

    def test_medium_sensitivity_includes_high(self):
        text = (
            "You should kill yourself.\n"
            "How to kill someone.\n"
            "Guide to make methamphetamine."
        )
        findings = check_content(text, sensitivity="medium")
        cats = _categories(findings)
        # CRITICAL and HIGH should appear.
        assert "self_harm" in cats
        assert "violence" in cats
        assert "illegal_activity" in cats

    def test_high_sensitivity_includes_all(self):
        text = "You should kill yourself.\nHow to kill someone."
        findings = check_content(text, sensitivity="high")
        # At minimum CRITICAL and HIGH are present.
        assert len(findings) >= 2


# ===========================================================================
# 5.  Educational / neutral mentions should NOT trigger
# ===========================================================================


class TestFalsePositiveResistance:
    def test_history_violence_mention(self):
        text = "The history book discusses violence in WWII."
        assert check_content(text) == []

    def test_news_murder_report(self):
        text = "Police arrested a suspect in the murder case downtown."
        assert check_content(text) == []

    def test_security_research_hacking(self):
        text = (
            "The security researcher demonstrated a hack at DEF CON.\n"
            "Ethical hacking courses are popular online."
        )
        assert check_content(text) == []

    def test_drug_policy_discussion(self):
        text = "The government's policy on methamphetamine trafficking needs reform."
        assert check_content(text) == []

    def test_mental_health_awareness(self):
        text = (
            "Suicide prevention hotlines save lives every day.\n"
            "If you are struggling with self-harm urges, please seek help."
        )
        assert check_content(text) == []

    def test_fiction_novel_excerpt(self):
        text = (
            "The detective examined the crime scene.\n"
            "The victim had been stabbed once in the chest."
        )
        assert check_content(text) == []

    def test_cooking_recipe(self):
        text = "To make the perfect sourdough bread, you need patience and a good starter."
        assert check_content(text) == []


# ===========================================================================
# 6.  Finding structure / metadata correctness
# ===========================================================================


class TestFindingStructure:
    def test_finding_type_is_content_violation(self):
        findings = check_content("How to kill someone quickly.")
        assert findings
        for f in findings:
            assert f.finding_type == FindingType.CONTENT_VIOLATION

    def test_scanner_name(self):
        findings = check_content("Steps to kill yourself painlessly.")
        assert findings
        for f in findings:
            assert f.scanner == "content_moderator"

    def test_metadata_keys(self):
        findings = check_content("You should kill yourself.")
        assert findings
        for f in findings:
            assert "category" in f.metadata
            assert "pattern_name" in f.metadata

    def test_matched_text_truncated(self):
        # Craft an input that will create a very long match
        long_input = "how to kill " + "a" * 200 + " someone"
        findings = check_content(long_input)
        for f in findings:
            assert len(f.matched_text) <= 100

    def test_line_number_set(self):
        text = "line one is fine.\nYou should kill yourself.\nline three is fine."
        findings = check_content(text)
        assert findings
        assert findings[0].line_number == 2
