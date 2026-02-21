"""Tests for the PII detection module."""

from guardianshield.findings import FindingType, Severity
from guardianshield.pii import check_pii


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _find_by_pii_type(findings, pii_type):
    """Return findings whose metadata pii_type matches *pii_type*."""
    return [f for f in findings if f.metadata.get("pii_type") == pii_type]


# ---------------------------------------------------------------------------
# Individual PII type detection
# ---------------------------------------------------------------------------


class TestEmailDetection:
    def test_simple_email(self):
        findings = check_pii("Contact us at alice@example.com for info.", sensitivity="high")
        emails = _find_by_pii_type(findings, "email")
        assert len(emails) >= 1
        f = emails[0]
        assert f.finding_type == FindingType.PII_LEAK
        assert f.severity == Severity.MEDIUM
        assert f.scanner == "pii_detector"

    def test_email_with_plus(self):
        findings = check_pii("Send to user+tag@domain.org", sensitivity="high")
        emails = _find_by_pii_type(findings, "email")
        assert len(emails) >= 1

    def test_email_redaction(self):
        findings = check_pii("Email: test@secret.com", sensitivity="high")
        emails = _find_by_pii_type(findings, "email")
        assert len(emails) >= 1
        assert "test@secret.com" not in emails[0].matched_text
        assert emails[0].matched_text == "***@***.***"


class TestSSNDetection:
    def test_standard_ssn(self):
        findings = check_pii("My SSN is 123-45-6789")
        ssns = _find_by_pii_type(findings, "ssn")
        assert len(ssns) >= 1
        assert ssns[0].severity == Severity.CRITICAL

    def test_ssn_redaction(self):
        findings = check_pii("SSN: 987-65-4321")
        ssns = _find_by_pii_type(findings, "ssn")
        assert len(ssns) >= 1
        assert "987-65-4321" not in ssns[0].matched_text
        assert ssns[0].matched_text == "***-**-****"


class TestCreditCardDetection:
    def test_visa_number(self):
        findings = check_pii("Card: 4111111111111111")
        cards = _find_by_pii_type(findings, "credit_card")
        assert len(cards) >= 1
        assert cards[0].severity == Severity.CRITICAL

    def test_card_with_spaces(self):
        findings = check_pii("Card: 4111 1111 1111 1111")
        cards = _find_by_pii_type(findings, "credit_card")
        assert len(cards) >= 1

    def test_card_with_dashes(self):
        findings = check_pii("Card: 4111-1111-1111-1111")
        cards = _find_by_pii_type(findings, "credit_card")
        assert len(cards) >= 1

    def test_credit_card_redaction(self):
        findings = check_pii("Pay with 4111111111111111")
        cards = _find_by_pii_type(findings, "credit_card")
        assert len(cards) >= 1
        assert "4111111111111111" not in cards[0].matched_text
        assert cards[0].matched_text == "****...****"


class TestPhoneDetection:
    def test_parenthesized_phone(self):
        findings = check_pii("Call (555) 123-4567 for help.", sensitivity="high")
        phones = _find_by_pii_type(findings, "phone")
        assert len(phones) >= 1
        assert phones[0].severity == Severity.MEDIUM

    def test_dashed_phone(self):
        findings = check_pii("Phone: 555-123-4567", sensitivity="high")
        phones = _find_by_pii_type(findings, "phone")
        assert len(phones) >= 1

    def test_plus1_phone(self):
        findings = check_pii("Dial +15551234567", sensitivity="high")
        phones = _find_by_pii_type(findings, "phone")
        assert len(phones) >= 1

    def test_phone_redaction(self):
        findings = check_pii("Ring (800) 555-0199", sensitivity="high")
        phones = _find_by_pii_type(findings, "phone")
        assert len(phones) >= 1
        assert "(800) 555-0199" not in phones[0].matched_text
        assert phones[0].matched_text == "(***) ***-****"


class TestIPAddressDetection:
    def test_ipv4(self):
        findings = check_pii("Server at 192.168.1.100", sensitivity="high")
        ips = _find_by_pii_type(findings, "ip_address")
        assert len(ips) >= 1
        assert ips[0].severity == Severity.LOW

    def test_ip_redaction(self):
        findings = check_pii("IP: 10.0.0.1", sensitivity="high")
        ips = _find_by_pii_type(findings, "ip_address")
        assert len(ips) >= 1
        assert "10.0.0.1" not in ips[0].matched_text
        assert ips[0].matched_text == "***.***.***.***"


class TestDateOfBirthDetection:
    def test_dob_prefix(self):
        findings = check_pii("DOB: 01/15/1990", sensitivity="high")
        dobs = _find_by_pii_type(findings, "date_of_birth")
        assert len(dobs) >= 1
        assert dobs[0].severity == Severity.MEDIUM

    def test_born_on_prefix(self):
        findings = check_pii("She was born on 03/22/1985", sensitivity="high")
        dobs = _find_by_pii_type(findings, "date_of_birth")
        assert len(dobs) >= 1

    def test_date_of_birth_prefix(self):
        findings = check_pii("Date of birth: 12/25/2000", sensitivity="high")
        dobs = _find_by_pii_type(findings, "date_of_birth")
        assert len(dobs) >= 1

    def test_dob_redaction(self):
        findings = check_pii("DOB: 07/04/1776", sensitivity="high")
        dobs = _find_by_pii_type(findings, "date_of_birth")
        assert len(dobs) >= 1
        assert "07/04/1776" not in dobs[0].matched_text
        assert dobs[0].matched_text == "DOB: **/**/****"


class TestPhysicalAddressDetection:
    def test_street_address(self):
        findings = check_pii("I live at 123 Main Street, Springfield, IL 62704", sensitivity="high")
        addrs = _find_by_pii_type(findings, "physical_address")
        assert len(addrs) >= 1
        assert addrs[0].severity == Severity.LOW

    def test_abbreviated_address(self):
        findings = check_pii("Office at 456 Oak Ave", sensitivity="high")
        addrs = _find_by_pii_type(findings, "physical_address")
        assert len(addrs) >= 1

    def test_address_redaction(self):
        findings = check_pii("Ship to 789 Elm Blvd", sensitivity="high")
        addrs = _find_by_pii_type(findings, "physical_address")
        assert len(addrs) >= 1
        assert "789 Elm Blvd" not in addrs[0].matched_text
        assert addrs[0].matched_text == "*** [ADDRESS REDACTED]"


# ---------------------------------------------------------------------------
# Sensitivity filtering
# ---------------------------------------------------------------------------


class TestSensitivityFiltering:
    """Verify that the sensitivity parameter controls which findings appear."""

    MIXED_TEXT = "SSN: 123-45-6789, email: a@b.com, IP: 10.0.0.1"

    def test_low_sensitivity_only_critical(self):
        findings = check_pii(self.MIXED_TEXT, sensitivity="low")
        for f in findings:
            assert f.severity == Severity.CRITICAL

    def test_medium_sensitivity_skips_low(self):
        findings = check_pii(self.MIXED_TEXT, sensitivity="medium")
        for f in findings:
            assert f.severity != Severity.LOW
        # Should still include CRITICAL and MEDIUM
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities

    def test_high_sensitivity_includes_all(self):
        findings = check_pii(self.MIXED_TEXT, sensitivity="high")
        severities = {f.severity for f in findings}
        # We expect at least CRITICAL (SSN) and LOW (IP) to appear.
        assert Severity.CRITICAL in severities
        assert Severity.LOW in severities


# ---------------------------------------------------------------------------
# Clean text
# ---------------------------------------------------------------------------


class TestCleanText:
    def test_no_pii(self):
        findings = check_pii("The quick brown fox jumps over the lazy dog.")
        assert findings == []

    def test_empty_string(self):
        findings = check_pii("")
        assert findings == []

    def test_code_without_pii(self):
        findings = check_pii("def hello():\n    print('world')\n")
        assert findings == []


# ---------------------------------------------------------------------------
# Presidio fallback
# ---------------------------------------------------------------------------


class TestPresidioFallback:
    def test_fallback_when_presidio_not_installed(self):
        """When presidio is not installed, use_presidio=True should fall back
        to the regex engine and still produce findings."""
        text = "My SSN is 123-45-6789"
        findings = check_pii(text, use_presidio=True)
        ssns = _find_by_pii_type(findings, "ssn")
        assert len(ssns) >= 1
        assert ssns[0].severity == Severity.CRITICAL
        assert ssns[0].matched_text == "***-**-****"


# ---------------------------------------------------------------------------
# Multiple PII types in one text
# ---------------------------------------------------------------------------


class TestMultiplePIITypes:
    def test_mixed_pii(self):
        text = (
            "Name: John Doe\n"
            "Email: john.doe@example.com\n"
            "SSN: 111-22-3333\n"
            "Phone: (555) 987-6543\n"
            "IP: 172.16.0.1\n"
            "DOB: 06/15/1992\n"
            "Address: 42 Wallaby Way, Sydney, CA 90210\n"
        )
        findings = check_pii(text, sensitivity="high")
        pii_types_found = {f.metadata["pii_type"] for f in findings}
        assert "email" in pii_types_found
        assert "ssn" in pii_types_found
        assert "phone" in pii_types_found
        assert "ip_address" in pii_types_found
        assert "date_of_birth" in pii_types_found
        assert "physical_address" in pii_types_found

    def test_mixed_pii_line_numbers(self):
        text = "SSN: 123-45-6789\nEmail: x@y.com"
        findings = check_pii(text, sensitivity="high")
        ssn_findings = _find_by_pii_type(findings, "ssn")
        email_findings = _find_by_pii_type(findings, "email")
        assert ssn_findings[0].line_number == 1
        assert email_findings[0].line_number == 2

    def test_all_findings_use_correct_type(self):
        text = "SSN 999-88-7777 and email foo@bar.baz"
        findings = check_pii(text, sensitivity="high")
        for f in findings:
            assert f.finding_type == FindingType.PII_LEAK
            assert f.scanner == "pii_detector"
            assert "pii_type" in f.metadata

    def test_no_raw_pii_in_matched_text(self):
        """Ensure none of the matched_text fields contain actual PII values."""
        text = (
            "SSN: 123-45-6789\n"
            "Email: secret@domain.com\n"
            "Card: 4111111111111111\n"
            "Phone: (800) 555-0123\n"
        )
        raw_values = [
            "123-45-6789",
            "secret@domain.com",
            "4111111111111111",
            "(800) 555-0123",
        ]
        findings = check_pii(text, sensitivity="high")
        for f in findings:
            for raw in raw_values:
                assert raw not in f.matched_text
