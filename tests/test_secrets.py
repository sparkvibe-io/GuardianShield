"""Tests for the secret/credential detection scanner."""

from guardianshield.findings import FindingType, Severity
from guardianshield.secrets import check_secrets

# -----------------------------------------------------------------------
# 1. AWS Access Key
# -----------------------------------------------------------------------

def test_aws_access_key():
    text = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
    findings = check_secrets(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.SECRET
    assert f.severity == Severity.CRITICAL
    assert f.metadata["secret_type"] == "AWS Access Key"
    assert f.line_number == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in f.matched_text
    assert f.matched_text.startswith("AKIA")


# -----------------------------------------------------------------------
# 2. AWS Secret Key
# -----------------------------------------------------------------------

def test_aws_secret_key():
    text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = check_secrets(text)
    assert any(f.metadata["secret_type"] == "AWS Secret Key" for f in findings)
    secret_finding = next(f for f in findings if f.metadata["secret_type"] == "AWS Secret Key")
    assert secret_finding.severity == Severity.CRITICAL
    # Full secret must not appear in matched_text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in secret_finding.matched_text


# -----------------------------------------------------------------------
# 3. GitHub Token
# -----------------------------------------------------------------------

def test_github_personal_access_token():
    text = 'GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl'
    findings = check_secrets(text)
    assert len(findings) >= 1
    f = next(f for f in findings if f.metadata["secret_type"] == "GitHub Token")
    assert f.severity == Severity.HIGH
    assert f.matched_text.startswith("ghp_")
    assert "REDACTED" in f.matched_text


def test_github_fine_grained_pat():
    text = 'token = "github_pat_ABCDEFGHIJKLMNOPQRSTUV1234567890abcdefghij"'
    findings = check_secrets(text)
    types = [f.metadata["secret_type"] for f in findings]
    assert "GitHub Token" in types


# -----------------------------------------------------------------------
# 4. Stripe Keys
# -----------------------------------------------------------------------

def test_stripe_live_key_critical():
    text = 'stripe_key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz"'
    findings = check_secrets(text)
    stripe = [f for f in findings if "Stripe" in f.metadata["secret_type"]]
    assert len(stripe) >= 1
    assert stripe[0].severity == Severity.CRITICAL


def test_stripe_test_key_high():
    text = 'stripe_key = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXyz"'
    findings = check_secrets(text)
    stripe = [f for f in findings if "Stripe" in f.metadata["secret_type"]]
    assert len(stripe) >= 1
    assert stripe[0].severity == Severity.HIGH


def test_stripe_pk_live():
    text = 'pk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz'
    findings = check_secrets(text)
    stripe = [f for f in findings if f.metadata["secret_type"] == "Stripe Live Key"]
    assert len(stripe) == 1
    assert stripe[0].severity == Severity.CRITICAL


# -----------------------------------------------------------------------
# 5. Private Keys
# -----------------------------------------------------------------------

def test_rsa_private_key():
    text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds...'
    findings = check_secrets(text)
    assert any(f.metadata["secret_type"] == "Private Key" for f in findings)
    pk = next(f for f in findings if f.metadata["secret_type"] == "Private Key")
    assert pk.severity == Severity.CRITICAL


def test_openssh_private_key():
    text = '-----BEGIN OPENSSH PRIVATE KEY-----'
    findings = check_secrets(text)
    assert any(f.metadata["secret_type"] == "Private Key" for f in findings)


def test_ec_private_key():
    text = '-----BEGIN EC PRIVATE KEY-----'
    findings = check_secrets(text)
    assert any(f.metadata["secret_type"] == "Private Key" for f in findings)


# -----------------------------------------------------------------------
# 6. JWT
# -----------------------------------------------------------------------

def test_jwt_detection():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings = check_secrets(token)
    assert any(f.metadata["secret_type"] == "JWT" for f in findings)
    jwt_finding = next(f for f in findings if f.metadata["secret_type"] == "JWT")
    assert jwt_finding.severity == Severity.MEDIUM


# -----------------------------------------------------------------------
# 7. Slack Tokens
# -----------------------------------------------------------------------

def test_slack_bot_token():
    text = 'SLACK_TOKEN="xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUv"'
    findings = check_secrets(text)
    slack = [f for f in findings if f.metadata["secret_type"] == "Slack Token"]
    assert len(slack) >= 1
    assert slack[0].severity == Severity.HIGH
    assert "REDACTED" in slack[0].matched_text


def test_slack_user_token():
    text = 'token = "xoxp-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUv"'
    findings = check_secrets(text)
    types = [f.metadata["secret_type"] for f in findings]
    assert "Slack Token" in types


# -----------------------------------------------------------------------
# 8. Password Assignments
# -----------------------------------------------------------------------

def test_password_in_assignment():
    text = 'password = "SuperS3cretP@ss!"'
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) == 1
    assert pw[0].severity == Severity.MEDIUM
    # Entire password must be fully redacted
    assert "SuperS3cretP@ss!" not in pw[0].matched_text
    assert pw[0].matched_text == "***REDACTED***"


def test_passwd_variant():
    text = "db_passwd = 'mydbpassword'"
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) >= 1


def test_pwd_variant():
    text = 'pwd: "anotherSecret"'
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) >= 1


# -----------------------------------------------------------------------
# 9. Connection Strings
# -----------------------------------------------------------------------

def test_postgres_connection_string():
    text = 'DATABASE_URL = "postgres://user:password@localhost:5432/mydb"'
    findings = check_secrets(text)
    cs = [f for f in findings if f.metadata["secret_type"] == "Connection String"]
    assert len(cs) >= 1
    assert cs[0].severity == Severity.HIGH


def test_mongodb_connection_string():
    text = 'MONGO_URI = "mongodb://admin:secret@mongo.example.com:27017/app"'
    findings = check_secrets(text)
    cs = [f for f in findings if f.metadata["secret_type"] == "Connection String"]
    assert len(cs) >= 1


def test_redis_connection_string():
    text = 'REDIS_URL="redis://default:mypassword@redis.example.com:6379"'
    findings = check_secrets(text)
    cs = [f for f in findings if f.metadata["secret_type"] == "Connection String"]
    assert len(cs) >= 1


def test_mysql_connection_string():
    text = 'mysql://root:password@127.0.0.1:3306/testdb'
    findings = check_secrets(text)
    cs = [f for f in findings if f.metadata["secret_type"] == "Connection String"]
    assert len(cs) >= 1


# -----------------------------------------------------------------------
# 10. Google API Key
# -----------------------------------------------------------------------

def test_google_api_key():
    text = 'GOOGLE_API_KEY = "AIzaSyA1bcDeFgHiJkLmNoPqRsTuVwXyZ012345"'
    findings = check_secrets(text)
    gk = [f for f in findings if f.metadata["secret_type"] == "Google API Key"]
    assert len(gk) >= 1
    assert gk[0].severity == Severity.HIGH
    assert gk[0].matched_text.startswith("AIza")
    assert "REDACTED" in gk[0].matched_text


# -----------------------------------------------------------------------
# 11. Generic API Key / Token Assignments
# -----------------------------------------------------------------------

def test_generic_api_key_assignment():
    text = 'api_key = "sk-abc123XYZ789defGHI"'
    findings = check_secrets(text)
    gk = [f for f in findings if f.metadata["secret_type"] == "Generic API Key"]
    assert len(gk) >= 1
    assert gk[0].severity == Severity.MEDIUM


def test_access_token_assignment():
    text = 'access_token: "eyAbCdEfGhIjKlMnOpQr"'
    findings = check_secrets(text)
    gk = [f for f in findings if f.metadata["secret_type"] == "Generic API Key"]
    assert len(gk) >= 1


def test_api_token_assignment():
    text = "api_token = 'a1b2c3d4e5f6g7h8'"
    findings = check_secrets(text)
    gk = [f for f in findings if f.metadata["secret_type"] == "Generic API Key"]
    assert len(gk) >= 1


# -----------------------------------------------------------------------
# 12. Telegram Bot Token
# -----------------------------------------------------------------------

def test_telegram_bot_token():
    text = 'TELEGRAM_TOKEN="1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawX"'
    findings = check_secrets(text)
    tg = [f for f in findings if f.metadata["secret_type"] == "Telegram Bot Token"]
    assert len(tg) >= 1
    assert tg[0].severity == Severity.HIGH
    assert "REDACTED" in tg[0].matched_text


# -----------------------------------------------------------------------
# Redaction tests
# -----------------------------------------------------------------------

def test_redaction_keys_show_first_four():
    """Keys/tokens should show the first 4 chars then ***REDACTED***."""
    text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"'
    findings = check_secrets(text)
    gh = [f for f in findings if f.metadata["secret_type"] == "GitHub Token"]
    assert len(gh) == 1
    assert gh[0].matched_text == "ghp_***REDACTED***"


def test_redaction_password_fully_hidden():
    """Password values must be completely redacted."""
    text = 'password = "MyP@ssw0rd!123"'
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) == 1
    assert pw[0].matched_text == "***REDACTED***"
    assert "MyP@ssw0rd" not in pw[0].matched_text


# -----------------------------------------------------------------------
# Sensitivity level tests
# -----------------------------------------------------------------------

def test_sensitivity_low_only_critical():
    """Low sensitivity should only return CRITICAL findings."""
    text = "\n".join([
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',            # CRITICAL
        'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl',  # HIGH
        'password = "hunter2!"',                         # MEDIUM
    ])
    findings = check_secrets(text, sensitivity="low")
    assert all(f.severity == Severity.CRITICAL for f in findings)
    assert len(findings) >= 1


def test_sensitivity_medium_skips_low():
    """Medium sensitivity should return MEDIUM and above, skip LOW/INFO."""
    text = "\n".join([
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',             # CRITICAL
        'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl',   # HIGH
        'password = "hunter2!"',                          # MEDIUM
    ])
    findings = check_secrets(text, sensitivity="medium")
    for f in findings:
        assert f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    # Should include all three types
    severities = {f.severity for f in findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities


def test_sensitivity_high_returns_all():
    """High sensitivity should return all findings."""
    text = 'password = "hunter2!"'  # MEDIUM
    findings_high = check_secrets(text, sensitivity="high")
    findings_medium = check_secrets(text, sensitivity="medium")
    # high should return at least as many as medium
    assert len(findings_high) >= len(findings_medium)


# -----------------------------------------------------------------------
# No false positives on clean code
# -----------------------------------------------------------------------

def test_no_false_positives_clean_code():
    """Normal code should not trigger secret detections."""
    clean = "\n".join([
        'name = "John"',
        "age = 30",
        "greeting = 'Hello, world!'",
        "# This is a comment",
        "def compute(x, y):",
        "    return x + y",
        "items = ['apple', 'banana', 'cherry']",
        "url = 'https://example.com/page'",
        'description = "A simple test string"',
        "MAX_RETRIES = 3",
    ])
    findings = check_secrets(clean)
    assert len(findings) == 0


def test_no_false_positive_variable_assignment():
    """Variable-to-variable assignments should not be detected as passwords."""
    text = 'password = os.environ["DB_PASSWORD"]'
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) == 0


def test_no_false_positive_empty_password():
    """Empty string passwords should not be flagged (< 4 chars)."""
    text = 'password = ""'
    findings = check_secrets(text)
    pw = [f for f in findings if f.metadata["secret_type"] == "Password in Assignment"]
    assert len(pw) == 0


# -----------------------------------------------------------------------
# Multi-line / multiple secrets
# -----------------------------------------------------------------------

def test_multiline_multiple_secrets():
    """Multiple secrets across several lines should all be detected."""
    text = "\n".join([
        '# Line 1',
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"',
        'db_url = "postgres://admin:secret@db.example.com:5432/prod"',
        'password = "Sup3rS3cure!"',
    ])
    findings = check_secrets(text)
    types = {f.metadata["secret_type"] for f in findings}
    assert "AWS Access Key" in types
    assert "GitHub Token" in types
    assert "Connection String" in types
    assert "Password in Assignment" in types
    # Verify line numbers (1-based)
    for f in findings:
        assert f.line_number >= 1


def test_line_numbers_correct():
    """Line numbers should be 1-based and accurate."""
    text = "safe line\nsafe line\nAKIAIOSFODNN7EXAMPLE\nsafe line"
    findings = check_secrets(text)
    assert len(findings) >= 1
    assert findings[0].line_number == 3


# -----------------------------------------------------------------------
# file_path pass-through
# -----------------------------------------------------------------------

def test_file_path_passed_through():
    """file_path argument should appear on every finding."""
    text = 'password = "s3cret!!"'
    findings = check_secrets(text, file_path="/app/config.py")
    assert len(findings) >= 1
    for f in findings:
        assert f.file_path == "/app/config.py"


def test_file_path_none_by_default():
    text = 'password = "s3cret!!"'
    findings = check_secrets(text)
    assert len(findings) >= 1
    for f in findings:
        assert f.file_path is None


# -----------------------------------------------------------------------
# Scanner field
# -----------------------------------------------------------------------

def test_scanner_field():
    text = 'AKIAIOSFODNN7EXAMPLE'
    findings = check_secrets(text)
    for f in findings:
        assert f.scanner == "secrets"


# -----------------------------------------------------------------------
# Finding type
# -----------------------------------------------------------------------

def test_finding_type_is_secret():
    text = 'AKIAIOSFODNN7EXAMPLE'
    findings = check_secrets(text)
    for f in findings:
        assert f.finding_type == FindingType.SECRET
