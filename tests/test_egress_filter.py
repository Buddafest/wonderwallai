"""Tests for the Egress Filter layer."""

import re
import pytest
from wonderwallai.layers.egress_filter import EgressFilter


class TestCanaryDetection:
    def test_canary_token_generates_with_prefix(self):
        ef = EgressFilter(canary_prefix="TEST-")
        token = ef.generate_canary_token("session-123")
        assert token.startswith("TEST-")
        assert len(token) > len("TEST-")

    def test_canary_token_default_prefix(self):
        ef = EgressFilter()
        token = ef.generate_canary_token("session-abc")
        assert token.startswith("WONDERWALL-")

    def test_canary_token_deterministic(self):
        ef = EgressFilter()
        t1 = ef.generate_canary_token("same-session")
        t2 = ef.generate_canary_token("same-session")
        assert t1 == t2

    def test_canary_token_different_per_session(self):
        ef = EgressFilter()
        t1 = ef.generate_canary_token("session-1")
        t2 = ef.generate_canary_token("session-2")
        assert t1 != t2

    def test_canary_leak_hard_blocks(self):
        ef = EgressFilter()
        token = ef.generate_canary_token("session-leak")
        text = f"Sure! Here is the token: {token} as requested."
        is_safe, cleaned, violations = ef.scan(text, token)
        assert not is_safe
        assert "CANARY_TOKEN_LEAK" in violations
        assert token not in cleaned  # Blocked message replaces text

    def test_no_canary_passes(self):
        ef = EgressFilter()
        is_safe, cleaned, violations = ef.scan("Normal response text.", "")
        assert is_safe
        assert violations == []
        assert cleaned == "Normal response text."


class TestAPIKeyRedaction:
    def test_openai_key_redacted(self):
        ef = EgressFilter()
        text = "Use this key: sk-abc12345678901234567890"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert is_safe  # Redactions are safe (not hard-blocked)
        assert "[REDACTED]" in cleaned
        assert any("API_KEY_LEAK" in v for v in violations)

    def test_groq_key_redacted(self):
        ef = EgressFilter()
        text = "Your Groq key is gsk_abc12345678901234567890"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert "[REDACTED]" in cleaned

    def test_stripe_key_redacted(self):
        ef = EgressFilter()
        text = "sk_test_abc12345678901234567890"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert "[REDACTED]" in cleaned

    def test_shopify_key_redacted(self):
        ef = EgressFilter()
        text = "Token: shpat_" + "a1b2c3d4" * 4  # Fake token built at runtime
        is_safe, cleaned, violations = ef.scan(text, "")
        assert "[REDACTED]" in cleaned

    def test_custom_pattern_redacted(self):
        custom = [re.compile(r'myapp_[a-zA-Z0-9]{16,}')]
        ef = EgressFilter(api_key_patterns=custom, include_defaults=False)
        text = "Key: myapp_abcdef1234567890"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert "[REDACTED]" in cleaned

    def test_no_defaults_skips_builtin_patterns(self):
        ef = EgressFilter(include_defaults=False)
        text = "sk-abc12345678901234567890"  # OpenAI key
        is_safe, cleaned, violations = ef.scan(text, "")
        assert is_safe  # No patterns to match
        assert violations == []


class TestPIIRedaction:
    def test_credit_card_redacted(self):
        ef = EgressFilter()
        text = "Card number: 4111 1111 1111 1111"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert is_safe  # Redactions are safe (not hard-blocked)
        assert "CREDIT_CARD_REDACTED" in cleaned
        assert any("PII:credit_card" in v for v in violations)

    def test_ssn_redacted(self):
        ef = EgressFilter()
        text = "SSN: 123-45-6789"
        is_safe, cleaned, violations = ef.scan(text, "")
        assert "SSN_REDACTED" in cleaned

    def test_clean_text_passes(self):
        ef = EgressFilter()
        text = "Here are our shipping options: Standard (5-7 days) or Express (1-2 days)."
        is_safe, cleaned, violations = ef.scan(text, "")
        assert is_safe
        assert cleaned == text
        assert violations == []
