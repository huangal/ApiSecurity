"""
Unit tests for the Lambda Authorizer.
Run with:  python -m pytest lambda/authorizer_test.py -v
"""

import json
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Patch SSM and env vars before importing the module under test
# ---------------------------------------------------------------------------
TRUSTED_DNS = [
    "CN=My Corp CA,O=My Corp,C=US",
    "CN=Partner CA,O=Partner Inc,C=GB",
]

SSM_RESPONSE = {
    "Parameter": {
        "Value": json.dumps(TRUSTED_DNS),
        "Name" : "/oauth-m2m-prod/authorizer/trusted-ca-dns",
    }
}

import os
os.environ.setdefault("SSM_TRUSTED_DNS_PATH", "/oauth-m2m-prod/authorizer/trusted-ca-dns")
os.environ.setdefault("LOG_LEVEL", "ERROR")

with patch("boto3.client") as mock_boto:
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = SSM_RESPONSE
    mock_boto.return_value = mock_ssm
    import authorizer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(subject_dn: str = "", issuer_dn: str = "", method_arn: str = "arn:aws:execute-api:us-east-1:123:abc/prod/POST/token") -> dict:
    return {
        "methodArn": method_arn,
        "requestContext": {
            "identity": {
                "clientCert": {
                    "subjectDN"   : subject_dn,
                    "issuerDN"    : issuer_dn,
                    "serialNumber": "01:AB:CD",
                    "validity"    : {
                        "notBefore": "2024-01-01T00:00:00Z",
                        "notAfter" : "2026-01-01T00:00:00Z",
                    },
                }
            }
        },
    }


def _effect(policy: dict) -> str:
    return policy["policyDocument"]["Statement"][0]["Effect"]


def _context_reason(policy: dict) -> str:
    return policy.get("context", {}).get("reason", "")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNormaliseDN(unittest.TestCase):

    def test_strips_whitespace(self):
        assert authorizer._normalise_dn("  CN=Test , O=Corp  ") == "cn=test , o=corp"

    def test_collapses_internal_whitespace(self):
        assert authorizer._normalise_dn("CN=My   Corp CA") == "cn=my corp ca"

    def test_lowercases(self):
        assert authorizer._normalise_dn("CN=UPPER,O=CASE") == "cn=upper,o=case"


class TestLambdaAuthorizer(unittest.TestCase):

    def setUp(self):
        # Ensure the module-level whitelist matches our test data
        authorizer._TRUSTED_DNS = {authorizer._normalise_dn(dn) for dn in TRUSTED_DNS}

        # Patch SSM so warm-invocation refresh also returns our test data
        self.mock_ssm = MagicMock()
        self.mock_ssm.get_parameter.return_value = SSM_RESPONSE
        authorizer.ssm = self.mock_ssm

    # ── Allow cases ──────────────────────────────────────────────────────────

    def test_allow_exact_match(self):
        event  = _make_event(subject_dn="CN=My Corp CA,O=My Corp,C=US")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Allow")
        self.assertEqual(result["principalId"], "cn=my corp ca,o=my corp,c=us")

    def test_allow_case_insensitive(self):
        event  = _make_event(subject_dn="cn=my corp ca,o=my corp,c=us")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Allow")

    def test_allow_with_extra_whitespace(self):
        event  = _make_event(subject_dn="CN=My Corp CA , O=My Corp , C=US")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Allow")

    def test_allow_second_trusted_dn(self):
        event  = _make_event(subject_dn="CN=Partner CA,O=Partner Inc,C=GB")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Allow")

    def test_allow_context_fields_forwarded(self):
        event  = _make_event(
            subject_dn="CN=My Corp CA,O=My Corp,C=US",
            issuer_dn="CN=Root CA,O=My Corp,C=US",
        )
        result = authorizer.lambda_handler(event, None)
        self.assertIn("context", result)
        self.assertEqual(result["context"]["issuerDN"], "CN=Root CA,O=My Corp,C=US")
        self.assertEqual(result["context"]["serialNumber"], "01:AB:CD")

    # ── Deny cases ───────────────────────────────────────────────────────────

    def test_deny_unknown_dn(self):
        event  = _make_event(subject_dn="CN=Untrusted CA,O=Evil Corp,C=XX")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Deny")
        self.assertEqual(_context_reason(result), "untrusted_certificate_dn")

    def test_deny_empty_subject_dn(self):
        event  = _make_event(subject_dn="")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Deny")
        self.assertEqual(_context_reason(result), "missing_client_certificate")

    def test_deny_no_client_cert_block(self):
        event = {
            "methodArn"     : "arn:aws:execute-api:us-east-1:123:abc/prod/POST/token",
            "requestContext": {"identity": {}},
        }
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Deny")
        self.assertEqual(_context_reason(result), "missing_client_certificate")

    def test_deny_partial_dn_match(self):
        # Substring of a trusted DN must not pass
        event  = _make_event(subject_dn="CN=My Corp CA")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Deny")

    # ── SSM failure — fail closed ─────────────────────────────────────────────

    def test_deny_when_ssm_unavailable(self):
        from botocore.exceptions import ClientError
        self.mock_ssm.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "boom"}},
            "GetParameter",
        )
        event  = _make_event(subject_dn="CN=My Corp CA,O=My Corp,C=US")
        result = authorizer.lambda_handler(event, None)
        self.assertEqual(_effect(result), "Deny")
        self.assertEqual(_context_reason(result), "ssm_unavailable")


if __name__ == "__main__":
    unittest.main()
