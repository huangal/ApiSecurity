"""
Lambda Authorizer — REQUEST type
=================================
Attached to API Gateway as a custom authorizer on the POST /token method.

What it does:
  1. Extracts the client certificate's Subject DN from the API Gateway
     request context (populated automatically during mTLS handshake).
  2. Validates the DN against the TRUSTED_CA_DNS whitelist stored in
     SSM Parameter Store (JSON array of allowed DN strings).
  3. Returns an IAM policy granting or denying execute-api:Invoke.

Environment variables (set by Terraform):
  SSM_TRUSTED_DNS_PATH  — SSM parameter path for the JSON DN whitelist
                          e.g. /oauth-m2m-prod/authorizer/trusted-ca-dns
  LOG_LEVEL             — Optional. DEBUG | INFO | WARNING | ERROR (default INFO)
"""

import json
import logging
import os
import re

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# ---------------------------------------------------------------------------
# SSM client — initialised once per cold start
# ---------------------------------------------------------------------------
ssm = boto3.client("ssm")

SSM_TRUSTED_DNS_PATH = os.environ["SSM_TRUSTED_DNS_PATH"]


def _load_trusted_dns() -> set:
    """
    Reads the JSON DN whitelist from SSM Parameter Store.
    Returns a set of normalised (lower-case, collapsed-whitespace) DN strings.

    Expected SSM value format (SecureString or String):
        ["CN=My Corp CA,O=My Corp,C=US", "CN=Partner CA,O=Partner Inc,C=GB"]
    """
    try:
        response = ssm.get_parameter(
            Name=SSM_TRUSTED_DNS_PATH,
            WithDecryption=True,
        )
        raw = response["Parameter"]["Value"]
        dns = json.loads(raw)

        if not isinstance(dns, list):
            raise ValueError("SSM parameter must be a JSON array of DN strings.")

        return {_normalise_dn(dn) for dn in dns}

    except ClientError as exc:
        logger.error("Failed to read trusted DN list from SSM: %s", exc)
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("Invalid trusted DN list format in SSM: %s", exc)
        raise


# Loaded once per cold start; refreshed on each warm invocation via
# the module-level cache below.  For production consider adding a
# time-based refresh (e.g. every 5 minutes) using functools.lru_cache
# with a TTL wrapper.
_TRUSTED_DNS: set = _load_trusted_dns()


# ---------------------------------------------------------------------------
# DN normalisation
# ---------------------------------------------------------------------------
_WHITESPACE_RE = re.compile(r"\s+")


def _normalise_dn(dn: str) -> str:
    """
    Normalise a Distinguished Name for comparison:
      - Strip leading/trailing whitespace
      - Collapse internal whitespace sequences to a single space
      - Lower-case the whole string

    Example:
        "CN=My Corp CA , O=My Corp , C=US"
        → "cn=my corp ca , o=my corp , c=us"
    """
    return _WHITESPACE_RE.sub(" ", dn.strip()).lower()


# ---------------------------------------------------------------------------
# Certificate field extraction helpers
# ---------------------------------------------------------------------------

def _extract_cert_fields(event: dict) -> dict:
    """
    Pull all certificate-related fields from the API Gateway request context.
    Returns a dict with subjectDN, issuerDN, serialNumber, validity, and
    the raw clientCert block so callers can log without redundancy.
    """
    identity   = event.get("requestContext", {}).get("identity", {})
    client_cert = identity.get("clientCert", {})

    validity = client_cert.get("validity", {})

    return {
        "subjectDN"    : client_cert.get("subjectDN", ""),
        "issuerDN"     : client_cert.get("issuerDN",  ""),
        "serialNumber" : client_cert.get("serialNumber", ""),
        "notBefore"    : validity.get("notBefore", ""),
        "notAfter"     : validity.get("notAfter",  ""),
        "clientCert"   : client_cert,
    }


# ---------------------------------------------------------------------------
# IAM policy builder
# ---------------------------------------------------------------------------

def _build_policy(effect: str, method_arn: str, principal_id: str, context: dict = None) -> dict:
    """
    Build a minimal IAM authorizer response.

    Args:
        effect       : "Allow" or "Deny"
        method_arn   : the ARN of the API Gateway method being invoked
        principal_id : identifier for the calling principal (the cert subject DN)
        context      : optional key/value pairs forwarded to the integration
                       (available as $context.authorizer.<key> in mapping templates
                        and as event['requestContext']['authorizer'] in Lambda proxy)
    """
    policy = {
        "principalId": principal_id or "unknown",
        "policyDocument": {
            "Version"  : "2012-10-17",
            "Statement": [
                {
                    "Action"  : "execute-api:Invoke",
                    "Effect"  : effect,
                    "Resource": method_arn,
                }
            ],
        },
    }

    if context:
        policy["context"] = context

    return policy


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context) -> dict:
    """
    Entry point for the API Gateway REQUEST-type Lambda Authorizer.

    API Gateway passes the full request event including:
      event["requestContext"]["identity"]["clientCert"]["subjectDN"]
      event["requestContext"]["identity"]["clientCert"]["issuerDN"]
      event["methodArn"]  — ARN of the method being invoked
    """
    method_arn = event.get("methodArn", "*")

    # ── 1. Extract certificate fields ────────────────────────────────────────
    cert = _extract_cert_fields(event)
    subject_dn   = cert["subjectDN"]
    issuer_dn    = cert["issuerDN"]
    serial_number = cert["serialNumber"]

    logger.info(
        "Authorizing request | subjectDN=%s | issuerDN=%s | serial=%s",
        subject_dn,
        issuer_dn,
        serial_number,
    )

    # ── 2. Guard: certificate must be present ────────────────────────────────
    if not subject_dn:
        logger.warning("No client certificate in request context — denying.")
        return _build_policy(
            effect       = "Deny",
            method_arn   = method_arn,
            principal_id = "anonymous",
            context      = {"reason": "missing_client_certificate"},
        )

    # ── 3. Normalise and check against whitelist ──────────────────────────────
    normalised_dn = _normalise_dn(subject_dn)

    # Re-read the whitelist from SSM on every warm invocation so that
    # additions/removals take effect without a cold start.
    # To cache for a warm-invocation TTL, wrap _load_trusted_dns with
    # a time-based cache instead.
    global _TRUSTED_DNS
    try:
        _TRUSTED_DNS = _load_trusted_dns()
    except Exception:
        # If SSM is temporarily unavailable, fail closed (deny all).
        logger.error("Cannot refresh trusted DN list — failing closed.")
        return _build_policy(
            effect       = "Deny",
            method_arn   = method_arn,
            principal_id = normalised_dn,
            context      = {"reason": "ssm_unavailable"},
        )

    if normalised_dn not in _TRUSTED_DNS:
        logger.warning(
            "Certificate DN not in trusted whitelist — denying | subjectDN=%s",
            subject_dn,
        )
        return _build_policy(
            effect       = "Deny",
            method_arn   = method_arn,
            principal_id = normalised_dn,
            context      = {"reason": "untrusted_certificate_dn"},
        )

    # ── 4. Allow ─────────────────────────────────────────────────────────────
    logger.info("Certificate DN authorised — allowing | subjectDN=%s", subject_dn)

    return _build_policy(
        effect       = "Allow",
        method_arn   = method_arn,
        principal_id = normalised_dn,
        context      = {
            # Forwarded to the backend Lambda as
            # event["requestContext"]["authorizer"]["subjectDN"] etc.
            "subjectDN"   : subject_dn,
            "issuerDN"    : issuer_dn,
            "serialNumber": serial_number,
            "notBefore"   : cert["notBefore"],
            "notAfter"    : cert["notAfter"],
        },
    )
