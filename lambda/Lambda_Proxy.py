import boto3
import os
import base64
import urllib.request
import urllib.parse
import json

# Loaded once at cold start — value comes from SSM/Secrets Manager
WAF_INTERNAL_SECRET = os.environ["WAF_INTERNAL_SECRET"]
COGNITO_DOMAIN      = os.environ["COGNITO_DOMAIN"]   # e.g. https://auth.example.com

def lambda_handler(event, context):
    # ── 1. Decode Basic Auth ──────────────────────────────────────────
    auth_header = (event.get("headers") or {}).get("authorization", "")
    if not auth_header.lower().startswith("basic "):
        return _error(401, "invalid_client", "Missing Basic Auth header")

    try:
        decoded    = base64.b64decode(auth_header[6:]).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
    except Exception:
        return _error(401, "invalid_client", "Malformed Basic Auth header")

    # ── 2. Forward to Cognito with secret internal header ────────────
    body = urllib.parse.urlencode({
        "grant_type"    : "client_credentials",
        "client_id"     : client_id,
        "client_secret" : client_secret,
        "scope"         : event.get("queryStringParameters", {}).get("scope", ""),
    }).encode("utf-8")

    req = urllib.request.Request(
        url    = f"{COGNITO_DOMAIN}/oauth2/token",
        data   = body,
        method = "POST",
        headers = {
            "Content-Type"   : "application/x-www-form-urlencoded",
            "Authorization"  : auth_header,
            # ✅ WAF gate — this header must match Rule 3 exactly
            "X-Internal-Token": WAF_INTERNAL_SECRET,
        },
    )

    with urllib.request.urlopen(req) as resp:
        token_response = json.loads(resp.read())

    # ── 3. Return Cognito response as-is ─────────────────────────────
    return {
        "statusCode": 200,
        "headers"   : {"Content-Type": "application/json"},
        "body"      : json.dumps(token_response),
    }

def _error(status, error, description):
    return {
        "statusCode": status,
        "headers"   : {"Content-Type": "application/json"},
        "body"      : json.dumps({"error": error, "error_description": description}),
    }