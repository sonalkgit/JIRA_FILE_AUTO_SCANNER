import hmac
import hashlib
import os

def verify_jira_signature(request, secret):
    """Verifies Jira webhook signature to prevent unauthorized requests."""
    signature = request.args.get("secret")
    print(request.args.get("secret"))
    print(secret)
    if not signature or signature != secret:
        return False
    return True
