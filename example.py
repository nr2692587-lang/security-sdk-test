import hashlib
import hmac
import json
import re
from urllib.parse import urlparse


class SecuritySDK:
    def __init__(self, api_key: str, allowed_hosts=None):
        self.api_key = api_key
        self.allowed_hosts = set(allowed_hosts or ["api.example.com"])

    def validate_url(self, url: str) -> str:
        if not url or not url.startswith("https://"):
            raise ValueError("Only HTTPS URLs are allowed.")

        host = urlparse(url).hostname
        if host is None or host.lower() not in self.allowed_hosts:
            raise ValueError(f"Host '{host}' is not allowed.")

        return url

    def validate_headers(self, headers: dict) -> None:
        required = ["x-request-id", "x-timestamp", "authorization"]
        missing = [name for name in required if not headers.get(name)]
        if missing:
            raise ValueError(f"Missing required headers: {', '.join(missing)}")

        auth = headers["authorization"]
        if not auth.lower().startswith("bearer "):
            raise ValueError("Authorization header must use the Bearer scheme.")

        if len(headers["x-request-id"]) < 8:
            raise ValueError("x-request-id must be at least 8 characters long.")

    def sign_payload(self, payload: dict, secret: str | None = None) -> str:
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signing_secret = secret or self.api_key
        return hmac.new(
            signing_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_request(self, url: str, headers: dict, payload: dict) -> dict:
        validated_url = self.validate_url(url)
        self.validate_headers(headers)

        signature = self.sign_payload(payload)
        return {
            "url": validated_url,
            "request_id": headers["x-request-id"],
            "signed_payload": signature,
            "status": "accepted",
        }


if __name__ == "__main__":
    sdk = SecuritySDK(api_key="super-secret-key", allowed_hosts={"api.example.com"})

    request = {
        "url": "https://api.example.com/v1/alerts",
        "headers": {
            "x-request-id": "req-123456",
            "x-timestamp": "2026-09-22T07:00:00Z",
            "authorization": "Bearer demo-token",
        },
        "payload": {
            "event": "login",
            "user": "alice@example.com",
            "risk_score": 42,
        },
    }

    result = sdk.verify_request(
        request["url"],
        request["headers"],
        request["payload"],
    )

    print("Security SDK example result:")
    print(json.dumps(result, indent=2))
