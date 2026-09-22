# Security SDK Test

This repo contains a small, safe example of a security-focused SDK that validates inbound requests, checks required headers, and signs payloads before sending them to a trusted backend.

## What the example does

- Ensures URLs use HTTPS and only allow known hosts
- Verifies required security headers are present
- Rejects suspicious or malformed requests early
- Produces a signed payload for downstream verification

## Run the example

```bash
python3 example.py
```

## Example output

The sample script prints a successful validation result for a request that meets the SDK checks.
