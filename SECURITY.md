# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that exposes credentials,
private investigation data, signature keys, or arbitrary code execution. Send a
private report to the repository owner with reproduction steps and the affected
version.

## Security boundaries

- Provider and AI credentials are read from environment variables and are never
  returned to the browser.
- Uploaded files are streamed into the local C SHA-256 implementation. The
  application sends only the digest to OTX and VirusTotal.
- Report signing uses RSA-PSS with SHA-256 through OpenSSL's EVP API. Private
  keys stay in the local data volume.
- The deterministic score is an aid for triage, not an automated block/allow
  decision.
- Demo fixtures are synthetic and contain no real threat claim.

Do not expose this demonstration instance directly to the public internet
without adding authentication, authorization, request throttling, and an
organization-specific retention policy.
