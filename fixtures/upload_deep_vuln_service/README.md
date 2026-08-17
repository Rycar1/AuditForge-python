# Upload Deep Verification Vulnerable Service

This fixture is intentionally vulnerable and is used to test AuditForge upload scans with deep verification.

Routes:
- `/search`: raw SQL string concatenation.
- `/ping`: command execution with user-controlled input.
- `/fetch`: SSRF-style outbound request.
- `/hello`: reflected HTML output.
- `/download`: user-controlled file path read.
- `/load-session`: unsafe pickle deserialization.
- `/safe-search`: parameterized SQL control sample.

