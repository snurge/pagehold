# Security

PageHold is a self-hosted archival application, not a hardened identity or
financial system. Internet-facing installations still require normal server
maintenance, HTTPS, strong credentials, restrictive file permissions, and
verified backups.

## Built-In Controls

- one local account with a minimum 12-character password;
- PBKDF2 password hashing and versioned signed sessions;
- CSRF tokens and origin checks on state-changing forms;
- login and setup rate limits;
- production host allowlists and secure cookies;
- outbound URL validation to reduce server-side request forgery risk;
- bounded request, page, asset, depth, timeout, and storage limits;
- archived scripts and form submissions disabled during replay;
- restrictive content security policies on replay pages and assets;
- deterministic Ed25519-signed local capture manifests;
- verified, checksum-protected backups and identity continuity checks.

## Deployment

Run the application as an unprivileged account, bind it to loopback, and place a
maintained HTTPS reverse proxy in front. Keep the data directory unreadable by
other users. Do not place secrets in the repository or command history. Apply
operating-system and Python dependency updates deliberately and test restore
procedures regularly.

## Scope Limits

PageHold does not currently provide MFA, encrypted archive storage, malware
scanning, sandboxed operating-system containers, or automatic security updates.
Captured content is untrusted even though replay disables active scripts.
