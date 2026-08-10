# Production Deployment

PageHold runs as one Python service with one local account. In production, bind
the application to loopback and terminate HTTPS with Caddy or an equivalent
maintained reverse proxy.

## Recommended Host

- Ubuntu 24.04 LTS or a supported macOS release
- Python 3.11 or newer in a dedicated virtual environment
- a dedicated unprivileged service account
- storage sized for captures plus separate backup capacity

## Required Environment

Set a random `WEBSNAPSHOT_SECRET` of at least 32 characters,
`WEBSNAPSHOT_ENV=production`, `WEBSNAPSHOT_BIND=127.0.0.1`, and an explicit
`WEBSNAPSHOT_ALLOWED_HOSTS`. Keep the environment file outside the repository
with mode `0600`.

The templates in `deploy/systemd/`, `deploy/launchd/`, `deploy/caddy/`, and
`deploy/websnapshot.env.example` are examples. Review paths, account names,
ports, and storage locations before installation.

## Hardening Checklist

- expose only HTTPS through the host firewall;
- keep PageHold and its data directory unprivileged and private;
- enable operating-system security updates;
- use a strong unique local password;
- keep active-browser dependencies patched;
- keep routine backups on another device or protected storage;
- test backup verification and restoration regularly;
- review disk usage and failed crawl logs;
- do not expose the development process controller as a production service.

## Backup

Use the included systemd backup timer as a starting point or call
`websnapshot_admin.py backup` from the platform scheduler. PageHold does not
hard-code a monitoring or backup vendor.
