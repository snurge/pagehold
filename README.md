# PageHold

PageHold is a self-hosted website archiver for keeping scheduled, locally stored
copies of sites you choose. It provides one local account, automatic bounded
crawling, private or public visibility, capture history, safe replay, search,
comparison, export, and verified backups.

PageHold does not discover sites across the Internet. It crawls only URLs you
add. Its Internet Archive integration is a browser link to the selected site's
history; PageHold does not import material from that service.

## Status

This is an alpha release. Use it for evaluation and keep verified
backups. Archive fidelity varies between websites, especially authenticated,
streaming, highly interactive, or anti-automation pages.

## Requirements

- Python 3.11 or newer
- macOS or a current Linux distribution
- Chromium installed by Playwright for active-page capture

## Install

```bash
git clone https://github.com/snurge/pagehold.git pagehold
cd pagehold
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/playwright install chromium
./scripts/install-standalone.sh
```

For a direct development start:

```bash
WEBSNAPSHOT_SECRET="replace-with-a-long-random-value" .venv/bin/python app.py
```

Open `http://127.0.0.1:18765`, create the sole local account, and add a site.
Registration closes as soon as that account is created.

## Data And Backups

Runtime state defaults to `data/` and is excluded from Git. It contains the
SQLite database, captured pages, assets, profile image, crawl work, and local
manifest-signing key.

```bash
.venv/bin/python websnapshot_admin.py backup /path/to/backups
.venv/bin/python websnapshot_admin.py verify-backup /path/to/backup.tar.gz
.venv/bin/python websnapshot_admin.py integrity
```

Keep backups on storage separate from the machine running PageHold. The signing
key is part of archive integrity and is included in encrypted/private backups.

## Production

See `PRODUCTION.md` for reverse-proxy HTTPS, service management, permissions,
backups, and hardening. PageHold should bind to loopback behind an HTTPS reverse
proxy in production.

## License

PageHold source is licensed under `AGPL-3.0-only`; see `LICENSE`. Archived
websites and user data remain separate from the PageHold source license.
