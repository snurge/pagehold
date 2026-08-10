# Changelog

## Unreleased

## 0.1.0-alpha.1 - 2026-08-10

### Changed

- Renamed the product PageHold while retaining WebSnapshot compatibility names internally.
- Reduced the publication candidate to a clean, single-account local archiver.
- Replaced mixed-purpose signing state with local archive integrity records under `data/integrity/`.
- Kept site public/private visibility entirely local to the installation.
- Retired Internet Archive importing in favor of a browser-opened site history button.
- Simplified first-use setup, account management, site listing, capture history, and snapshot navigation.
- Published the standalone source at `https://github.com/snurge/pagehold` and enabled that in-product Source link by default.

### Security

- Kept CSRF checks, secure cookie support, host validation, rate limiting, SSRF controls, bounded requests, and script-disabled replay.
- Preserved deterministic signed capture manifests and verified backup/restore checks.

### License

- Added the unmodified GNU Affero General Public License v3 text and adopted `AGPL-3.0-only`.
