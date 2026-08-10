# Changelog

## Unreleased

### Changed

- Renamed the product PageHold while retaining WebSnapshot compatibility names internally.
- Reduced the publication candidate to a clean, single-account local archiver.
- Replaced mixed-purpose signing state with local archive integrity records under `data/integrity/`.
- Kept site public/private visibility entirely local to the installation.
- Retired Internet Archive importing in favor of a browser-opened site history button.
- Simplified first-use setup, account management, site listing, capture history, and snapshot navigation.

### Security

- Kept CSRF checks, secure cookie support, host validation, rate limiting, SSRF controls, bounded requests, and script-disabled replay.
- Preserved deterministic signed capture manifests and verified backup/restore checks.

### License

- Added the unmodified GNU Affero General Public License v3 text and adopted `AGPL-3.0-only`.

Dates and versioned release entries will begin with the first published release.
