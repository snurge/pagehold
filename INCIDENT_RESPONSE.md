# Local Incident Recovery

## Suspected Account Compromise

1. Restrict network access to the installation.
2. Reset the local password with `websnapshot_admin.py set-password`.
3. Restart PageHold so old sessions remain invalidated by the password change.
4. Review local events, captures, visibility changes, and filesystem timestamps.
5. Restore from a verified backup when unauthorized destructive changes occurred.

## Suspected Archive Corruption

1. Stop the service to avoid further writes.
2. Preserve a copy of the current data directory for diagnosis.
3. Run `websnapshot_admin.py integrity` against the copy.
4. Verify candidate backups before selecting one to restore.
5. Restore into an absent or empty directory and rerun the integrity check.

## Suspected Key Exposure

The key under `data/integrity/` signs local capture manifests. Preserve the
affected data and backups for evidence. A replacement workflow is intentionally
not automated in the alpha release because changing the key alters continuity
for existing manifests.
