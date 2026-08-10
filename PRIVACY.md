# Privacy

PageHold stores its account, site metadata, schedules, jobs, captures, assets,
profile image, audit events, and integrity key in the local data directory.
It does not include analytics or a central account service.

## Network Activity

PageHold makes outbound requests only when the local user asks it to capture an
explicit site, when a scheduled capture becomes due, or when the user follows an
external link in their own browser. Target websites can see the installation's
network address and crawler request metadata.

## Visibility

Private sites require the local account on every page and asset request. Public
sites are reachable by anyone who can reach the installation. Changing a site
from public to private takes effect on subsequent requests and does not delete
the archived data.

## Backups And Exports

Backups contain the database, captures, assets, profile data, and local signing
key. Treat them as private data and store them encrypted or on access-controlled
media. Portable exports may contain third-party website content and should be
shared only when the user has authority to do so.

PageHold does not prescribe a retention period. The local user controls archive
deletion and backup retention.
