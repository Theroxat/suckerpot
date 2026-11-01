"""Advisory lock keys shared by services.

``ABUSE_SMTP_PROFILE``: ingest holds it in SHARED mode for the whole of a report mail (it reads
the SMTP profile and delivers), the API takes it EXCLUSIVELY to change or delete the profile, so a
profile write waits for a send in flight and a send never uses a half-changed profile.

``ABUSE_IMAP_PROFILE`` (M26): the same pattern for the replies mailbox. Ingest holds it SHARED
during a poll, the API takes it EXCLUSIVELY (with a lock timeout) to change or delete the profile.
"""

ABUSE_SMTP_PROFILE = 25_001
ABUSE_IMAP_PROFILE = 26_001
