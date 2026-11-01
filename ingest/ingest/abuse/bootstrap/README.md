Seed copies of the IANA RDAP bootstrap registries (public data, format of RFC 9224).

They are deliberately small. They give the worker a list of RDAP servers it may talk to before
the first refresh; on its first cycle with the egress gate open the worker downloads the full
files through the gate and keeps them in the `rdap_bootstrap` table (refreshed weekly).
