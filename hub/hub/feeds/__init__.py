"""Public blocklist feeds (design M30): selection, exclusions, lifecycle, publication.

Everything here runs in ``hub-worker``. ``select``, ``filter`` (matching) and ``lifecycle`` are
pure over loaded rows; ``publish`` owns the files; ``job`` ties them to the database.
"""
