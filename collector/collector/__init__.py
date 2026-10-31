"""SuckerPot collector and analyzer.

``collector`` downloads recorded payload URLs through the egress proxy into a quarantine volume.
``analyzer`` parses those files statically in a resource-limited child process. Nothing here ever
executes a downloaded file.
"""
