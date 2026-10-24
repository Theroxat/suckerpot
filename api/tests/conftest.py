import os

# Existing endpoint tests exercise the routes, not the login flow: run them with auth open.
# Auth tests pass explicit AuthSettings to create_app, so this default never affects them.
os.environ.setdefault("API_AUTH_DISABLED", "true")
os.environ.setdefault("SUCKERPOT_DEMO", "1")
