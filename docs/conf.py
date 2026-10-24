"""Sphinx configuration for the SuckerPot documentation.

The source directory is ``docs/``. Only files inside it are part of the site.
Build locally with::

    sphinx-build -W --keep-going -b html docs docs/_build/html
"""

project = "SuckerPot"
author = "SuckerPot contributors"
copyright = "2026, SuckerPot contributors"

# Pages are written in Markdown (MyST).
extensions = [
    "myst_parser",
    "sphinx_copybutton",
]
source_suffix = {
    ".md": "markdown",
}
root_doc = "index"

# Files and folders that Sphinx must never read as pages.
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    ".venv",
    "requirements.txt",
    "ENVIRONMENT.local.md",
]

# MyST options.
myst_enable_extensions = [
    "colon_fence",  # ::: fences for directives
    "deflist",      # definition lists
    "tasklist",     # - [ ] and - [x] items
]
myst_heading_anchors = 3

# Theme: furo follows the reader's light or dark setting.
html_theme = "furo"
html_title = "SuckerPot documentation"

# Copy button: skip the shell prompt when copying commands.
copybutton_prompt_text = r"\$ "
copybutton_prompt_is_regexp = True
