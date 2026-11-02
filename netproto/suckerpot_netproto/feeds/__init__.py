"""Selfhostr public blocklist feed formats (design M30 section 6): models, renderers, minisign
signatures and bounded parsers. Pure functions, no I/O. Used by the hub (render and sign) and by
the node worker (verify and parse)."""

from __future__ import annotations

from . import minisign
from .errors import FeedError
from .models import (
    LIST_IDS,
    FeedEntry,
    FeedList,
    IndexFile,
    IndexFileRef,
    IndexList,
    IndexOther,
)
from .parse import (
    ParsedList,
    ParsedTxt,
    parse_index,
    parse_list_json,
    parse_txt,
    verify_file_against_index,
    verify_index,
)
from .render import (
    RenderContext,
    Rendered,
    build_index,
    clean_entries,
    index_list,
    index_other,
    render_csv,
    render_index,
    render_ipset,
    render_json,
    render_list,
    render_nft,
    render_rsc,
    render_stix,
    render_txt,
    render_txt_family,
)

__all__ = [
    "LIST_IDS",
    "FeedEntry",
    "FeedError",
    "FeedList",
    "IndexFile",
    "IndexFileRef",
    "IndexList",
    "IndexOther",
    "ParsedList",
    "ParsedTxt",
    "RenderContext",
    "Rendered",
    "build_index",
    "clean_entries",
    "index_list",
    "index_other",
    "minisign",
    "parse_index",
    "parse_list_json",
    "parse_txt",
    "render_csv",
    "render_index",
    "render_ipset",
    "render_json",
    "render_list",
    "render_nft",
    "render_rsc",
    "render_stix",
    "render_txt",
    "render_txt_family",
    "verify_file_against_index",
    "verify_index",
]
