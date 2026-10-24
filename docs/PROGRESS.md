# Progress log

Newest entries at the bottom. One entry per milestone or significant step: date, what was done, what is left.

## 2026-10-24 — M0 Bootstrap

- Created `.gitignore` first, then `CLAUDE.md`, project subagents in `.claude/agents/`, roadmap, architecture and security docs, README skeleton, MIT licence and `.env.example` (placeholders only).
- Added a gitleaks pre-commit hook (`scripts/install-hooks.sh`, custom rule for private IPv4 ranges) and a CI workflow (gitleaks over full history, Python/web lint and tests, compose config check).
- Left open: CI to be confirmed green on GitHub; secret scanning and push protection to be enabled in the repo settings by the owner.
