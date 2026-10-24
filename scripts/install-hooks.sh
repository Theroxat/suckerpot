#!/usr/bin/env bash
# Install the secret-scanning pre-commit hook without root.
#
# Preferred: pre-commit (via uv, pipx or pip --user) + `pre-commit install`.
# Fallback:  pinned gitleaks binary in ~/.local/bin + a minimal .git/hooks/pre-commit.
# Force the fallback with: SUCKERPOT_HOOKS_FALLBACK=1 scripts/install-hooks.sh
set -euo pipefail

GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_SHA256_LINUX_ARM64="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
BIN_DIR="${HOME}/.local/bin"

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
export PATH="${BIN_DIR}:${PATH}"

have() { command -v "$1" >/dev/null 2>&1; }

install_pre_commit() {
  if have pre-commit; then
    return 0
  fi
  if have uv; then
    uv tool install pre-commit
  elif have pipx; then
    pipx install pre-commit
  elif have python3 && python3 -m pip --version >/dev/null 2>&1; then
    python3 -m pip install --user pre-commit
  else
    return 1
  fi
  have pre-commit
}

install_gitleaks_binary() {
  if have gitleaks; then
    return 0
  fi
  local arch sha tmp
  case "$(uname -m)" in
    x86_64 | amd64) arch="x64"; sha="$GITLEAKS_SHA256_LINUX_X64" ;;
    aarch64 | arm64) arch="arm64"; sha="$GITLEAKS_SHA256_LINUX_ARM64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac
  [ "$(uname -s)" = "Linux" ] || { echo "Fallback supports Linux only" >&2; return 1; }
  have curl || { echo "curl is required for the fallback" >&2; return 1; }
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local tarball="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"
  curl -fsSL -o "${tmp}/${tarball}" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"
  echo "${sha}  ${tmp}/${tarball}" | sha256sum -c - >/dev/null
  tar -xzf "${tmp}/${tarball}" -C "$tmp" gitleaks
  mkdir -p "$BIN_DIR"
  install -m 0755 "${tmp}/gitleaks" "${BIN_DIR}/gitleaks"
  echo "Installed gitleaks ${GITLEAKS_VERSION} to ${BIN_DIR}/gitleaks"
}

write_fallback_hook() {
  local hook
  hook="$(git rev-parse --git-path hooks/pre-commit)"
  mkdir -p "$(dirname "$hook")"
  cat >"$hook" <<'HOOK'
#!/usr/bin/env bash
# Installed by scripts/install-hooks.sh (gitleaks-only fallback).
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
root="$(git rev-parse --show-toplevel)"
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks not found; re-run scripts/install-hooks.sh" >&2
  exit 1
fi
exec gitleaks git --pre-commit --staged --redact --verbose \
  --config "${root}/.gitleaks.toml" "${root}"
HOOK
  chmod 0755 "$hook"
  echo "Wrote fallback hook: ${hook}"
}

if [ "${SUCKERPOT_HOOKS_FALLBACK:-0}" != "1" ] && install_pre_commit; then
  pre-commit install
  echo "pre-commit hook installed."
else
  echo "pre-commit unavailable (or fallback forced): using gitleaks-only hook." >&2
  install_gitleaks_binary
  write_fallback_hook
fi
