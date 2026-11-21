#!/usr/bin/env bash
# Install portable SOC-ready security logging Agent Skills into your AI coding agent or project repo.
#
# Usage:
#   ./scripts/install-skills.sh --target claude --scope user
#   ./scripts/install-skills.sh --target codex --scope project --project-dir /path/to/vendor-app
#   ./scripts/install-skills.sh --target agents --scope project --project-dir .
#   ./scripts/install-skills.sh --target all-project --project-dir /path/to/vendor-app

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SKILLS_SRC="${REPO_ROOT}/skills"

TARGET="agents"
SCOPE="project"
PROJECT_DIR="$(pwd)"
DRY_RUN=false

usage() {
  cat <<EOF
Install soc-ready-logging Agent Skills (SKILL.md) for AI coding agents.

Options:
  --target <name>       Target agent format:
                          agents      (.agents/skills — universal standard)
                          claude      (Claude Code: .claude/skills or ~/.claude/skills)
                          codex       (Codex: .codex/skills or ~/.codex/skills)
                          cursor      (Cursor: .cursor/skills or ~/.cursor/skills)
                          antigravity (Antigravity: .agent/skills or ~/.gemini/antigravity/skills)
                          copilot     (GitHub Copilot: .github/skills)
                          opencode    (OpenCode: .opencode/skills or ~/.config/opencode/skills)
                          all-project (Install into .agents/skills, .claude/skills, .cursor/skills)
  --scope <scope>       project (default) or user
  --project-dir <path>  Destination repository path when --scope project (default: cwd)
  --dry-run             Print planned copy actions without modifying files
  -h, --help            Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --scope)
      SCOPE="$2"
      shift 2
      ;;
    --project-dir)
      PROJECT_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

install_to_dir() {
  local dest="$1"
  echo "Installing soc-ready-logging skills -> ${dest}"
  for skill_dir in "${SKILLS_SRC}"/soc-*; do
    [[ -d "${skill_dir}" ]] || continue
    local skill_name
    skill_name="$(basename "${skill_dir}")"
    if [[ "${DRY_RUN}" == "true" ]]; then
      echo "  [dry-run] copy ${skill_name} -> ${dest}/${skill_name}"
    else
      mkdir -p "${dest}"
      rm -rf "${dest:?}/${skill_name}"
      cp -R "${skill_dir}" "${dest}/${skill_name}"
      echo "  ✓ ${skill_name}"
    fi
  done
}

case "${TARGET}" in
  agents)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.agents/skills"
    else
      install_to_dir "${PROJECT_DIR}/.agents/skills"
    fi
    ;;
  claude)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.claude/skills"
    else
      install_to_dir "${PROJECT_DIR}/.claude/skills"
    fi
    ;;
  codex)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.codex/skills"
    else
      install_to_dir "${PROJECT_DIR}/.codex/skills"
    fi
    ;;
  cursor)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.cursor/skills"
    else
      install_to_dir "${PROJECT_DIR}/.cursor/skills"
    fi
    ;;
  antigravity)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.gemini/antigravity/skills"
    else
      install_to_dir "${PROJECT_DIR}/.agent/skills"
    fi
    ;;
  copilot)
    install_to_dir "${PROJECT_DIR}/.github/skills"
    ;;
  opencode)
    if [[ "${SCOPE}" == "user" ]]; then
      install_to_dir "${HOME}/.config/opencode/skills"
    else
      install_to_dir "${PROJECT_DIR}/.opencode/skills"
    fi
    ;;
  all-project)
    install_to_dir "${PROJECT_DIR}/.agents/skills"
    install_to_dir "${PROJECT_DIR}/.claude/skills"
    install_to_dir "${PROJECT_DIR}/.cursor/skills"
    ;;
  *)
    echo "Unsupported target: ${TARGET}" >&2
    usage >&2
    exit 2
    ;;
esac

echo "Done. Ask your coding agent to run 'soc-logging-audit' on your repository to get started."
