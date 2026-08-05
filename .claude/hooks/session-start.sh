#!/bin/bash
# Correct the git author identity when it is the agent runner's placeholder.
#
# Claude Code's hosted containers ship a baked-in /root/.gitconfig setting
# user.name=Claude and user.email=noreply@anthropic.com. Nothing in a commit
# *message* reveals it, so commits authored that way pass a message review and
# only show up in `git log --format=%an` or the GitHub UI — which is how a whole
# branch of them reached a pull request once already.
#
# The guard is the important part: this only replaces the runner placeholder. A
# contributor who has configured their own identity keeps it and this hook is a
# no-op — including someone whose real address happens to be @anthropic.com,
# which is why the match is the exact placeholder rather than the domain.
#
# If you fork this repo, change OWNER_* below to yourself — or drop the file,
# since with your own identity set the hook does nothing.
set -uo pipefail

OWNER_NAME="Gerrrt"
OWNER_EMAIL="garrettallen2@gmail.com"

# The literal identity the runner image ships with.
PLACEHOLDER_NAME="Claude"
PLACEHOLDER_EMAIL="noreply@anthropic.com"

# Never let this hook fail a session start. Identity is worth correcting, not
# worth blocking work over, so every path below ends in success.
repo="${CLAUDE_PROJECT_DIR:-}"
if [ -z "$repo" ]; then
    repo="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [ -z "$repo" ] || ! git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
    echo "git identity: no repository resolved, leaving config alone"
    exit 0
fi

current_name="$(git -C "$repo" config --get user.name 2>/dev/null || true)"
current_email="$(git -C "$repo" config --get user.email 2>/dev/null || true)"

is_placeholder=false
if [ -z "$current_name" ] && [ -z "$current_email" ]; then
    # Nothing configured at all: git would refuse to commit, or invent
    # something from the hostname.
    is_placeholder=true
elif [ "$current_email" = "$PLACEHOLDER_EMAIL" ]; then
    is_placeholder=true
elif [ "$current_name" = "$PLACEHOLDER_NAME" ] && [[ "$current_email" == *"@anthropic.com" ]]; then
    # Same placeholder, should the image ever change which no-reply it uses.
    is_placeholder=true
fi

if [ "$is_placeholder" = true ]; then
    # Repo-local, so it cannot leak into unrelated checkouts in the same
    # container.
    if git -C "$repo" config --local user.name "$OWNER_NAME" 2>/dev/null &&
        git -C "$repo" config --local user.email "$OWNER_EMAIL" 2>/dev/null; then
        echo "git identity: replaced runner placeholder with $OWNER_NAME <$OWNER_EMAIL>"
    else
        echo "git identity: could not write repo-local config, leaving it alone"
    fi
else
    echo "git identity: keeping configured $current_name <$current_email>"
fi

exit 0
