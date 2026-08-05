#!/bin/bash
# Correct the git author identity when it is the agent runner's placeholder.
#
# Claude Code's hosted containers ship a baked-in /root/.gitconfig setting
# user.name=Claude and user.email=noreply@anthropic.com. Nothing in a commit
# *message* reveals it, so commits authored that way pass a message review and
# only show up in `git log --format=%an` or the GitHub UI — which is how a whole
# branch of them reached a pull request once already.
#
# The guard is the important part: this only replaces the placeholder. A
# contributor who has configured their own identity keeps it, and this hook is
# a no-op for them. If you fork this repo, change OWNER_* below to yourself —
# or drop the file, since with your own identity set the hook does nothing.
set -euo pipefail

OWNER_NAME="Gerrrt"
OWNER_EMAIL="garrettallen2@gmail.com"

current_name="$(git config --get user.name || true)"
current_email="$(git config --get user.email || true)"

is_placeholder=false
case "$current_email" in
    *@anthropic.com | "") is_placeholder=true ;;
esac
[ "$current_name" = "Claude" ] && is_placeholder=true

if [ "$is_placeholder" = true ]; then
    # Repo-local, so it cannot leak into unrelated checkouts in the same
    # container.
    git config --local user.name "$OWNER_NAME"
    git config --local user.email "$OWNER_EMAIL"
    echo "git identity: replaced placeholder '${current_name:-unset} <${current_email:-unset}>' with '$OWNER_NAME <$OWNER_EMAIL>'"
else
    echo "git identity: keeping configured '$current_name <$current_email>'"
fi
