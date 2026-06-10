#!/usr/bin/env bash
# Push the current HEAD to origin/main, surviving a concurrent push from a
# sibling job or any other writer.
#
# fetch-rebase-push is NOT atomic: another writer can advance main between the
# rebase and the push, so the push is rejected non-fast-forward. We retry the
# whole fetch-rebase-push with linear backoff until it lands (or give up and
# fail the step). Any rebase left in progress by a failed attempt is aborted
# first so the next attempt restarts from a clean state.
#
# Shared by the `publish` (bench/results) and `publish-datasheet`
# (blog/artifacts) jobs in .github/workflows/benchmark.yml — they run on
# separate runners and cannot share an inline shell function, so the logic
# lives in this single committed script to avoid drift.
set -euo pipefail

attempts="${PUSH_RETRY_ATTEMPTS:-5}"

for attempt in $(seq 1 "$attempts"); do
  if git pull --rebase origin main && git push; then
    exit 0
  fi
  git rebase --abort 2>/dev/null || true
  # Don't back off after the final attempt — we're about to give up.
  if [ "$attempt" -lt "$attempts" ]; then
    echo "push attempt $attempt hit a concurrent update; retrying after backoff..."
    sleep "$((attempt * 3))"
  fi
done

echo "failed to push to main after $attempts attempts" >&2
exit 1
