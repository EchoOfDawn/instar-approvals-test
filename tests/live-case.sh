#!/bin/sh
# live-case.sh <proposal|act> <file> [extra-path extra-file]: submit, wait (max 4 min) for the verifier, print its verdict.
cd "$(dirname "$0")/.." || exit 1
PR=$(GHE=$GHE node tests/submit.mjs "$@" 2>/dev/null | tail -1 | sed 's#.*/##')
i=0; while [ $i -lt 60 ] && [ "$($GHE pr view "$PR" -R EchoOfDawn/instar-approvals-test --json state --jq .state)" != CLOSED ]; do sleep 4; i=$((i+1)); done
echo "PR $PR: $($GHE pr view "$PR" -R EchoOfDawn/instar-approvals-test --json state,comments --jq '.state + " | " + (.comments[-1].body // "no verdict")')"
