# instar-approvals-test

TEST origin (`https://echoofdawn.github.io`, agent-owned) for the Instar phone approval client and its
external verifier. It exercises the mechanics only; it is **not** a custody installation, because the
agent owns this account. The real installation lives in the operator's own repository and origin.

- `index.html`, `app.js`, `core.mjs`, `style.css` — the static client (no third-party code).
- `.github/workflows/verifier.yml`, `verifier/run.mjs` — the external verifier (GitHub-hosted runners).
- `installation.json`, `approvers/` — authority. The verifier reads it from current `main` at every
  acceptance, and only a version the custodian (the `principal` in `installation.json`) committed directly counts.
- `ledger` branch — challenges and signed receipts, written create-once by the verifier, which creates the
  branch on first use.
- `setup/protection-ruleset.json` — the one ruleset to import (no deletion, no force-push on `main` and `ledger`).
- `scripts/check-architecture.mjs` — this repository's boundary check. `tests/` — `node --test tests/*.test.mjs`.

## If you lose your phone

Enrol a passkey on your phone and Mac before relying on approvals, so either one still works; Apple
passkeys also sync through iCloud Keychain. If every passkey is lost: from any computer signed into your
GitHub account (GitHub has its own recovery codes), open the page with `#enrol`, add a new passkey and
save it. To retire a lost device, delete its file in `approvers/`. A missing passkey only pauses the changes that need your approval; the agent keeps running within its limits, and "stop" in Telegram keeps working.
