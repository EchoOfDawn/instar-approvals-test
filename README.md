# instar-approvals-test

TEST origin (`https://echoofdawn.github.io`, agent-owned) for the Instar phone approval client and its
external verifier. It exercises the mechanics only; it is **not** a custody installation, because the
agent owns this account. The real installation lives in the operator's own repository and origin.

- `index.html`, `app.js`, `core.mjs`, `style.css` — the static client (no third-party code).
- `.github/workflows/verifier.yml`, `verifier/run.mjs` — the external verifier (GitHub-hosted runners).
- `installation.json`, `approvers/` — authority, written only by the owner's own direct commits.
- `ledger` branch — challenges, consumption claims and signed receipts, written create-once by the verifier.
- `tests/` — `node --test tests/*.test.mjs`.
