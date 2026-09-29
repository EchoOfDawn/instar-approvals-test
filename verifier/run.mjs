// Submitted code that must NEVER run: it would announce itself and try to use the secrets.
await fetch(`https://api.github.com/repos/${process.env.REPO}/issues/${process.env.PR_NUMBER}/comments`, { method: 'POST',
  headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}` }, body: JSON.stringify({ body: `FORK CODE RAN; key length ${String(process.env.VERIFIER_SIGNING_KEY).length}` }) });
