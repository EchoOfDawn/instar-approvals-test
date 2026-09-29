// Agent side: submit one bounded file as a pull request (the agent's only channel into the verifier).
//   node tests/submit.mjs <proposal|act> <json-file> [<extra-path> <extra-file>]  -> prints the PR number
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
const [kind, file, extraPath, extraFile] = process.argv.slice(2);
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const name = `${kind}-${randomBytes(6).toString('hex')}`, branch = `submit/${name}`;
git('fetch', '-q', 'origin', 'main');
git('switch', '-q', '-c', branch, 'origin/main');
try {
  git('show', `HEAD:README.md`);
  execFileSync('cp', [file, `inbox/${name}.json`]);
  git('add', `inbox/${name}.json`);
  if (extraPath) { execFileSync('mkdir', ['-p', extraPath.split('/').slice(0, -1).join('/') || '.']); execFileSync('cp', [extraFile, extraPath]); git('add', extraPath); }
  git('commit', '-qm', `submit ${name}`);
  git('push', '-q', 'origin', branch);
  console.log(execFileSync(process.env.GHE, ['pr', 'create', '-R', 'EchoOfDawn/instar-approvals-test', '--head', branch, '--base', 'main',
    '--title', `submit ${name}`, '--body', 'Verifier submission.'], { encoding: 'utf8' }).trim());
} finally { git('switch', '-q', 'main'); }
