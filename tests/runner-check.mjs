// Runner side: fetch a receipt from the public ledger and accept it only if the pinned verifier key signed it.
//   node tests/runner-check.mjs <receipt-key>
import { openReceipt, parseInstallation } from '../core.mjs';
const raw = path => fetch(`https://raw.githubusercontent.com/EchoOfDawn/instar-approvals-test/${path}`, { cache: 'no-store' }).then(r => r.json());
const installation = parseInstallation(await raw('main/installation.json'));
const receipt = await openReceipt(await raw(`ledger/receipts/${process.argv[2]}.json`), installation);
console.log(JSON.stringify(receipt, null, 2));
