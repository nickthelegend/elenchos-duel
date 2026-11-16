// Creates the strategy salt and commitment once. The salt goes only to .env.strategy (gitignored) and never to
// stdout; the commitment is public and is printed so it can be registered on the Agent Games dashboard.
// Usage: node scripts/commitment.js            (refuses to overwrite an existing .env.strategy)
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { buildPoseidon } from 'circomlibjs';
import { PARAMS } from '../src/steal.js';

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const file = new URL('../.env.strategy', import.meta.url);
if (existsSync(file)) { console.error('.env.strategy exists; delete it deliberately to make a new commitment'); process.exit(1); }
let salt;
do { salt = BigInt(`0x${randomBytes(32).toString('hex')}`); } while (salt === 0n || salt >= R);
export async function commit(params, s) {
  const p = await buildPoseidon();
  return BigInt(p.F.toString(p([...params, s])));
}
const c = await commit(PARAMS, salt);
writeFileSync(file, `STRATEGY_PARAMS=${PARAMS.join(',')}\nSTRATEGY_SALT=${salt}\nSTRATEGY_COMMITMENT=${c}\n`, { mode: 0o600 });
console.log(`commitment (decimal) ${c}\ncommitment (hex)     0x${c.toString(16).padStart(64, '0')}\nsalt written to .env.strategy (not shown)`);
process.exit(0);
