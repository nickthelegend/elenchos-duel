// Steal the VFY turn logic. The strategy is the official circuit's policy family with parameters 10,0,0,0:
// FORTIFY never (selfBalance < 0 is impossible), EXTRACT 10 whenever the opponent has anything, otherwise HOLD.
// Brute force over all 87,120 legal policies (and an all-move-sequences search by the VFY council) found nothing
// that beats it head-to-head; the edge left is a valid proof on every turn and never missing a deadline.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { concat, keccak256, numberToHex } from 'viem';
import * as snarkjs from 'snarkjs';

const ART = fileURLToPath(new URL('../artifacts/', import.meta.url));
const VK = JSON.parse(readFileSync(`${ART}vfy-policy_vk.json`, 'utf8'));
// The official circuit files, read once per instance (snarkjs takes them as in-memory buffers).
const WASM = new Uint8Array(readFileSync(`${ART}vfy-policy.wasm`));
const ZKEY = new Uint8Array(readFileSync(`${ART}vfy-policy_final.zkey`));
export const PARAMS = [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const HOLD = 0n, FORTIFY = 1n, EXTRACT = 2n;
const NAMES = ['HOLD', 'FORTIFY', 'EXTRACT'];

/** Exactly the circuit's policy for PARAMS. */
export function decide(selfBalance, opponentBalance) {
  const [amount, fortifyBelow, extractAbove, holdFlag] = PARAMS;
  if (selfBalance < fortifyBelow) return { action: FORTIFY, amount: 0n };
  if (opponentBalance > extractAbove && holdFlag === 0n) return { action: EXTRACT, amount };
  return { action: HOLD, amount: 0n };
}

export const matchIdField = (matchId) => BigInt(`0x${matchId.replace(/-/g, '')}`);

/** Build guide: keccak256 over eight 32-byte big-endian words. */
export function publicInputsHash(commitment, e, action, amount) {
  return keccak256(concat([commitment, matchIdField(e.matchId), BigInt(e.turn), BigInt(e.state.selfBalance), BigInt(e.state.opponentBalance), action, amount, 1n]
    .map((v) => numberToHex(v, { size: 32 }))));
}

/** UUID-shaped (v5 bits) and deterministic per (match, turn): a retry reuses it, a new turn never does. */
export function idempotencyKey(matchId, turn) {
  const b = createHash('sha256').update(`elenchos:${matchId}:${turn}`).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function strategyFromEnv(env = process.env) {
  if (!env.STRATEGY_SALT || !env.STRATEGY_COMMITMENT) throw new Error('Setup required: STRATEGY_SALT and STRATEGY_COMMITMENT');
  return { salt: BigInt(env.STRATEGY_SALT), commitment: BigInt(env.STRATEGY_COMMITMENT) };
}

const answered = new Map();  // turn key -> the exact response already sent (identical retries)
const proved = new Map();    // proof key -> { proof, publicSignals } proved ahead of time

/** Proves the policy move for one exact state. Verified locally; throws if it cannot prove honestly. */
async function prove(cfg, matchId, turn, self, opp) {
  const pick = decide(self, opp);
  const input = {
    strategyParams: PARAMS.map(String), salt: cfg.salt.toString(), commitment: cfg.commitment.toString(),
    matchId: matchIdField(matchId).toString(), turnNumber: String(turn), selfBalance: self.toString(), opponentBalance: opp.toString(),
    action: pick.action.toString(), amount: pick.amount.toString(), circuitVersion: '1',
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY, undefined, undefined, { singleThread: true });
  if (!(await snarkjs.groth16.verify(VK, publicSignals, proof))) throw new Error('Local policy proof failed to verify');
  return { proof, publicSignals };
}
const proofKey = (matchId, turn, self, opp) => `${matchId}:${turn}:${self}:${opp}`;

/**
 * After answering turn t, prove turn t+1 for the most likely next state: balances unchanged, which is exactly what a
 * mirror match (both sides EXTRACT 10) produces. A prediction is only a cache entry keyed on the full public state, so
 * a wrong guess is never used: the real turn then proves from scratch as before.
 */
export function prepareNext(e, cfg, log = () => {}) {
  if (!(e.turn >= 1 && e.turn < 20)) return Promise.resolve();
  const self = BigInt(e.state.selfBalance), opp = BigInt(e.state.opponentBalance);
  const k = proofKey(e.matchId, e.turn + 1, self, opp);
  if (proved.has(k)) return Promise.resolve();
  return prove(cfg, e.matchId, e.turn + 1, self, opp)
    .then((p) => { proved.set(k, p); if (proved.size > 200) proved.delete(proved.keys().next().value); })
    .catch((err) => log({ at: 'prepare-failed', matchId: e.matchId, turn: e.turn + 1, error: err.message }));
}

/** Proves and answers one turn. Throws on anything it cannot prove honestly. */
export async function playTurn(e, cfg, log = (o) => console.log(JSON.stringify(o))) {
  if (!e || typeof e.matchId !== 'string' || !/^[0-9a-f-]{32,36}$/i.test(e.matchId) || !Number.isSafeInteger(e.turn) || !e.state) throw new Error('Malformed turn envelope');
  const key = `${e.mode ?? ''}:${e.matchId}:${e.turn}`;
  if (answered.has(key)) return answered.get(key);
  const self = BigInt(e.state.selfBalance), opp = BigInt(e.state.opponentBalance);
  if (self < 0n || opp < 0n || self > 65535n || opp > 65535n) throw new Error('Balance outside the circuit range');
  // The proof opens OUR commitment; publicInputsHash follows the one the platform holds. They differ only for
  // practice placeholders or a bad registration, which we log loudly.
  const held = e.strategyCommitment?.hash ? BigInt(e.strategyCommitment.hash) : cfg.commitment;
  if (held !== cfg.commitment) log({ at: 'commitment-mismatch', mode: e.mode, held: e.strategyCommitment.hash });
  const pick = decide(self, opp);
  const pk = proofKey(e.matchId, e.turn, self, opp);
  const ready = proved.get(pk);
  const { proof, publicSignals } = ready ?? await prove(cfg, e.matchId, e.turn, self, opp);
  if (ready) proved.delete(pk);
  const body = {
    protocolVersion: 'v1', matchId: e.matchId, turn: e.turn,
    action: pick.action === EXTRACT ? { type: 'EXTRACT', amount: Number(pick.amount) } : { type: NAMES[Number(pick.action)] },
    policyProof: {
      circuitVersion: 'v1', proof, public_signals: publicSignals,
      publicInputsHash: publicInputsHash(held, e, pick.action, pick.amount),
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKey(e.matchId, e.turn),
  };
  answered.set(key, body);
  if (answered.size > 2000) answered.delete(answered.keys().next().value);
  if (ready) log({ at: 'turn-prepared', matchId: e.matchId, turn: e.turn });
  return body;
}
