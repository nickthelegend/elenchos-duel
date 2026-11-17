// Elenchos Gate: the Proof Gatekeeper side of the same agent.
// Deterministic checks decide; the official gatekeeper circuit proves the decision; a durable seen-set stops replays.
// The circuit forces the decision from the arithmetic (a REJECT on inputs that pass, or an APPROVE on a trap, cannot be
// proven), so PROOF_REUSED is the one verdict that ships without a proof: no valid one exists for it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

export const GATE_TYPE = 'agent-games.proof-gatekeeper.v1';
const ART = fileURLToPath(new URL('../artifacts/', import.meta.url));
const VK = JSON.parse(readFileSync(`${ART}gatekeeper_vk.json`, 'utf8'));
export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const HEX = /^0x[0-9a-fA-F]{1,64}$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const UUID_TAIL = /([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$/;
const FIELDS = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block', 'current_block',
  'recipient', 'condition_recipient', 'amount', 'max_transfer', 'proof_tx'];

// Numbers may arrive as decimal strings or JSON integers; both are read exactly (never as floats).
const DEC = /^(0|[1-9][0-9]{0,9})$/;
const num = (v) => (typeof v === 'string' && DEC.test(v) && BigInt(v) <= 0xffffffffn ? BigInt(v)
  : Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff ? BigInt(v) : null);

/** Returns null when the task is well formed, else the first problem (never interpreted, only rejected).
 *  Extra input fields are ignored: the decision depends only on the documented ones. */
export function invalid(t) {
  if (!t || t.type !== GATE_TYPE) return 'type';
  if (typeof t.task_id !== 'string' || !t.task_id || t.task_id.length > 160) return 'task_id';
  if (!Number.isFinite(Date.parse(t.deadline_at))) return 'deadline_at';
  const i = t.input;
  if (!i || typeof i !== 'object') return 'input';
  if (!HEX.test(i.registered_vk ?? '') || !HEX.test(i.proof_vk ?? '')) return 'vk';
  for (const k of ['minimum', 'public_balance', 'amount', 'max_transfer', 'expiry_block', 'current_block']) if (num(i[k]) === null) return k;
  if (!ADDR.test(i.recipient ?? '') || !ADDR.test(i.condition_recipient ?? '')) return 'address';
  if (!HEX.test(i.proof_tx ?? '')) return 'proof_tx';
  return null;
}

/** Input fields this agent does not use (logged, never acted on). */
export const extraFields = (t) => Object.keys(t?.input ?? {}).filter((k) => !FIELDS.includes(k));

/** The five arithmetic checks, in the trap encyclopedia's order. Values compared as integers, never floats. */
export function arithmetic(i) {
  if (BigInt(i.registered_vk) !== BigInt(i.proof_vk)) return 'VK_SUBSTITUTION';
  if (num(i.public_balance) < num(i.minimum)) return 'THRESHOLD_MISMATCH';
  if (num(i.expiry_block) <= num(i.current_block)) return 'EXPIRED_CONDITION';
  if (BigInt(i.recipient) !== BigInt(i.condition_recipient)) return 'RECIPIENT_MISMATCH';
  if (num(i.amount) > num(i.max_transfer)) return 'AMOUNT_OVERFLOW';
  return 'VALID_CONDITION';
}

/** The circuit's taskId: the task id's UUID tail as one 128-bit integer (null if the id carries no UUID). */
export function taskIdSignal(taskId) {
  const m = UUID_TAIL.exec(taskId);
  return m ? BigInt(`0x${m.slice(1).join('')}`) : null;
}

/** Public inputs in circuit order (they follow the commitment output in public_signals). */
export function publicInputs(t, approve) {
  const i = t.input;
  return [i.registered_vk, i.proof_vk, i.minimum, i.public_balance, i.expiry_block, i.current_block, i.recipient,
    i.condition_recipient, i.amount, i.max_transfer, approve ? 1 : 0, taskIdSignal(t.task_id)]
    .map((v) => (BigInt(v) % FIELD).toString());
}
const WITNESS = ['registeredVkHash', 'proofVkHash', 'minimum', 'publicBalance', 'expiryBlock', 'currentBlock',
  'recipient', 'conditionRecipient', 'amount', 'maxTransfer', 'decision', 'taskId'];

export async function proveDecision(t, approve) {
  const values = publicInputs(t, approve);
  const witness = Object.fromEntries(WITNESS.map((n, k) => [n, values[k]]));
  const salt = new Uint8Array(32); crypto.getRandomValues(salt);
  witness.salt = (BigInt(`0x${Buffer.from(salt).toString('hex')}`) % FIELD).toString();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(witness, `${ART}gatekeeper.wasm`, `${ART}gatekeeper_final.zkey`, undefined, undefined, { singleThread: true });
  if (publicSignals.length !== 13 || publicSignals.slice(1).some((v, k) => v !== values[k])) throw new Error('public signals do not match the task');
  if (!(await snarkjs.groth16.verify(VK, publicSignals, proof))) throw new Error('local verification failed');
  return { proof, public_signals: publicSignals };
}

const answered = new Map(); // task_id -> { body, reply }: identical retries get the identical answer on a warm instance

/**
 * Decide one task. `seen.claim(ref, taskId, mode)` resolves 'fresh' | 'retry' | 'reused' and throws if the store is down.
 * Fail closed: anything uncertain is a REJECT; an APPROVE always carries a locally verified proof.
 */
export async function playGate(t, raw, { seen, log = () => {}, now = Date.now() } = {}) {
  const prior = answered.get(t?.task_id);
  if (prior) return prior.body === raw ? prior.reply : { decision: 'REJECT', reason_code: 'TASK_ID_CONFLICT' };
  const remember = (reply) => { answered.set(t.task_id, { body: raw, reply }); if (answered.size > 5000) answered.delete(answered.keys().next().value); return reply; };

  const bad = invalid(t);
  const extra = extraFields(t);
  if (extra.length) log({ at: 'gate-extra-fields', task: t?.task_id, fields: extra });
  if (bad) { log({ at: 'gate-invalid', task: t?.task_id, field: bad }); return remember({ decision: 'REJECT', reason_code: 'INVALID_TASK' }); }
  if (Date.parse(t.deadline_at) <= now) return remember({ decision: 'REJECT', reason_code: 'TIMEOUT' });

  const reason = arithmetic(t.input);
  let claim;
  try { claim = seen ? await seen.claim(t.input.proof_tx, t.task_id, t.mode) : null; } catch (err) { log({ at: 'gate-seen-error', task: t.task_id, error: err.message }); claim = null; }

  let reply;
  if (reason !== 'VALID_CONDITION') reply = { decision: 'REJECT', reason_code: reason };
  else if (claim === 'reused') return remember({ decision: 'REJECT', reason_code: 'PROOF_REUSED' });
  else if (claim === null) return remember({ decision: 'REJECT', reason_code: 'REPLAY_CHECK_UNAVAILABLE' }); // cannot rule out reuse
  else reply = { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };

  if (taskIdSignal(t.task_id) === null) {
    log({ at: 'gate-no-uuid', task: t.task_id });
    return remember(reply.decision === 'APPROVE' ? { decision: 'REJECT', reason_code: 'UNPROVABLE_TASK_ID' } : reply);
  }
  try {
    return remember({ ...reply, ...(await proveDecision(t, reply.decision === 'APPROVE')) });
  } catch (err) {
    log({ at: 'gate-proof-failed', task: t.task_id, error: err.message });
    return remember(reply.decision === 'APPROVE' ? { decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED' } : reply);
  }
}

/** Durable seen-set on Vercel Blob: one private blob per proof reference, created only if absent. */
export function blobSeen(token = process.env.BLOB_READ_WRITE_TOKEN) {
  if (!token) return null;
  return {
    // Practice and scored tasks keep separate seen-sets, so a practice fixture can never make a scored task look reused.
    async claim(ref, taskId, mode) {
      const { put, get } = await import('@vercel/blob');
      const pathname = mode === 'practice' ? `seen/${BigInt(ref).toString(16)}.json` : `seen/scored/${BigInt(ref).toString(16)}.json`;
      try {
        await put(pathname, JSON.stringify({ taskId, at: new Date().toISOString() }),
          { access: 'private', addRandomSuffix: false, allowOverwrite: false, contentType: 'application/json', token });
        return 'fresh';
      } catch (err) {
        if (!/already exists/i.test(err.message)) throw err;
        const r = await get(pathname, { access: 'private', token, useCache: false });
        if (!r || r.statusCode !== 200) throw new Error('seen entry exists but could not be read');
        const { taskId: first } = JSON.parse(await new Response(r.stream).text());
        return first === taskId ? 'retry' : 'reused';
      }
    },
  };
}
