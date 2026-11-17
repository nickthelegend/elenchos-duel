// Proof Gatekeeper: every trap from the event's encyclopedia, real Groth16 proofs with the official gatekeeper circuit,
// real HMAC. The seen-set is exercised in-process and, when a Blob token is present, against the real Vercel Blob store.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
import { handle } from '../src/handler.js';
import { authenticate, sign } from '../src/hmac.js';
import { arithmetic, blobSeen, playGate } from '../src/gate.js';

after(async () => { await globalThis.curve_bn128?.terminate(); });
const VK = JSON.parse(readFileSync(new URL('../artifacts/gatekeeper_vk.json', import.meta.url), 'utf8'));
const SECRET = 'test-secret-not-a-real-one-0123456789';
const quiet = () => {};
const memorySeen = () => { const m = new Map(); return { claim: async (ref, id) => (m.has(BigInt(ref)) ? (m.get(BigInt(ref)) === id ? 'retry' : 'reused') : (m.set(BigInt(ref), id), 'fresh')) }; };
const addr = (b) => `0x${b.repeat(20)}`;
const task = (input = {}, over = {}) => ({
  type: 'agent-games.proof-gatekeeper.v1', task_id: `gk_R05_${randomUUID()}`, mode: 'practice',
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60_000).toISOString(),
  input: { registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0', proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    minimum: '1000', public_balance: '1460', expiry_block: 19842201, current_block: 19832000, recipient: addr('de'), condition_recipient: addr('de'),
    amount: '500', max_transfer: '1000', proof_tx: `0x${randomBytes(32).toString('hex')}`, ...input },
  ...over,
});
const play = (t, seen = memorySeen()) => playGate(t, JSON.stringify(t), { seen, log: quiet });
const verified = async (r) => r.proof && snarkjs.groth16.verify(VK, r.public_signals, r.proof);

const TRAPS = [
  ['VK_SUBSTITUTION', { proof_vk: '0xa4c1b8ff' }],
  ['THRESHOLD_MISMATCH', { public_balance: '999' }],
  ['EXPIRED_CONDITION', { expiry_block: 19832000 }],
  ['RECIPIENT_MISMATCH', { condition_recipient: addr('ab') }],
  ['AMOUNT_OVERFLOW', { amount: '1001' }],
];

test('valid condition: APPROVE with a proof that verifies against the official gatekeeper key', async () => {
  const r = await play(task());
  assert.equal(r.decision, 'APPROVE'); assert.equal(r.reason_code, 'VALID_CONDITION');
  assert.equal(r.public_signals.length, 13); assert.equal(r.public_signals[11], '1');
  assert.ok(await verified(r));
});

for (const [code, input] of TRAPS) {
  test(`${code}: REJECT with the trap's reason and a verified rejection proof`, async () => {
    const r = await play(task(input));
    assert.equal(r.decision, 'REJECT'); assert.equal(r.reason_code, code);
    assert.equal(r.public_signals[11], '0');
    assert.ok(await verified(r));
  });
}

test('PROOF_REUSED: a reference seen in an earlier task is rejected; an identical retry gets the same answer', async () => {
  const seen = memorySeen();
  const first = task();
  const a = await play(first, seen);
  assert.equal(a.decision, 'APPROVE');
  assert.deepEqual(await play(first, seen), a, 'identical retry returns the saved reply');
  const replay = task({ proof_tx: first.input.proof_tx });
  const b = await play(replay, seen);
  assert.deepEqual(b, { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
});

test('fail closed: no replay store means no APPROVE; malformed and expired tasks reject', async () => {
  const down = { claim: async () => { throw new Error('store down'); } };
  assert.deepEqual(await play(task(), down), { decision: 'REJECT', reason_code: 'REPLAY_CHECK_UNAVAILABLE' });
  const trap = await play(task({ amount: '5000' }), down); // traps still prove their rejection
  assert.equal(trap.reason_code, 'AMOUNT_OVERFLOW'); assert.ok(await verified(trap));
  assert.equal((await play(task({ amount: '1.5' }))).reason_code, 'INVALID_TASK');
  assert.equal((await play(task({ amount: String(2 ** 32) }))).reason_code, 'INVALID_TASK');
  assert.equal((await play(task({}, { deadline_at: new Date(Date.now() - 1).toISOString() }))).reason_code, 'TIMEOUT');
});

test('tolerant input: an extra field is ignored and numbers may arrive as JSON integers or decimal strings', async () => {
  const r = await play(task({ note: 'added later', minimum: 1000, public_balance: 1460, amount: 500, max_transfer: 1000, expiry_block: '19842201', current_block: '19832000' }));
  assert.equal(r.decision, 'APPROVE'); assert.equal(r.reason_code, 'VALID_CONDITION'); assert.ok(await verified(r));
  assert.equal((await play(task({ public_balance: 999, minimum: 1000 }))).reason_code, 'THRESHOLD_MISMATCH');
  assert.equal((await play(task({ amount: 1.5 }))).reason_code, 'INVALID_TASK');
});

test('scored tasks never see practice references: the same proof_tx is fresh in scored mode', async () => {
  const calls = [];
  const seen = { claim: async (ref, id, mode) => { calls.push(mode); return 'fresh'; } };
  await play(task({}, { mode: 'scored' }), seen);
  await play(task(), seen);
  assert.deepEqual(calls, ['scored', 'practice']);
});

test('check order follows the encyclopedia and compares integers, not strings', () => {
  const base = task().input;
  assert.equal(arithmetic({ ...base, proof_vk: '0x6B79C6012A6D8651F3E13BC4D2A20370280AB49700C90C5316D4168BFBAD77B0' }), 'VALID_CONDITION');
  assert.equal(arithmetic({ ...base, recipient: addr('DE') }), 'VALID_CONDITION');
  assert.equal(arithmetic({ ...base, public_balance: '1000' }), 'VALID_CONDITION');
  assert.equal(arithmetic({ ...base, amount: '1000' }), 'VALID_CONDITION');
});

test('transport: a signed gatekeeper task returns a signed decision; a bad signature is refused', async () => {
  const t = task();
  const raw = Buffer.from(JSON.stringify(t));
  const r = await handle(raw, sign(raw.toString(), SECRET), { secret: SECRET, seen: memorySeen(), log: quiet });
  assert.equal(r.status, 200);
  assert.ok(authenticate(Buffer.from(r.body), r.headers['x-agent-games-signature'], SECRET));
  assert.equal(JSON.parse(r.body).decision, 'APPROVE');
  const forged = await handle(raw, sign(raw.toString(), 'wrong-secret-0123456789abcdef'), { secret: SECRET, seen: memorySeen(), log: quiet });
  assert.equal(forged.status, 401);
});

let blobToken;
try { process.loadEnvFile(new URL('../.env.local', import.meta.url)); blobToken = process.env.BLOB_READ_WRITE_TOKEN; } catch { /* no local token */ }
test('live Vercel Blob seen-set: fresh, retry, reused', { skip: blobToken ? false : 'Setup required: BLOB_READ_WRITE_TOKEN (vercel env pull)' }, async () => {
  const seen = blobSeen(blobToken);
  const ref = `0x${randomBytes(32).toString('hex')}`;
  assert.equal(await seen.claim(ref, 'gk_test_a'), 'fresh');
  assert.equal(await seen.claim(ref, 'gk_test_a'), 'retry');
  assert.equal(await seen.claim(ref, 'gk_test_b'), 'reused');
});
