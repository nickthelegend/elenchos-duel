// Real tests: real Groth16 proofs with the official circuit artifacts, real HMAC. No mocks.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'node:fs';
import { handle } from '../src/handler.js';
import { authenticate, sign } from '../src/hmac.js';
import { decide, idempotencyKey, publicInputsHash, PARAMS } from '../src/steal.js';

after(async () => { await globalThis.curve_bn128?.terminate(); });
const SECRET = 'test-secret-not-a-real-one-0123456789';
const SALT = 1234567890123456789n;
const poseidon = await buildPoseidon();
const COMMITMENT = BigInt(poseidon.F.toString(poseidon([...PARAMS, SALT])));
const env = { STRATEGY_SALT: String(SALT), STRATEGY_COMMITMENT: String(COMMITMENT) };
const quiet = () => {};
const req = (o) => { const raw = Buffer.from(JSON.stringify(o)); return { raw, sig: sign(raw.toString(), SECRET) }; };
const turn = (over = {}) => ({
  protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice', matchId: '0b6f7c3e-2a41-4f5e-9d3a-7c1e2b4a5d6f', turn: 3,
  issuedAt: new Date().toISOString(), state: { selfBalance: '104', opponentBalance: '96', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: `0x${COMMITMENT.toString(16)}` }, ...over,
});

test('policy is 10,0,0,0: extract 10 while the opponent has anything, never fortify', () => {
  assert.deepEqual(decide(100n, 100n), { action: 2n, amount: 10n });
  assert.deepEqual(decide(0n, 5n), { action: 2n, amount: 10n });
  assert.deepEqual(decide(50n, 0n), { action: 0n, amount: 0n });
});

test('HMAC: accepts hex, sha256= prefix and base64 forms; rejects tampering and wrong secrets', () => {
  const raw = Buffer.from('{"a":1}');
  assert.ok(authenticate(raw, sign('{"a":1}', SECRET), SECRET));
  assert.ok(authenticate(raw, `sha256=${sign('{"a":1}', SECRET)}`, SECRET));
  assert.ok(authenticate(raw, Buffer.from(sign('{"a":1}', SECRET), 'hex').toString('base64'), SECRET));
  assert.equal(authenticate(Buffer.from('{"a":2}'), sign('{"a":1}', SECRET), SECRET), null);
  assert.equal(authenticate(raw, sign('{"a":1}', 'another-secret-0123456789'), SECRET), null);
  assert.equal(authenticate(raw, null, SECRET), null);
  assert.equal(authenticate(raw, sign('{"a":1}', SECRET), undefined), null);
});

test('unsigned or badly signed requests get 401 and are never parsed', async () => {
  const r = await handle(Buffer.from('not json'), 'deadbeef', { secret: SECRET, env, log: quiet });
  assert.equal(r.status, 401);
  assert.equal(r.headers['x-agent-games-signature'], undefined);
});

test('preflight is answered and the response bytes are signed', async () => {
  const { raw, sig } = req({ type: 'agent-games.preflight.v1', agent_id: 'x', issued_at: new Date().toISOString(), nonce: 'n1' });
  const r = await handle(raw, sig, { secret: SECRET, env, log: quiet });
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.body), { ok: true, protocolVersion: 'v1' });
  assert.equal(r.headers['x-agent-games-signature'], sign(r.body, SECRET));
});

test('stale envelopes are refused', async () => {
  const { raw, sig } = req(turn({ issuedAt: new Date(Date.now() - 3_600_000).toISOString() }));
  assert.equal((await handle(raw, sig, { secret: SECRET, env, log: quiet })).status, 400);
});

test('a turn returns EXTRACT 10 with a real Groth16 proof that the official VK accepts; retries are identical', async () => {
  const e = turn();
  const { raw, sig } = req(e);
  const r = await handle(raw, sig, { secret: SECRET, env, log: quiet });
  assert.equal(r.status, 200, r.body);
  const body = JSON.parse(r.body);
  assert.deepEqual(body.action, { type: 'EXTRACT', amount: 10 });
  const vk = JSON.parse(readFileSync(new URL('../artifacts/vfy-policy_vk.json', import.meta.url)));
  assert.ok(await snarkjs.groth16.verify(vk, body.policyProof.public_signals, body.policyProof.proof));
  const s = body.policyProof.public_signals;
  assert.equal(s.length, 9);
  assert.deepEqual(s.slice(1), [COMMITMENT, BigInt('0x0b6f7c3e2a414f5e9d3a7c1e2b4a5d6f'), 3n, 104n, 96n, 2n, 10n, 1n].map(String));
  assert.equal(body.policyProof.publicInputsHash, publicInputsHash(COMMITMENT, e, 2n, 10n));
  assert.match(body.idempotencyKey, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(body.idempotencyKey, idempotencyKey(e.matchId, 3));
  const again = await handle(raw, sig, { secret: SECRET, env, log: quiet });
  assert.equal(again.body, r.body);
});

test('HOLD omits amount, and a proof is still produced', async () => {
  const e = turn({ turn: 7, state: { selfBalance: '200', opponentBalance: '0' } });
  const { raw, sig } = req(e);
  const body = JSON.parse((await handle(raw, sig, { secret: SECRET, env, log: quiet })).body);
  assert.deepEqual(body.action, { type: 'HOLD' });
  assert.equal(body.policyProof.public_signals[6], '0');
});

test('a wrong salt cannot produce a proof (the circuit opens the commitment)', async () => {
  const { raw, sig } = req(turn({ turn: 9 }));
  const r = await handle(raw, sig, { secret: SECRET, env: { ...env, STRATEGY_SALT: '99' }, log: quiet });
  assert.equal(r.status, 503);
});

test('missing strategy config fails loudly, not with a fake move', async () => {
  const { raw, sig } = req(turn({ turn: 11 }));
  const r = await handle(raw, sig, { secret: SECRET, env: {}, log: quiet });
  assert.equal(r.status, 503);
});
