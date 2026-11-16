// Transport for the Agent Games webhook: verify the HMAC over the raw bytes before parsing, answer preflight,
// decide Proof Gatekeeper tasks, play Steal the VFY turns, sign the exact response bytes.
import { authenticate } from './hmac.js';
import { playTurn, strategyFromEnv } from './steal.js';
import { GATE_TYPE, blobSeen, playGate } from './gate.js';

const out = (status, payload, signer) => {
  const body = JSON.stringify(payload);
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (signer) headers['x-agent-games-signature'] = signer(body);
  return { status, body, headers };
};

export function checkIssued(e, now = Date.now()) {
  const at = Date.parse(e.issued_at ?? e.issuedAt);
  if (!Number.isFinite(at) || at > now + 120_000 || at < now - 600_000) throw new Error('Invalid or stale issue timestamp');
}

export async function handle(raw, signature, { secret, env = process.env, now = Date.now(), seen = blobSeen(env.BLOB_READ_WRITE_TOKEN), log = (o) => console.log(JSON.stringify(o)) }) {
  if (raw.length > 64 * 1024) return out(413, { error: 'Body too large' });
  const signer = authenticate(raw, signature, secret);
  if (!signer) { log({ at: 'auth-failed', bytes: raw.length, hasHeader: Boolean(signature) }); return out(401, { error: 'Invalid signature' }); }
  let e;
  try {
    e = JSON.parse(raw.toString('utf8'));
    if (!e || typeof e !== 'object' || Array.isArray(e)) throw new Error('not an object');
    checkIssued(e, now);
  } catch (err) {
    log({ at: 'bad-envelope', error: err.message });
    return out(400, { error: 'Invalid request' }, signer);
  }
  if (e.type === 'agent-games.preflight.v1') { log({ at: 'preflight', agent: e.agent_id }); return out(200, { ok: true, protocolVersion: 'v1' }, signer); }
  if (e.type === GATE_TYPE) {
    const started = Date.now();
    const body = await playGate(e, raw.toString('utf8'), { seen, log, now: Date.now() });
    log({ at: 'gate', mode: e.mode, task: e.task_id, decision: body.decision, reason: body.reason_code, proof: Boolean(body.proof), ms: Date.now() - started });
    return out(200, body, signer);
  }
  if (!(e.eventId === 'steal-the-vfy' || (e.matchId && e.turn !== undefined))) return out(400, { error: 'Unsupported task type' }, signer);
  const started = Date.now();
  try {
    const body = await playTurn(e, strategyFromEnv(env), log);
    log({ at: 'turn', mode: e.mode, matchId: e.matchId, turn: e.turn, self: e.state.selfBalance, opp: e.state.opponentBalance, action: body.action, ms: Date.now() - started });
    return out(200, body, signer);
  } catch (err) {
    log({ at: 'turn-failed', matchId: e.matchId, turn: e.turn, error: err.message });
    return out(503, { error: 'Turn processing failed' }, signer);
  }
}
