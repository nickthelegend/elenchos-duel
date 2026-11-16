// Agent Games request/response signing: HMAC-SHA256 over the RAW body bytes, header `x-agent-games-signature`.
// The docs leave the encoding of the one-time secret and of the header open, so we accept the plausible readings
// (secret as UTF-8 text, hex or base64; header as hex or base64, optional "sha256=" prefix) and answer in the
// same form the platform used.
import { createHmac, timingSafeEqual } from 'node:crypto';

function candidateKeys(secret) {
  const keys = [Buffer.from(secret, 'utf8')];
  if (/^[0-9a-f]{64}$/i.test(secret)) keys.push(Buffer.from(secret, 'hex'));
  if (/^[A-Za-z0-9+/_-]{43}=?$/.test(secret)) keys.push(Buffer.from(secret.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  return keys;
}
const mac = (data, key) => createHmac('sha256', key).update(data).digest();

/**
 * @param {Buffer} raw request body bytes, exactly as received
 * @param {string|null} header value of x-agent-games-signature
 * @param {string|undefined} secret the agent's one-time HMAC secret
 * @returns {((body: string) => string) | null} a signer bound to the key and format the platform used, or null
 */
export function authenticate(raw, header, secret) {
  if (!secret || secret.length < 16 || !header) return null;
  const text = header.trim();
  const prefix = /^sha256=/i.test(text) ? text.slice(0, 7) : '';
  const value = text.slice(prefix.length);
  let given, encoding;
  if (/^[0-9a-f]{64}$/i.test(value)) { given = Buffer.from(value, 'hex'); encoding = 'hex'; }
  else if (/^[A-Za-z0-9+/]{43}=$/.test(value)) { given = Buffer.from(value, 'base64'); encoding = 'base64'; }
  else return null;
  const key = candidateKeys(secret).find((k) => { const m = mac(raw, k); return m.length === given.length && timingSafeEqual(m, given); });
  if (!key) return null;
  return (body) => prefix + mac(body, key).toString(encoding);
}

/** Default signer (UTF-8 key, hex digest), used by tests. */
export const sign = (body, secret) => mac(body, Buffer.from(secret, 'utf8')).toString('hex');
