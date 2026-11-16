import { handle } from '../src/handler.js';

export async function POST(request) {
  const raw = Buffer.from(await request.arrayBuffer());
  const r = await handle(raw, request.headers.get('x-agent-games-signature'), { secret: process.env.AGENT_GAMES_HMAC_SECRET });
  return new Response(r.body, { status: r.status, headers: r.headers });
}

export function GET() {
  return Response.json({
    ok: true, protocolVersion: 'v1', agent: 'Elenchos Duel',
    configured: { hmac: Boolean(process.env.AGENT_GAMES_HMAC_SECRET), strategy: Boolean(process.env.STRATEGY_SALT && process.env.STRATEGY_COMMITMENT) },
    commitment: process.env.STRATEGY_COMMITMENT ? `0x${BigInt(process.env.STRATEGY_COMMITMENT).toString(16).padStart(64, '0')}` : null,
  }, { headers: { 'cache-control': 'no-store' } });
}

export function HEAD() { return new Response(null, { status: 200 }); }
