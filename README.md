# Elenchos Duel

One agent for both live games of the zkVerify Agent Games, Steal the VFY and Proof Gatekeeper. Every answer it gives
comes with a Groth16 proof from the organisers' official circuit for that game.

- Live endpoint: `https://elenchos-duel.vercel.app/agent` (a GET returns health and the public commitment)
- Strategy: `10,0,0,0` in the circuit's policy family. It extracts 10 whenever the opponent has a balance, never
  fortifies, and holds only when there is nothing to take.

## Why 10,0,0,0

| Opponent's move this turn | Our gain over them with EXTRACT 10 |
|---|---|
| EXTRACT 10 | 0 |
| FORTIFY | +10 |
| HOLD | +20 |

The table shows how many more points we gain than the opponent in each case. Under both readings of the rules
(a shield that applies on the same turn, or on the next one), no legal policy beats it in a single match. We
checked this by brute force over all 87,120 legal threshold policies, and with a dynamic program over every
adaptive move sequence. Mirror matches end in a draw.

What's left to compete on is reliability: a valid proof on every turn and no missed deadline.

## How a turn works

1. Verify `x-agent-games-signature`, the HMAC-SHA256 over the raw body bytes, before anything is parsed.
2. Answer preflight (`agent-games.preflight.v1`) with `{ok:true, protocolVersion:"v1"}`.
3. For a turn:
   1. Choose the action exactly as the circuit's policy would.
   2. Build the witness and prove it with `snarkjs` in single-thread mode, using the official
      `vfy-policy.wasm` and `vfy-policy_final.zkey`.
   3. Verify the proof locally against the exported key.
   4. Return the proof with `publicInputsHash` and a UUID-shaped idempotency key.
4. Sign the exact bytes of the response. A retry gets back the identical body.

## Proof Gatekeeper

The same endpoint answers `agent-games.proof-gatekeeper.v1` tasks (`src/gate.js`).

- **Decide with code, not a model.** Five checks run in the order of the event's trap list: verification key
  substitution, balance below the minimum, expired condition, wrong recipient, amount over the cap. Values are
  compared as integers.
- **Prove the decision.** The official gatekeeper circuit proves APPROVE or REJECT, and the proof is verified locally
  against the official key before it is sent. The circuit derives the decision from the task's numbers, so a wrong
  decision cannot be proven.
- **Stop replays.** Each proof reference is written once to a private Vercel Blob store (create-if-absent). A
  reference that an earlier task already used is rejected as `PROOF_REUSED`, and a retry of the same task gets the
  same answer. No valid circuit proof exists for this case, so the answer ships without one.
- **Fail closed.** If the replay store can't be reached, or a proof doesn't verify, the agent never approves.

## Run it

```bash
npm install
npm test                      # 20 tests, real proofs with the official artifacts, no mocks
node scripts/commitment.js    # creates .env.strategy (salt never printed); prints the public commitment
```

The deployment needs four environment variables: `AGENT_GAMES_HMAC_SECRET`, `STRATEGY_SALT`,
`STRATEGY_COMMITMENT` and `BLOB_READ_WRITE_TOKEN` (the Gatekeeper replay store). The repository contains no secrets.

The circuit artifacts in `artifacts/` were downloaded unchanged from agentgames.zkverify.io. Their checksums are
in `artifacts/README.md`.

MIT licensed. Part of [Elenchos](https://github.com/nickthelegend), a red team for code that trusts zkVerify proofs.
