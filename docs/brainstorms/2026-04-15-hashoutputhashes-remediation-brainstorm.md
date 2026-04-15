# `hashOutputHashes` Remediation — Brainstorm

**Date:** 2026-04-15
**Status:** Brainstorm complete — ready for `/workflows:plan`
**Predecessor:** [v1 brainstorm 2026-04-14](./2026-04-14-radiant-ledger-app-v1-brainstorm.md) + [v1 plan](../plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md) + [INVESTIGATION.md Phase 1 section](../../INVESTIGATION.md)

---

## What We're Building

Extend the Radiant Ledger app (already live on device through Phase 1) to compute the `hashOutputHashes` field that Radiant inserts into its signature preimage. This is the single missing piece blocking successful signed mainnet RXD transactions. Plus targeted hardening discovered during the research pass.

Scope is intentionally tight: **fix the one preimage field, add one canonical-form output check, build a Python oracle for pre-merge verification.** v1 remains plain P2PKH only. Glyph / NFT signing stays deferred to v2.

**Out of scope for this brainstorm:**
- Glyph push-ref scanning (v2)
- Speculos / Ragger emulator test harness (v2+)
- WebHID, additional devices, official Ledger review (v3+)
- Dependency cleanup (btchip-python setup.py, Electron-Wallet vendoring) — separate pre-release track

---

## Why This Approach

**Strategy A: device independently computes `hashOutputHashes`.** As each output's scriptPubKey bytes stream in via APDU, run a parallel SHA256 context to compute the per-output summary, feed those into an accumulator, finalize at output-stream-end, inject into preimage. Zero host-trust added — the device derives `hashOutputHashes` from the same bytes it already trust-derives `hashOutputs` from. Rejected alternative (Strategy B, host pre-computes) creates a latent host-commitment channel that's self-correcting today but becomes a trust-model violation if Radiant consensus ever evolves ref-binding semantics.

**Canonical P2PKH enforcement for v1 outputs.** Device rejects any output whose scriptPubKey is not the exact 25-byte form `OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG`. Makes `totalRefs=0 ∧ refsHash=0x00…00` a **proven invariant** rather than a host-trusting assumption. Catches Glyph-bearing output construction attempts in v1 — without this check, such outputs would get rejected by the Radiant network post-sign, which is safe-failure but wastes device time and RXD dust. ~15-line check.

**Python oracle first, then C.** Write a small Python function that reconstructs Radiant's preimage + sighash from unsigned-tx-bytes + prevout-data exactly as `radiant-node/src/script/interpreter.cpp:2596-2658` does. Test against known mainnet txs (known sig + pubkey → verify). Then implement the C diff and compare device signatures to oracle-computed sighashes. Half-day of oracle work prevents further sign-then-reject iteration loops.

**The comparison protocol** (since Ledger apps return signatures, not preimage bytes):

1. Oracle takes unsigned tx hex + per-input `{scriptPubKey, amount}` → outputs the 32-byte Radiant sighash for each input.
2. Device signs the same inputs → returns DER signatures.
3. Test harness verifies each signature against `(oracle_sighash, device_pubkey)` using a local `secp256k1` check.
4. If verification passes, the device signed what the oracle expected. If it fails, preimage divergence — fall back to raw APDU tracing.

The harness treats the oracle itself as trusted only after it has been validated against at least one mainnet-confirmed tx with known `(signature, pubkey)` — see Open Questions #5 on test-vector sourcing.

**Keep the runtime-`if` pattern, not `#ifdef`.** Research confirms lib-app-bitcoin's house style. `if (COIN_KIND == COIN_KIND_RADIANT)` gets constant-folded by GCC when `-DCOIN_KIND=COIN_KIND_RADIANT` (enum constant, not string).

---

## v1 Output-Type Limitation (user-visible)

Strict canonical-P2PKH enforcement on outputs means v1 users **cannot**:

- Send RXD to P2SH addresses (addresses starting with `3…`)
- Include OP_RETURN memos in sends
- Send to any non-standard output script

These are niche cases on Radiant — the vast majority of RXD addresses are P2PKH (`1…`). But worth calling out explicitly so users aren't surprised. Users who need P2SH sends or memo outputs in the interim should use the software Electron Radiant wallet.

v2 relaxes this check — either to a whitelist of standard forms (`{P2PKH, P2SH, small-OP_RETURN}`) or to a push-ref-aware opcode scan that allows any script lacking `OP_PUSHINPUTREF*` bytes.

---

## Key Decisions

| Decision | Choice | Why |
|---|---|---|
| **Compute strategy** | A — device computes from stream | Strategy B creates latent host-commitment channel (security review) |
| **Output validation** | Enforce canonical P2PKH in v1 | Makes `totalRefs=0, refsHash=zero` a proven invariant; closes latent ref-mismatch footgun; v2 relaxes |
| **Script length bound** | Reject scriptPubKey > MAX_SCRIPT_SIZE (10KB) | Prevents APDU buffer over-read; cheap defense |
| **Test harness** | Python oracle first, then C diff | Half-day of oracle = no more mainnet sign-reject iteration; mainnet-example-driven |
| **Preimage location** | Extend `transaction.c:721-732` (NOT `hash_sign.c`) | Research surprise: `hash_sign.c` only finalizes; preimage is in `transaction.c` |
| **Context struct** | New `hashedOutputHashes[32]` in `segwit_cache_s`; consider sharing RAM for `hashOutputHashesCtx` with the dead `segwit.hash.hashPrevouts` if space is tight | Research finding, not a committed design; finalize in plan |
| **SIGHASH gate** | Already correct (`sighashType != 0x41` with exact equality) | No change needed — double-checked against security review #1 |
| **Fork-id** | Keep COIN_FORKID=0 (matches Radiant network) | `hashOutputHashes` length/bytes provide domain separation from BCH despite identical fork-id value |
| **v2 bridge (push-refs)** | Add scaffolding but no-op for v1 | Canonical P2PKH check makes this a short-circuit; v2 replaces with real scan |

---

## Network Constants (verified during research)

| Property | Value | Same as BCH? |
|---|---|---|
| Sighash type byte | `0x41` (`SIGHASH_ALL \| SIGHASH_FORKID`) | ✅ yes |
| `COIN_FORKID` | 0 | ✅ yes |
| Preimage field order | `version, hashPrevouts, hashSequence, prevout, scriptCode, amount, nSequence, `**`hashOutputHashes`**`, hashOutputs, locktime, sighashType` | ❌ **new field** |
| Signature format | ECDSA DER (~70-72B) or Schnorr (64B) | ✅ yes |
| Tx serialization on-wire | `nVersion \|\| vin \|\| vout \|\| nLockTime` | ✅ yes (new opcodes only affect script semantics, not tx-wire format) |
| Tx version accepted | 1 or 2 | ✅ yes |
| `COINBASE_MATURITY` | 100 blocks | ✅ yes |
| Dust threshold | 1 satoshi | ⚠️ more permissive (BCH: 546) |
| New sighash flags | none | ✅ yes |
| New opcodes | 0xBD-0xDF (refs, state-separator) | ❌ — but don't affect P2PKH signing |

Bottom line: Radiant is byte-compatible with BCH at every layer **except** the inserted `hashOutputHashes` preimage field. That's the whole delta.

---

## Open Questions

1. **Schnorr signature support**. Lib-app-bitcoin emits ECDSA DER. Radiant accepts both (verified via `interpreter.cpp:2681-2689`). Schnorr would be shorter/cheaper but requires device-side Schnorr-BCH impl. **Deferred to post-v1** — ECDSA works and is what we're emitting.

2. **`SIGHASH_SINGLE` path**. Radiant's SINGLE construction for `hashOutputHashes` differs from the ALL/NONE construction (summary blob vs serialized output — see `interpreter.cpp:2623-2632`). Our v1 rejects everything except `0x41` so this is moot. If a future Electron-Wallet flow ever needs SINGLE (it doesn't today), we re-evaluate.

3. **`ANYONECANPAY`**. Same story — gate rejects. Re-evaluate if needed.

4. **Dependency cleanup for shipping**. btchip-python's broken setup.py and Electron-Wallet's unvendored dependency tree are real v1-release blockers but separate from this sighash work. **Track as parallel workstream**, not part of this brainstorm.

5. **Test vector sourcing**. Oracle needs 1–3 known-good mainnet-confirmed RXD txs with full tx hex + per-input prevout `{scriptPubKey, amount}` to self-validate against pre-computed `(signature, pubkey)` pairs. Candidate sources: (a) Radiant block explorers that expose vin scriptSig + prevout via JSON API (`radiantexplorer.com/api/tx/<txid>` may work — needs testing), (b) the incoming `3521c21…` tx on our dev wallet (has scriptSig + can look up prevout `6e57ee8fb9…`), (c) direct `getrawtransaction` from the `radiant-mainnet` Docker container on FlipperHub. Decide in plan phase which source is most reliable.

6. **Community tester build matrix with real Python oracle**. Once oracle exists, Phase 3 community testing can include "tester runs Python oracle + compares against their device-signed sigs." Richer than just "txid confirmed." Noted for plan phase.

---

## Definition of Done (this remediation workstream)

A Nano S Plus running the Radiant Ledger app can:

1. Compute `hashOutputHashes` on-device from streaming output data, bit-identical to what `radiant-node` computes server-side for the same tx
2. Reject any output whose scriptPubKey is not canonical 25-byte P2PKH (SW_INCORRECT_DATA)
3. Reject any output whose scriptPubKey exceeds MAX_SCRIPT_SIZE
4. Sign a 1-in/2-out Radiant tx that Radiant mainnet **accepts** (opposite of our current "script execution error" outcome)
5. Continue to pass all Phase 1 tests (path-lock, address derivation, P2_CASHADDR rejection, bitcoin_cash regression build)

Plus supporting infrastructure:

6. Python oracle in `scripts/radiant-preimage-oracle.py` that reconstructs any Radiant sighash from unsigned tx + prevout data
7. Bit-compare test harness that runs oracle output vs. device output for a known test vector
8. Updated `INVESTIGATION.md` with the fix arc + final mainnet txid

---

## v2 Tracking (items surfaced during this brainstorm)

All work items v2 must address, capturing them here so they don't get lost. Also lives as TODOs in the plan; duplicated here as the authoritative v2-intake list from this remediation cycle.

### v2 is the right time for

- **Real `GetPushRefs` implementation** — device-side opcode-aware scan of output scriptPubKeys for `OP_PUSHINPUTREF` (0xD0), `OP_REQUIREINPUTREF` (0xD1), `OP_DISALLOWPUSHINPUTREF` (0xD2), `OP_DISALLOWPUSHINPUTREFSIBLING` (0xD3), `OP_PUSHINPUTREFSINGLETON` (0xD8). Extracts 36-byte ref ids, sorts lexicographically, concatenates, SHA256s → `refsHash`. Replaces v1's canonical-P2PKH-and-short-circuit-to-zero.
- **Relax canonical-P2PKH output check** — once real `GetPushRefs` exists, device can accept any standard script (P2PKH, P2SH, OP_RETURN, Glyph commit/reveal scripts). UX win: sends to P2SH addresses and memo outputs start working.
- **SIGHASH_SINGLE preimage path** — Radiant's SINGLE construction for `hashOutputHashes` differs from ALL/NONE (uses `writeOutputDataSummaryVector` against the single matched output, not a full per-output iteration — see `radiant-node/src/script/interpreter.cpp:2623-2632`). v1 gate rejects everything except `SIGHASH_ALL|FORKID`, so this is moot until v2 needs it. When needed, adds ~30 lines.
- **SIGHASH_ANYONECANPAY** — requires zeroing `hashPrevouts`/`hashSequence`, signing for one-input-at-a-time. Security-sensitive (allows post-sign input substitution). Gate in v1, design properly in v2 when/if a flow demands it.
- **Schnorr signature emission** — Radiant accepts both ECDSA DER (~70-72B) and Schnorr (64B). Schnorr is cheaper fee-wise. Lib-app-bitcoin only emits ECDSA today. Add Schnorr support when implementation cost is justified by actual v2 tx volumes.
- **Speculos / Ragger emulator test harness** — automated per-commit tests against emulated device in CI. Heavy lift (~1-2 days) but buys regression safety across every subsequent change. v1 gets by with hardware-in-the-loop + Python oracle; v2 warrants the CI investment.
- **Device UX for Glyph-specific signing** — when a user signs a tx that spends or creates a Glyph, what does the device display? Token name? Ref ID? A generic "contains push-refs" warning? Design work, not just code.
- **Multi-device coverage** — Nano X (BLE), Stax / Flex (NBGL UI rewrite). Each adds build matrix + UI porting work.

### v1 infrastructure deliberately positioned for v2

- `hashOutputHashes` accumulator **is already correct for the Glyph case** — v2 only replaces the `totalRefs` and `refsHash` computation with real opcode-scanning output. The rest of the preimage assembly stays put.
- Canonical-P2PKH output check in v1 becomes `if (COIN_KIND_FEATURE & GLYPH_ENABLED) allow_ref_outputs()` in v2.
- Python oracle handles `totalRefs>0` and non-zero `refsHash` cases from day one (required to validate oracle against known Glyph mainnet txs). v1 just happens to only exercise the zero-ref path.
- Runtime `if (COIN_KIND == COIN_KIND_RADIANT)` pattern scales cleanly — each v2 feature adds a new runtime branch inside the same gate, no architectural rework.

### Confirmed NOT needing v2 work (from research)

- ECDSA signature path unchanged (Radiant verifies DER sigs identically to BCH)
- Wire tx serialization unchanged (new opcodes are script-level only)
- Nothing else in Radiant consensus diverges from BCH at the signing layer — the research sweep confirmed `hashOutputHashes` is the only preimage delta, full stop

---

## Next Step

Run `/workflows:plan` against this brainstorm to produce the concrete implementation plan: Python oracle spec, C diff map with exact insertion points, test-vector sourcing, incremental sideload + compare protocol, mainnet final-test strategy.

## Research artifacts (for plan phase)

- Radiant protocol deep-dive: see agent report 1 (file paths cached at `/tmp/interpreter.cpp`, `/tmp/transaction.h`, etc.)
- lib-app-bitcoin extension points: see agent report 2 (cached at `/tmp/lab/{context.h,transaction.c,hash_input_finalize_full.c,...}`)
- Reference implementations: Zcash (ZIP-244) is the closest precedent for tree-of-subtree-digests preimages
- Security threat model: see agent report 4 findings 1-5
