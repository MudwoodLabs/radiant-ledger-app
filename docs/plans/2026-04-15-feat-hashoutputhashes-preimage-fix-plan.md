---
title: "feat: hashOutputHashes preimage fix (Radiant Ledger app v1 remediation)"
type: feat
date: 2026-04-15
parent_plan: docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md
brainstorm: docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md
---

# `hashOutputHashes` Preimage Fix — Implementation Plan

## Overview

Extend the Radiant Ledger app (`Zyrtnin-org/app-radiant`, currently at `v0.0.2-bootstrap`) to compute the `hashOutputHashes` field that Radiant consensus requires in every signature preimage. This is the single issue blocking successful mainnet RXD transactions from the Ledger. Everything else on the happy path (build reproducibility, address derivation, path-lock defense, plugin integration, wallet creation, balance discovery) is already verified working on real hardware.

Scope is deliberately narrow: fix the one preimage field + targeted hardening from the security review, ship Python oracle first for verifiable correctness, keep v1 plain P2PKH only. Glyph / NFT signing remains deferred to v2.

**Origin**: Phase 1 walking-skeleton test on 2026-04-15 signed a 1-in/2-out RXD spend that Radiant mainnet rejected with "script execution error." Root cause traced to [`radiant-node/src/script/interpreter.cpp:2636-2650`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2636) inserting a new 32-byte `hashOutputHashes` field into the preimage that our BCH-family code path doesn't produce. Walking-skeleton strategy caught this at 1 RXD of risk, pre-release.

---

## Problem Statement

Radiant's signature preimage is not byte-identical to Bitcoin Cash despite the sighash type byte (`0x41`) matching. Specifically:

```
BCH preimage:      version | hashPrevouts | hashSequence | outpoint | scriptCode | amount | nSequence | hashOutputs        | locktime | sighashType
Radiant preimage:  version | hashPrevouts | hashSequence | outpoint | scriptCode | amount | nSequence | hashOutputHashes   | hashOutputs | locktime | sighashType
                                                                                                          ^^^^^^^^^^^^^^^^^^^
                                                                                                          new 32-byte field
```

`hashOutputHashes` is the double-SHA256 of concatenated per-output 76-byte summaries, where each summary is:

```
nValue               (u64 LE,  8 bytes)
sha256d(scriptPubKey) (        32 bytes)  ← double SHA256 of the locking script
totalRefs            (u32 LE,  4 bytes)   ← 0 for non-Glyph outputs
refsHash             (         32 bytes)  ← zeros for non-Glyph outputs
```

Our Ledger Radiant app currently uses the stock BCH preimage construction from `lib-app-bitcoin`, which doesn't compute or emit this field. The device signs one hash; Radiant nodes verify a different hash; `OP_CHECKSIG` fails.

Until this is fixed, no Ledger-signed RXD transaction can successfully broadcast on Radiant mainnet. One RXD is currently stuck at `1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc` awaiting the remediated app for its first successful spend.

---

## Proposed Solution

**Strategy A**: the device independently computes `hashOutputHashes` from the same streaming output bytes it already processes for `hashOutputs`. No host trust added — the new field is derived from data the device was already seeing and hashing. Rejected Strategy B (host pre-computes) creates a latent host-commitment channel, per the security review.

**Canonical P2PKH enforcement** for v1 outputs. Device rejects any output whose scriptPubKey is not exactly 25 bytes of the form `OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG`. This makes `totalRefs=0 ∧ refsHash=0x00…00` a proven invariant rather than a host-trusting assumption. Users cannot send to P2SH (`3…`) addresses or add OP_RETURN memos in v1 — documented limitation that v2 relaxes.

**Python oracle first, then C.** Port [`radiantjs/lib/transaction/sighash.js:171-237`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L171) to Python. Self-validate via three independent checks (per SpecFlow finding #7) before trusting the oracle as our device-verification truth. Then implement C and compare device signatures to oracle-computed sighashes via local `secp256k1.verify`.

---

## Technical Approach

### Architecture

```
┌──────────────────────┐       ┌──────────────────────┐       ┌──────────────────────┐
│ Python oracle         │ ───▶ │ secp256k1.verify      │ ◀─── │ Ledger Radiant app    │
│  - ports radiantjs    │       │  (oracle_sighash,     │       │  - computes new       │
│    sighash.js         │       │   device_signature,   │       │    hashOutputHashes   │
│  - self-validated     │       │   device_pubkey)      │       │  - inserts in         │
│    3 ways             │       │  → true if device     │       │    preimage before    │
│  - produces sighash   │       │    signed what oracle │       │    hashOutputs        │
│    for each input     │       │    expected           │       │  - rejects non-P2PKH  │
└──────────────────────┘       └──────────────────────┘       │    outputs            │
                                                                └──────────────────────┘
```

### Full preimage construction (authoritative reference)

From [radiantjs sighash.js](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js) — direct port target:

```javascript
// lib/transaction/sighash.js:91-128 — GetHashOutputHashes
// Equivalent Python we need to write:
//
// for output in tx.outputs:
//     writer += u64_le(output.satoshis)
//     writer += sha256d(output.script_buffer)        # DOUBLE sha256
//     push_refs = get_push_refs(output.script_buffer)  # v1: always empty
//     writer += u32_le(len(push_refs))                # v1: 0
//     writer += sorted_hash_refs(push_refs) if push_refs else zero32
// return sha256d(writer)                              # DOUBLE sha256

// lib/transaction/sighash.js:171-237 — sighashPreimageForForkId
// Equivalent Python:
//
// preimage = int32_le(tx.version)
//          + hashPrevouts
//          + hashSequence
//          + reverse(input.prev_tx_id) + u32_le(input.output_index)
//          + varint(len(subscript)) + subscript
//          + u64_le(input.satoshis)
//          + u32_le(input.sequence_number)
//          + hashOutputHashes                         # <-- the new field
//          + hashOutputs
//          + u32_le(tx.locktime)
//          + u32_le(sighash_type)  # 0x41 = ALL|FORKID
// sighash = sha256d(preimage)
```

Key constants (verified in radiantjs):
- `Hash.sha256sha256` = double SHA256 everywhere (same as BCH convention)
- For v1 plain P2PKH: `push_refs` always empty, `len(push_refs)=0`, `refsHash=0x00…00 * 32`

### C diff map — exact insertion points

Research (4 parallel agents, brainstorm phase) traced the lib-app-bitcoin output-streaming flow. The BIP143 preimage lives in `transaction.c`, NOT `hash_sign.c` (surprise — `hash_sign.c` only finalizes).

All changes are in `Zyrtnin-org/lib-app-bitcoin@radiant-v1` (our submodule fork).

#### 1. `context.h` — cache field + parallel hasher

```c
// context.h — segwit_cache_s (currently ~line 83)
struct segwit_cache_s {
  unsigned char hashedPrevouts[32];
  unsigned char hashedSequence[32];
  unsigned char hashedOutputs[32];
  unsigned char hashedOutputHashes[32];   // NEW — free inside existing union (dominated by blake2b)
};

// context.h — struct context_s
struct context_s {
  // ... existing fields ...
  cx_sha256_t hashOutputHashesCtx;         // NEW — running accumulator for hashOutputHashes
  cx_sha256_t currentOutputScriptCtx;      // NEW — per-output inner sha256d of scriptPubKey
  uint32_t    currentOutputBytesRemaining; // NEW — tracks APDU-chunk-spanning scripts
  uint64_t    currentOutputSatoshis;       // NEW — captured when amount bytes arrive
};
```

Research finding: `hashOutputHashesCtx` and `currentOutputScriptCtx` can potentially share RAM with `segwit.hash.hashPrevouts` (dead by output-streaming time). **Finalize RAM layout in Phase 1.5.3 Task 0** after a quick on-device sizing check; not a blocking design decision. Default to peer struct members unless the build errors on size.

#### 2. `handler/hash_input_start.c` — initialize Radiant-only hashers

Existing code initializes various hashers based on COIN_KIND. Add:

```c
if (COIN_KIND == COIN_KIND_RADIANT) {
    cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
}
// currentOutputScriptCtx is initialized per-output, not once
```

#### 3. `handler/hash_input_finalize_full.c` — per-output hashing

This is the meaty change. Current code (around line 334) streams output chunks straight into `transactionHashFull.sha256` to produce `hashedOutputs`. We add a parallel per-output streaming pipe.

Output wire format: `amount (8 bytes LE) | script_len (varint) | script_bytes`. Per SpecFlow finding #1, scriptPubKey can span multiple APDU chunks, so we track state:

```c
// Pseudocode for the added branch (actual code lives in handle_output_state)
if (COIN_KIND == COIN_KIND_RADIANT) {
    for each byte consumed from this APDU chunk:
        switch (outputParsingState) {
            case PARSING_AMOUNT:
                accumulate 8 bytes → currentOutputSatoshis (LE);
                on complete: emit 8 bytes into hashOutputHashesCtx (LE encoding of satoshis);
                             transition to PARSING_SCRIPT_LEN;
            case PARSING_SCRIPT_LEN:
                read varint;
                on complete: if (script_len != 25) return SW_INCORRECT_DATA;  // canonical P2PKH gate
                             cx_sha256_init_no_throw(&currentOutputScriptCtx);
                             currentOutputBytesRemaining = script_len;
                             transition to PARSING_SCRIPT;
            case PARSING_SCRIPT:
                hash bytes into currentOutputScriptCtx;
                decrement currentOutputBytesRemaining;
                on 0 remaining:
                    // Double SHA256 of the scriptPubKey (Radiant uses sha256d per radiantjs).
                    // Follow the same init/update/CX_LAST pattern lib-app-bitcoin already uses
                    // for other sha256d computations (e.g., transactionHashFull finalization).
                    uint8_t digest1[32];
                    cx_hash_no_throw(&currentOutputScriptCtx.header, CX_LAST, NULL, 0, digest1, 32);
                    cx_sha256_t finalCtx;
                    cx_sha256_init_no_throw(&finalCtx);
                    uint8_t scriptHash[32];  // sha256d result
                    cx_hash_no_throw(&finalCtx.header, CX_LAST, digest1, 32, scriptHash, 32);
                    // Now emit the 4-field summary:
                    emit scriptHash (32 bytes) into hashOutputHashesCtx;
                    emit 0x00 0x00 0x00 0x00 (4-byte totalRefs=0) into hashOutputHashesCtx;
                    emit 32 zero bytes (refsHash) into hashOutputHashesCtx;
                    // Check if this was the canonical P2PKH (last-byte check — should be OP_CHECKSIG 0xAC)
                    transition back to PARSING_AMOUNT for next output;
        }
}
```

**Also**: add an explicit canonical-P2PKH shape check — not just length=25, but the full pattern `76 a9 14 xx*20 88 ac`. Done after we have the full 25 bytes assembled (a small buffer is fine since size is fixed).

Finalization of `hashOutputHashesCtx` → `segwit.cache.hashedOutputHashes` happens at the same point `hashedOutputs` is finalized (around line 407-423). Double-SHA256 per the radiantjs reference.

#### 4. `transaction.c:721-732` — preimage insertion

```c
// transaction.c — existing code (around line 721):
if (context.usingSegwit && context.segwitParsedOnce) {
  if (!context.usingOverwinter) {
    // NEW — append hashedOutputHashes FIRST (before hashedOutputs) for Radiant
    if (COIN_KIND == COIN_KIND_RADIANT) {
      PRINTF("RADIANT hashedOutputHashes\n%.*H\n",
             sizeof(context.segwit.cache.hashedOutputHashes),
             context.segwit.cache.hashedOutputHashes);
      if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                           context.segwit.cache.hashedOutputHashes,
                           sizeof(context.segwit.cache.hashedOutputHashes),
                           NULL, 0)) {
        goto fail;
      }
    }
    // Existing code continues:
    PRINTF("SEGWIT hashedOutputs\n%.*H\n", ...);
    if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                         context.segwit.cache.hashedOutputs, 32, NULL, 0)) {
      goto fail;
    }
  }
  context.transactionContext.transactionState = TRANSACTION_SIGN_READY;
}
```

#### 5. `hash_input_finalize_full_reset` — state teardown

Per SpecFlow findings #4, #6: mid-stream interrupt, user reject, power loss. Extend the existing reset function to clear the new state:

```c
void hash_input_finalize_full_reset(void) {
  context.currentOutputOffset = 0;
  context.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;  // always reset
  memset(context.totalOutputAmount, 0, sizeof(context.totalOutputAmount));
  context.changeOutputFound = 0;
  // NEW for Radiant — Security H2: reset ALL new state fields unconditionally,
  // including currentOutputScriptCtx (re-init it here, not only when entering
  // PARSING_SCRIPT). A cancel during PARSING_SCRIPT leaves the ctx in a
  // half-consumed state otherwise, and the next sign could read stale state.
  if (COIN_KIND == COIN_KIND_RADIANT) {
    cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
    cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
    context.currentOutputBytesRemaining = 0;
    context.currentOutputSatoshis = 0;
  }
}
```

**Cancel-path audit task** (Phase 1.5.3 step 6): trace every `return` or `goto` in `hash_input_finalize_full.c` that could exit mid-output-stream (error returns, user-reject via UI confirm flow, USB disconnect). Confirm each either calls `hash_input_finalize_full_reset()` or cannot reach the next `hash_input_start` without reset being called somewhere else in the state machine. Document findings inline in the C diff's commit message.

#### 6. Runtime assertion on COIN_KIND gating (scoped)

One assertion at the entry point of the new hashOutputHashes finalization function. Not sprawled per-write — that adds style drift from upstream `lib-app-bitcoin` without load-bearing safety value (CI SHA256 diff of `bitcoin_cash` is the real regression control).

```c
// At the top of the function that finalizes hashedOutputHashes:
static int finalize_radiant_output_hashes(void) {
    if (COIN_KIND != COIN_KIND_RADIANT) {
        return SW_TECHNICAL_PROBLEM;  // entry-point-only assertion — inline documentation
                                      // that this function is Radiant-only, plus a safety net
                                      // if a future refactor accidentally calls it under BCH.
    }
    // ... finalization logic ...
}
```

Rationale for entry-point-only: catches the worst-case scenario (function ever called outside Radiant context) without style inconsistency. Per-write assertions are redundant with the outer `if (COIN_KIND == COIN_KIND_RADIANT)` guards they'd be nested inside.

### Python oracle spec

File: `scripts/radiant-preimage-oracle.py`

```python
def compute_radiant_sighash(
    tx_hex: str,                        # unsigned tx, raw hex
    input_index: int,                   # which input to compute sighash for
    prevout_script: bytes,              # scriptPubKey of the prev output being spent
    prevout_amount_sats: int,           # amount of the prev output (satoshis)
    sighash_type: int = 0x41,           # SIGHASH_ALL | SIGHASH_FORKID
) -> bytes:                              # returns 32-byte sighash digest
    ...
```

Direct port of [`radiantjs sighash.js:171-237`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L171):
- Reuses `hashlib.sha256` (stdlib) for double-SHA256
- Reuses `ecdsa` / `coincurve` for `secp256k1.verify` (already in Electron-Wallet venv)
- For v1, the `get_push_refs(script)` helper always returns `[]` (test that this matches what radiant-node's `GetPushRefs` returns for P2PKH inputs — should confirm with at least one mainnet example where we can compare radiant-node RPC output to our oracle)

---

### Implementation Phases

#### Phase 1.5.0 — Pre-implementation checklist (~30 min)

Before any code is written, confirm these spec details by reading the canonical sources directly. A wrong assumption here wastes downstream phases.

- [x] Confirm `totalRefs` wire format in `radiant-node/src/primitives/transaction.h:475-540` is **u32 little-endian (4 bytes)**, not a varint. One wrong line of Python hides a bug that all three validation checks could miss if vectors don't vary output count. ✅ Verified: `uint32_t totalRefs`, u32 LE via CHashWriter + `writer.writeUInt32LE`
- [x] Confirm tx-version handling: radiantjs `sighash.js` does not branch on version 1 vs 2. Port should not either. Document the assumption in the oracle header. ✅ Verified: both radiantjs and radiant-node emit `transaction.version` directly, no version-dependent branching
- [x] Confirm the per-output summary byte-layout ordering: `nValue(8) + sha256d(scriptPubKey)(32) + totalRefs(4) + refsHash(32)` = 76 bytes, in this exact order. ✅ Verified: two-source agreement between `radiant-node/src/primitives/transaction.h:489-492` and `radiantjs sighash.js:99-123`
- [x] Confirm: the final `hashOutputHashes` is `sha256d(concatenated summaries)`, double-SHA256 (per `radiantjs/lib/transaction/sighash.js:127`). ✅ Verified: `Hash.sha256sha256(buf)` in radiantjs, `CHashWriter.GetHash()` (double by convention) in radiant-node
- [x] Confirm: the SIGHASH gate in our existing code is exact-equality `!= 0x41` (not bitmask). Triple-check the operator before Phase 1.5.3. ✅ Verified: `lib-app-bitcoin/handler/hash_sign.c:127` uses `!= (SIGHASH_ALL | SIGHASH_FORKID)` — exact-equality rejection

All five checkboxes green → proceed. Any red → re-read source before coding.

---

#### Phase 1.5.1 — Python oracle + triple self-validation (~1 day)

Per SpecFlow finding #7: validate the oracle three ways before trusting it, not just against one tx.

**Tasks:**

1. Write `scripts/radiant-preimage-oracle.py` — port from radiantjs sighash.js
2. Write `scripts/oracle-self-validate.py` — runs the three checks below
3. **Validation check A** — reconstruct sighash for a known mainnet-confirmed RXD tx; verify that the tx's on-chain signature validates against the oracle-computed sighash + known public key via `secp256k1.verify`. Target tx: candidates surfaced in brainstorm Open Question #2 (the source-wallet tx that funded us at `3521c21…` is a candidate).
4. **Validation check B** — hand-compute preimage bytes against the spec. Cover **both** shapes:
   - **B.1**: one P2PKH-output fixture, matching the device's signing scope.
   - **B.2**: at least one non-P2PKH-output fixture (e.g., a real mainnet RXD tx with a P2SH or OP_RETURN output). Oracle-only — device will correctly reject signing these. Rationale: closes Security H1 (triple-validation monoculture gap). All else equal, the `sha256d(scriptPubKey)` varint-length-parsing and nValue-endianness paths only get exercised against a single script length (25 bytes) if we stay P2PKH-only. A non-P2PKH fixture exercises the varying-script-length path in the oracle itself.
   - For each fixture: write expected preimage hex in a comment or fixture file. Diff against oracle output byte-for-byte.
5. **Validation check C** — independent-signer agreement. Use FlipperHub's existing PHP flow (`blockchain_rpc.php`), which calls `radiant-cli signrawtransaction` on the Docker `radiant-mainnet` node. Feed the same unsigned tx + prevout data through that path, get back a signed tx. Extract `(signature, pubkey)` from the signed tx's scriptSig. Verify against the oracle's computed sighash via `secp256k1.verify`.

   **What this proves**: our oracle's sighash matches what a real Radiant node produces signatures against.
   **What this does NOT prove**: oracle's preimage bytes match the node's preimage bytes (node doesn't expose them).
   Checks A + B cover byte-level correctness; check C covers "a second end-to-end implementation agrees on the signed digest."
6. Python oracle commits to `Zyrtnin-org/radiant-ledger-app` under `scripts/`.

**Deliverables:**

- [x] `scripts/radiant_preimage_oracle.py` with doctest-style self-test for encoding/hash helpers
- [x] `scripts/oracle_self_validate.py` executes all three checks and exits 0 only if all pass — **2026-04-15: PASS (exit 0)**
- [x] Check A: mainnet tx `3521c21…` input 0 → oracle sighash `c8554a48…` verifies against published signature
- [x] Check B.1: P2PKH hand-computed preimage byte-matches oracle (214B; sighash `f76d55ea…`)
- [x] Check B.2: OP_RETURN + P2PKH hand-computed preimage byte-matches oracle (closes Security H1; sighash `a63585c1…`)
- [x] Check C: mainnet tx `841c66a…` (100-in, different signer) — 4/4 sampled inputs verify against oracle

**Why first:** prevents another sign-then-reject mainnet iteration. If the oracle is wrong, we find out without costing RXD.

---

#### Phase 1.5.2 — Golden test vectors (~0.5 day)

(Formerly 1.5.2b — the standalone "RAM budget" phase was absorbed into Phase 1.5.3 Task 0 as a ~15-min check. Research already indicates comfortable slack; not worth a standalone half-day phase.)

Per SpecFlow finding #8: fill the gap between oracle existing and C implementation. Produce static byte-level fixtures that both oracle and C must match.

**Source of test vectors**: direct `getrawtransaction <txid>` + `getrawtransaction <vin[i].txid> true` calls against the FlipperHub `radiant-mainnet` Docker container. Rationale: we control the node, can query it authoritatively over SSH, and can pick real mainnet-confirmed txs of each shape. Block-explorer APIs are a fallback only if the Docker node is unreachable. All vectors are real confirmed RXD transactions — not synthesized — so each one is a self-contained proof that oracle output matches mainnet-reality.

**Tasks:**

1. Pick 4 representative tx shapes (each sourced from a real confirmed RXD tx):
   - 1-in / 1-out (sweep)
   - 1-in / 2-out (with change — matches our stuck 1 RXD test)
   - 3-in / 2-out (multi-input)
   - 10-in / 1-out consolidation — exercises per-output-hasher lifecycle repeatedly (init/stream/finalize/accumulate × 10). Script length is fixed-P2PKH so input count is the only variable; 10-in gives sufficient signal at lower curation cost than 30-in.
2. For each: capture unsigned tx hex + prevout data + expected `hashOutputHashes` + expected preimage + expected sighash
3. Write `scripts/fixtures/preimage-vectors.json` with all four
4. Oracle test: oracle computes sighash for each vector, compare against expected
5. These same vectors will drive the Phase 1.5.4 device compare harness

**Deliverables:**

- [x] `scripts/fixtures/preimage-vectors.json` with 4 test vectors covering all target shapes — **2026-04-15: built via `build_fixtures.py`**:
  - `sweep_1in_1out` (txid `48bcbdef…`) — 1 input verified
  - `standard_1in_2out` (txid `3521c21…` our funding tx) — 1 input verified
  - `multi_3in_2out` (txid `266fdbec…`) — 3 inputs verified
  - `consolidation_11in_1out` (txid `b4debc15…`) — 11 inputs verified
  - **Total: 16 oracle-computed sighashes, every one verified against published mainnet signatures**
- [x] `scripts/test_oracle_against_vectors.py` passes all 4 vectors — 16/16 input sighashes re-verify against the oracle and against published sigs. Exit 0.

---

#### Phase 1.5.3 — C implementation + canonical P2PKH check (~3-5 days)

Implement the full C diff on `Zyrtnin-org/lib-app-bitcoin@radiant-v1` branch.

**Tasks:**

1. [x] **Task 0** — RAM check done: context.bss grew from 0x3c8 (968B) to 0x4b0 (1200B), +232B, ~24% growth — within budget. Chose peer struct members (plan default) per ADR in INVESTIGATION.md.
2. [x] **`context.h`** — `hashedOutputHashes[32]` added to `segwit_cache_s`; `hashOutputHashesCtx`, `currentOutputScriptCtx`, `currentOutputBytesRemaining`, `currentOutputSatoshis`, `outputParsingSubstate` added to `struct context_s`. New `radiant_output_substate_t` enum.
3. [x] **`handler/hash_input_start.c`** — calls `radiant_output_hash_init()` on first APDU (no-op for non-Radiant)
4. [x] **`handler/hash_input_finalize_full.c`** — Radiant FSM feeds `discardSize` bytes of each just-completed output into `hashOutputHashesCtx`; canonical-P2PKH check rejects non-25-byte scripts with `SW_INCORRECT_DATA`; finalization alongside existing `hashedOutputs` finalize. All logic in helpers.c (`radiant_output_hash_*` family).
5. [x] **`transaction.c:721-732`** — inserts `hashedOutputHashes` into `transactionHashFull.sha256` BEFORE `hashedOutputs` guarded by `COIN_KIND == COIN_KIND_RADIANT`
6. [x] **`hash_input_finalize_full_reset`** — calls `radiant_output_hash_reset()` which unconditionally clears all new FSM state (Security H2 / SpecFlow #4+#6 closure)
7. [x] **Runtime assertion** — one at entry of `radiant_output_hash_finalize()`. Per-write asserts dropped per review.
8. [x] **Electron-Wallet plugin pre-check** — `electroncash_plugins/ledger/ledger.py` pre-check loop rejects non-canonical-P2PKH outputs with a user-friendly error before any APDU dispatch. Committed to `Zyrtnin-org/Electron-Wallet@radiant-ledger-512`.
9. [x] **Commit + push**: `Zyrtnin-org/lib-app-bitcoin@radiant-v1 @bd7085c` (+299 lines across 6 files). `Zyrtnin-org/app-radiant@develop` bumped submodule.
10. [x] **Submodule pin bumped**: `Zyrtnin-org/app-radiant@develop` now points at `lib-app-bitcoin@bd7085c`.

**Deliverables:**

- C diff in `lib-app-bitcoin@radiant-v1`, probably ~200-300 lines
- CI green on both variants (`bitcoin_cash` no-regression + `radiant` new)
- `sha256` of new artifact recorded in `BUILDER.md`

---

#### Phase 1.5.4 — Device ↔ oracle compare harness (~1-2 days)

Wire the oracle and the device together. Run all four golden vectors through both and compare.

**Tasks:**

1. Write `scripts/compare-device-to-oracle.py`:
   - For each vector in `preimage-vectors.json`:
     - Oracle computes expected sighash
     - Sideload current build, send the transaction through the standard ledgerblue APDU sequence (untrustedTxInputHashStart / untrustedHashTransactionInputFinalizeFull / untrustedHashSign)
     - Capture returned DER signature
     - Verify signature against `(oracle_sighash, device_pubkey)` using local `secp256k1.verify`
     - Record pass/fail per vector
2. Add SpecFlow-flagged shapes to vectors if not already there:
   - 1-in/1-out (sweep) — confirms vout_count=1 handling (SpecFlow #2)
   - 30-in consolidation — APDU boundary stress (SpecFlow #3)
3. Run canceled-sign test: start a sign flow, press left button on device (reject). Then immediately retry same sign. Verify state was reset properly (SpecFlow #4, #6).
4. **State-reset regression check**: replay the identical APDU byte sequence N=10 times in a row without restarting the app. Device output must be bit-identical across all 10 replays. If it varies, reset is broken — return to Phase 1.5.3 step 6 before proceeding. (Replaces the formerly-standalone Phase 1.5.6 "pre-fix regression guard," which Security L1 correctly identified as shadow-boxing — the old code path doesn't exist as a conditional branch, so catching it is not the failure mode we should guard against. The real regression risk is stale state between signs.)
5. Record all results in `INVESTIGATION.md`.

**Deliverables:**

- All 4+ golden vectors: device signature validates against oracle sighash locally
- Cancel-then-retry works without stale state
- Any failures: drop into raw APDU tracing to diagnose preimage divergence

**Gate**: must pass all vectors before Phase 1.5.5 touches mainnet.

---

#### Phase 1.5.5 — Mainnet final-test (~0.5 day)

Sign and broadcast the 1-in/2-out spend that originally failed. Unstick the 1 RXD at `1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc`.

**Tasks:**

1. Sideload the Phase 1.5.3 build to the dev Nano S Plus (same device used for all Phase 1 testing)
2. Open Electron-Wallet (venv with our modified plugin at `radiant-ledger-512` branch)
3. Compose 0.5 RXD send back to source wallet `16nqCDuBCQEcgRUZ3DCigtq18gfjEWUuyS`
4. Sign on device; verify every screen (amount, fee, destination)
5. Broadcast via Electrum
6. Verify acceptance: `getrawtransaction <txid>` returns the tx; it confirms in a block
7. Screenshot every device screen; record txid

**Deliverables:**

- [x] One confirmed mainnet RXD tx signed by the Ledger Radiant app — **txid `d942de8c94c2e1a9ed5afe14e8505556170e3d5243ecbfa80260a1feeaf3d679`, block 420756**
- [x] Annotated screenshots of device signing screens
- [x] Updated `INVESTIGATION.md` with the fix arc + final mainnet txid
- [x] Tag `v0.0.3-sighash-fix` on `Zyrtnin-org/app-radiant` at commit `cd043c4`

**If the mainnet test FAILS**, branch on the failure shape:

1. Capture the exact `blockchain.transaction.broadcast` response string — the node's rejection often carries more detail than Electron-Wallet's generic error surface. Pull from `/tmp/electron-radiant.log` or manually broadcast the signed tx hex via Electrum CLI to see the raw response.

2. Decide failure class:
   - **Deterministic, device ↔ oracle matches but mainnet still rejects**: a second preimage discrepancy exists beyond `hashOutputHashes` that neither we nor radiantjs know about. Trigger a focused mini-brainstorm (scope: what ELSE in radiant-node's signing path differs). Do NOT retry mainnet until diagnosis lands.
   - **Deterministic, device ↔ oracle MISMATCHES for a tx shape Phase 1.5.4 said was fine**: the golden-vector set didn't cover the real-tx shape. Add the shape to vectors, iterate Phase 1.5.3 → 1.5.4 until the harness passes.
   - **Intermittent — signs and confirms N-of-M times**: this is the nightmare state-reset class. Stop mainnet immediately. Drop to device-isolated replay: send the identical APDU sequence N≥10 times, compare device outputs bit-for-bit. If device output varies across replays, state reset is broken — return to Phase 1.5.3 step 6 before any further mainnet activity. If device output is identical but mainnet acceptance varies, the problem is host-side (Electron-Wallet APDU chunking) and is out of scope for this plan — document and escalate.
   - **`v0.0.3-sighash-fix` tag discipline**: do NOT tag until a full 10-for-10 deterministic green replay is logged. No mainnet-retry without changing something material in code or vectors.

3. Whatever the outcome, append it to `INVESTIGATION.md`. Protects remaining RXD dust and makes the failure arc self-documenting for Phase 3 community testers later.

---

---

## Alternative Approaches Considered

**Strategy B: host-assisted pre-computation.** Host (Electron-Wallet plugin) computes `hashOutputHashes` and passes it to device via an extra APDU. Device uses it opaquely in preimage. Simpler C diff (~30 lines instead of ~250). **Rejected**: security review flagged latent host-commitment channel. Even though today's Radiant consensus makes inconsistent host input self-correcting (the tx gets rejected by the network), any future consensus change — especially around ref-binding semantics — would turn it into a trust-model violation. Not worth saving ~200 lines.

**Clean-slate rewrite of preimage code in `lib-app-bitcoin` for Radiant.** Would let us structure around Radiant's semantics from the start. **Rejected**: 5-10x the work. Changes to well-tested upstream code = risk. The BCH path is battle-tested across dozens of variants. We want Radiant to be a branch in that tree, not a separate tree.

**Implement full `GetPushRefs` opcode-aware scan now.** Would allow non-P2PKH outputs in v1. **Rejected**: adds ~50-100 lines of opcode-walking C code, turns v1 into v1.5. We want the canonical-P2PKH short-circuit for v1 because it makes correctness provable and trivially auditable. v2 replaces it.

---

## Acceptance Criteria

### Functional Requirements

- [ ] `make COIN=radiant` against the pinned builder image produces `bin/app.hex` with a SHA256 reproducible across machines and matches CI
- [ ] Python oracle self-validates via three checks (mainnet tx signature match, hand-computed fixture match, cross-check vs independent signer); exits 0 only if all three pass
- [ ] Oracle successfully computes sighash for all four golden vectors
- [ ] Device signs a 1-in/1-out Radiant tx (sweep); signature validates locally against oracle sighash via `secp256k1.verify`
- [ ] Device signs a 1-in/2-out Radiant tx (with change); validates
- [ ] Device signs a 3-in/2-out Radiant tx (multi-input); validates
- [ ] Device signs a 10-in/1-out Radiant tx (consolidation-scale); validates — stresses per-output-hasher lifecycle over multiple iterations
- [ ] Device rejects any non-canonical-P2PKH output with `SW_INCORRECT_DATA`; rejection surfaces to user cleanly
- [ ] Device rejects any output with `scriptPubKeyLen > MAX_SCRIPT_SIZE`
- [ ] All signatures verify against `(oracle_sighash, device_pubkey)` via local secp256k1 check — this is the "bit-match" proof
- [ ] Cancel signing on device, then retry same sign immediately: second attempt succeeds (SpecFlow #4/#6 — state reset works)
- [ ] Real mainnet RXD tx: the stuck 1 RXD at `1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc` confirms in a block via Ledger-signed 1-in/2-out spend
- [ ] `bitcoin_cash` variant still builds, artifact SHA256 unchanged from `v0.0.2-bootstrap` (regression check — SpecFlow #9)

### Non-Functional Requirements

- [ ] CI matrix green on every push: builds both `bitcoin_cash` AND `radiant` variants
- [ ] Local↔CI artifact SHA256 byte-identical for `radiant` variant
- [ ] RAM usage fits Nano S Plus app budget — **measured**, not projected — via an on-device `SP` (stack pointer) `PRINTF` at output-stream entry in Phase 1.5.3 Task 0. `.map` inspection alone is not a measurement.
- [ ] **Builder-image mirror pin** — `docker save` the pinned `ledger-app-builder-lite@sha256:b82bfff7…` image tarball and archive it to a Zyrtnin-org-owned GitHub release asset on `Zyrtnin-org/app-radiant`. If ghcr.io ever removes or reassigns the digest, builds remain reproducible from the archived tarball. Release blocker for v1.0.0, not for this remediation phase — flagged here so it doesn't slip.
- [ ] No regression to Phase 0 / Phase 1 tests already passing (path-lock defense, address derivation, P2_CASHADDR rejection, plugin wizard)
- [ ] One entry-point `COIN_KIND == COIN_KIND_RADIANT` assertion at the top of the new `finalize_radiant_output_hashes` function. Regression control against silent BCH contamination is the CI SHA256 diff, not per-write asserts

### Quality Gates

- [ ] `scripts/radiant-preimage-oracle.py` has doctests for each helper
- [ ] `scripts/oracle-self-validate.py` passes all three checks
- [ ] `scripts/fixtures/preimage-vectors.json` has 4 curated test vectors
- [ ] `scripts/compare-device-to-oracle.py` passes all vectors
- [ ] Pre-fix regression guard test passes: no code path produces the old (BCH-style, no hashOutputHashes) preimage
- [ ] `INVESTIGATION.md` updated with: fix arc, RAM-budget ADR, all golden-vector sighashes, final mainnet txid

---

## Success Metrics

Leading indicators that matter (adopted from parent v1 plan):

- **Python oracle independently validated three ways** — the core trust primitive. If the oracle is wrong, everything built on it is wrong.
- **Zero reports of stuck funds, wrong-network signing, or signing unintended addresses** — the only bug class that actually threatens user value.
- **Reproducibility verified by ≥1 non-author for the post-fix build**

Explicitly **not** a release gate:
- Install counts, tx counts per month (vanity — same as parent plan)

---

## Dependencies & Prerequisites

- **Hardware**: the existing dev Nano S Plus (`2c97:5000` on PID 0x5000) with the Radiant test seed that produced `1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc`
- **Stuck 1 RXD** — still safely at the Ledger address; the `v0.0.3-sighash-fix` install will sign it
- **Python env**: the Electron-Wallet venv we already built (pip-installed + the btchip direct-copy workaround). Minor: need to add `coincurve` for secp256k1.verify if not already
- **radiantjs reference**: pinned to a specific commit of `RadiantBlockchain/radiantjs` so the oracle's JS→Python port is auditable
- **FlipperHub `blockchain_rpc.php`** (for validation check C): running on the FlipperHub VPS; we control this code path already
- **Upstream**: `LedgerHQ/lib-app-bitcoin` remains untouched; our fork owns the Radiant variant
- **No new GitHub org permissions** needed

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Python oracle has a subtle JS→Python port bug that matches radiant-node's behavior by coincidence | Low | Very high (silent sign-fail or, worse, sign-wrong-thing) | Triple self-validation (SpecFlow #7): mainnet tx + hand-computed fixture + independent-signer cross-check. Oracle rejected as truth until all three pass |
| APDU-chunk-spanning scriptPubKey mishandled | Medium | High (wrong sighash for some tx shapes) | State machine in `handle_output_state` tracks `currentOutputBytesRemaining`; consolidation golden vector (30+ inputs) exercises the boundary |
| Silent `bitcoin_cash` regression from un-gated Radiant write | Low | High (breaks upstream BCH variant) | Runtime `COIN_KIND == COIN_KIND_RADIANT` assertions at every new-code write site; CI matrix builds both variants every push |
| User reject / cancel leaves stale hasher state | Medium | Medium (next sign fails until app reopen) | Extend `hash_input_finalize_full_reset`; audit cancel path explicitly; regression test in compare harness |
| RAM budget overrun from adding 2 `cx_sha256_t` + state fields | Low | Medium (build fails, linker error) | Phase 1.5.3 Task 0 measures first; fall back to union with dead `hashPrevouts` if tight |
| Mainnet rejects again due to a SECOND preimage difference we haven't found | Very low | High (another sign-reject cycle) | Oracle self-validation against real mainnet tx *before* any device signing proves the expected sighash is what mainnet uses. If oracle → validates via real signature, we know the format is correct |
| Radiant consensus changes hashOutputHashes format between plan-write and ship | Very low | High (signs stop working on a future block) | No mitigation proposed — Radiant hasn't had consensus changes in years; flag only |
| Ledger firmware update breaks something between now and mainnet sign | Low | Medium | Test on same firmware version used for Phase 1 validation; record version in `INVESTIGATION.md` |
| User spends a UTXO whose prevout scriptPubKey contains `OP_PUSHINPUTREF` bytes (e.g., dev seed has Glyph history). Radiant node may enforce sibling-input ref-binding rules we don't model | Low | Low (safe-failure: network rejects broadcast, no stuck funds) | Document in `INVESTIGATION.md`: "v1 Ledger app is not aware of Radiant ref-binding on inputs; if a spend fails and the UTXO is Glyph-touched, fall back to a software wallet." One-shot mainnet test (Security L3): sign a spend *from* a Glyph-bearing UTXO if available. If it confirms, v1 is safe even for Glyph-touched seeds |
| Coinbase dust threshold mismatch (Radiant = 1 sat; Electron-Wallet's BCH-inherited default = 546 sat) causes user-attempted sub-546-sat outputs to be refused wallet-side even though Radiant would accept them | Medium | Low (UX, not security) | Document in `INVESTIGATION.md` as known limitation. Electron-Wallet fix is out of scope for this phase |
| ghcr.io removes or reassigns the pinned builder digest, breaking future reproducibility | Low | Medium | Mirror-pin via `docker save` → archive as a `Zyrtnin-org/app-radiant` release asset (release criterion above) |

---

## Resource Requirements

- **People**: 1 developer (C + Python); same person as Phase 1
- **Time**: ~5-9 focused days
  - 0.5h Phase 1.5.0 pre-implementation checklist
  - 1 day Phase 1.5.1 oracle + triple validation (with non-P2PKH fixture in Check B)
  - 0.5 day Phase 1.5.2 golden vectors
  - 3-5 days Phase 1.5.3 C implementation (the bulk; includes Task-0 on-device RAM check, plugin pre-check, cancel-path audit)
  - 1-2 days Phase 1.5.4 compare harness + state-reset N=10 replay check
  - 0.5 day Phase 1.5.5 mainnet final test
- **Infra**: existing (Nano S Plus, Electron-Wallet venv, GitHub Actions, Radiant mainnet node access via Electrum)

---

## Future Considerations

All items tracked in [brainstorm v2 Tracking section](../brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md#v2-tracking-items-surfaced-during-this-brainstorm). Recap of what DOES get unblocked after this plan ships:

- Plan's Phase 2 (hardening) and Phase 3 (community validation) can finally execute end-to-end signing tests — they were gated on this fix
- The parent v1 plan's v1.0.0 release becomes unblocked (subject to the parallel dependency-cleanup workstream: btchip-python vendoring, Electron-Wallet packaging)

Post-v1 work items **explicitly added during this planning cycle**:

- Real `GetPushRefs` opcode scan (unlocks P2SH / OP_RETURN / Glyph outputs) — v2
- `SIGHASH_SINGLE` / `SIGHASH_ANYONECANPAY` support — v2
- Schnorr signature emission — v2
- Speculos / Ragger emulator CI — v2
- Glyph-aware device UX — v2

---

## Documentation Plan

In-tree (under `Zyrtnin-org/radiant-ledger-app`):

- `INVESTIGATION.md` — update with fix arc, RAM-budget ADR, golden vectors, final mainnet txid
- `scripts/radiant-preimage-oracle.py` — inline docstrings + header explaining the port from radiantjs
- `scripts/oracle-self-validate.py` — header explaining the triple-check philosophy
- `scripts/fixtures/README.md` — what each vector covers and how it was produced
- `scripts/compare-device-to-oracle.py` — usage notes

In-tree (under `Zyrtnin-org/app-radiant`):

- `BUILDER.md` — update with new builder image digest (if it bumped), new submodule pin SHA
- Release notes on `v0.0.3-sighash-fix` tag — explain the fix, link to INVESTIGATION.md

In `lib-app-bitcoin@radiant-v1`:

- Inline comments at each Radiant-specific branch explaining *why* (cite `radiant-node/src/script/interpreter.cpp:2636` and `radiantjs sighash.js:171-237`)
- No separate README for now — the diff is self-contained

---

## References & Research

### Internal References

- Brainstorm: [`docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md`](../brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md)
- Parent v1 plan: [`docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md`](./2026-04-14-feat-radiant-ledger-app-v1-plan.md)
- Phase 1 hardware test arc: [`INVESTIGATION.md`](../../INVESTIGATION.md#phase-1-end-to-end-hardware-test-2026-04-15-continued)

### Authoritative Radiant References

- Preimage construction (node, C++): [`radiant-node/src/script/interpreter.cpp:2596-2658`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2596)
- `GetHashOutputHashes` (node, C++): [`radiant-node/src/primitives/transaction.h:475-540`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h#L475)
- Preimage construction (JS, our port target): [`radiantjs/lib/transaction/sighash.js:171-237`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L171)
- `GetHashOutputHashes` (JS): [`radiantjs/lib/transaction/sighash.js:91-128`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L91)

### lib-app-bitcoin Extension Points (our fork)

- `Zyrtnin-org/lib-app-bitcoin@radiant-v1`:
  - [`context.h:219-250`](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/context.h#L219) — coin_kind enum, segwit_cache_s
  - [`handler/hash_input_finalize_full.c`](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/handler/hash_input_finalize_full.c) — output streaming
  - [`transaction.c:721-732`](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/transaction.c#L721) — preimage insertion point

### External References

- Ledger BOLOS SDK: [`developers.ledger.com/docs/device-app/architecture/bolos`](https://developers.ledger.com/docs/device-app/architecture/bolos)
- Reusable build workflows: [`LedgerHQ/ledger-app-workflows`](https://github.com/LedgerHQ/ledger-app-workflows)
- Ledger Donjon path-lock (LSB-014 — empirically not enforced per Phase 0 Task 0.0): [`donjon.ledger.com/lsb/014/`](https://donjon.ledger.com/lsb/014/)
- Zcash Ledger app (precedent for fully-owned preimage code): [`github.com/hhanh00/zcash-ledger`](https://github.com/hhanh00/zcash-ledger) (ZIP-244 is the closest architectural analogue)

### FlipperHub (validation cross-check source)

- `/home/eric/apps/Pinball/blockchain_rpc.php` — existing production-running Radiant signing for Glyph NFT minting. Mainnet-tested. Independent implementation for validation check C.
