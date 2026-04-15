# Phase 0 investigation log

Transient doc. Delete after Phase 1 ships.

## Task 0.0 — LSB-014 path-lock verification

**Runbook:** [`scripts/task-0.0-runbook.md`](scripts/task-0.0-runbook.md)

**Status:** ✅ **PASS**

**Date:** 2026-04-15
**Operator:** eric
**Device:** Nano S Plus (USB 2c97:5000, home-screen state)
**Host:** Linux 6.17.0-20-generic, Ubuntu 24.04

**Outcome:** PASS — Ledger OS permitted an unsigned community app to declare `--path "44'/512'"` at install time. Coin type 512 is usable for the Radiant app.

**Method:**
- Built unmodified `LedgerHQ/app-boilerplate` @ `ac10944e` inside `ledger-app-builder-lite@sha256:b82bfff7...` (Nano S Plus target).
- Sideloaded via `ledgerblue.loadApp` with explicit `--path "44'/512'"` override:
  ```
  python3 -m ledgerblue.loadApp \
    --targetId 0x33100004 --targetVersion="" --apiLevel 25 --tlv \
    --curve secp256k1 --path "44'/512'" --appFlags 0x0 \
    --fileName bin/app.hex --appName "Path512Test" --appVersion "0.0.1" \
    --dataSize 512 --installparamsSize 67 --delete
  ```

**Evidence:**
- User approved "Allow unsafe manager" prompt on device (one-time for session).
- `loadApp` completed without exception; computed `Application full hash : 08d7bcbb887c2e9912ad633a51567e8f5adee486dbbab7b8bbc4f976b05c5e5b`.
- `ledgerblue.listApps` confirmed the installed app, hash matches: `{'name': 'Boilerplate', 'hash': b'\x08\xd7\xbc\xbb\x88|.\x99...'}` — same 32 bytes.
- No additional "this app may sign Bitcoin transactions" or other cross-chain warning observed during install.

**Negative control (attempted `--path "44'/0'"`):** ⚠️ **FAILED TO BLOCK — Bitcoin-path unsigned app installed cleanly.**

Sequence: prior Boilerplate uninstalled → loadApp invoked with `--path "44'/0'"` → device prompted user to approve install → user approved → app installed and runs. No additional Bitcoin-specific warning. No path-related error from loadApp.

**Conclusion:** On current Nano S Plus firmware (2026-04-15), Ledger OS does **NOT** enforce LSB-014 at install time for unsigned community apps. An unsigned app can legitimately declare `--path "44'/0'"` and be sideloaded. Either LSB-014 has been relaxed for unsigned apps, enforcement is runtime-only, or the constraint was never as strict as the research agent claimed.

**Plan impact:**

- The brainstorm and plan listed three reasons for choosing SLIP-44 coin type 512 over 0. Reason #1 (**LSB-014 blocks 44'/0' at install time**) is now empirically falsified and should be removed.
- Reasons #2 (**SLIP-0044 registry standard for RXD**) and #3 (**app-slot collision: both the BTC and Radiant apps would derive identical keys from 44'/0', allowing accidental cross-chain signing**) still fully justify the 512 choice.
- The plan's **runtime path-lock defense** (refusing derivations outside `m/44'/512'/…` in `get_wallet_public_key.c`) becomes even more important now — it's the actual defense against a misbehaving host, not LSB-014.
- Custom-CLA defense-in-depth (deferred to v2) gets slightly more attractive now that app-confusion is empirically possible.

**Main Task 0.0 PASS is unaffected** — 44'/512' still installs cleanly, which is what we need to ship v1.

**Implication:** Phase 1 C work can proceed. The Radiant app's declared path `m/44'/512'/…` will install on end-user devices under the same flow tested here.

---

## Task 0.1 — Derivation cross-check

**Script:** [`scripts/task-0.1-derivation-crosscheck.js`](scripts/task-0.1-derivation-crosscheck.js)

**Status:** ✅ **PASS**

**Date:** 2026-04-15

**Test seed:** standard BIP39 public test vector — `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`. Canonical reference seed; no real funds; widely used to verify BIP32 implementations.

**Script output:**
- `m/44'/0'/0'/0/0` → `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` (PKH `d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa`)
- `m/44'/512'/0'/0/0` → `18qiat9Kff5niCcincht6efD8HhFfzL1AJ` (PKH `55ff8f32c1a7e6a5664609e9f1e07ca396de3fb7`)

**Cross-check:** `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` is the well-known canonical derivation of this public BIP39 vector at `m/44'/0'/0'/0/0`, produced identically by Electrum, Bitcoin Core, iancoleman.io/bip39, Trezor, Ledger, and every other conformant BIP32 implementation. Our script matches. No device derivation needed — the independence comes from using a widely-verified public vector.

**Outcome:** PASS — BIP32/BIP44 math is as expected. No custom entropy handling, no non-standard hardening. `m/44'/512'/0'/0/0` for our Radiant app will derive what `radiantjs` (and any BIP32-compliant lib) computes for the same seed.

**Notes:**
- Using a public test vector instead of the user's real seed avoided a destructive device-wipe just to cross-check math.
- The 512-row address (`18qiat9K...`) is the reference address that Phase 1 integration test will check against when the user loads this seed on the finished Radiant app.

---

## Phase 1 walking skeleton — milestone (2026-04-15)

**Radiant Ledger app live on real hardware.**

C diff: ~58 lines across 5 files in `lib-app-bitcoin@radiant-v1` (commit `6e4228a`):
- `context.h` — new `COIN_KIND_RADIANT` enum value
- `helpers.{h,c}` — `is_radiant_path_allowed()` strict path-lock helper
- `handler/hash_sign.c` — extend SIGHASH_FORKID gate; refuse signing outside m/44'/512'
- `handler/get_wallet_public_key.c` — explicit Radiant arm rejecting CashAddr; refuse derivation outside m/44'/512'

Build:
- `app-radiant@develop` — submodule pinned at `6e4228a`, Makefile `radiant` variant added
- CI matrix builds both `bitcoin_cash` (regression) and `radiant` (new) green
- **Reproducibility verified**: local Docker build SHA256 matches CI artifact SHA256 exactly
  - `app.hex`: `0076b3c7da1659b5310350a8c5fea420f3f7a112ef2a11e40eb4072e7f0076b5`
  - `app.elf`: `6cc604c026479c0817c2da3583a11af263b55d25bf7119ee767f3ea6e71fab2f`

Device:
- Sideloaded to Nano S Plus (developer device, real seed).
- Derived address at `m/44'/512'/0'/0/0`: **`1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc`**
- Independently re-derived from device pubkey via Python → byte-identical match
- Pubkey: `0445e713b307d0280d7d621292cfc218d5e649e127c72e8420824ecd246207ea8e7e308375c168ed642b8add3fc2353fca346555e47250973130c2cbf6cea8a9e6`

Runtime path-lock validated against four test cases:
| Path | Outcome | Expected |
|---|---|---|
| `m/44'/512'/0'/0/0` | derives `1LkYcHB...` | succeed ✅ |
| `m/44'/512'/0'/0/1` | derives `15jhhFT...` | succeed ✅ |
| `m/44'/0'/0'/0/0` (Bitcoin) | SW 6a80 | reject ✅ |
| `m/44'/145'/0'/0/0` (BCH) | SW 6a80 | reject ✅ |

## Plugin diff (2026-04-15 — continuation of Phase 1)

**Branch**: [`Zyrtnin-org/Electron-Wallet@radiant-ledger-512`](https://github.com/Zyrtnin-org/Electron-Wallet/tree/radiant-ledger-512)

36 lines changed across 4 files:

- `electroncash/keystore.py` — `bip44_derivation(account_id, *, coin_type=None)`. Software-wallet behavior unchanged; optional kwarg lets hardware-wallet flow override
- `electroncash/base_wizard.py:269` — hardware-wallet wizard now defaults to `bip44_derivation(0, coin_type=512)` so NEW Radiant Ledger wallets land at `m/44'/512'/0'` automatically. User can still override in the derivation dialog
- `electroncash_plugins/ledger/ledger.py:590` — sanity xpub probe now requests `m/44'/512'/0'` instead of `m/44'/0'/0'`. Doubles as app-identity check since our Radiant app rejects non-512 paths with SW_INCORRECT_DATA — a stock Bitcoin app would NOT reject, so a probe success at `m/44'/512'` actually proves we're talking to the Radiant variant
- `electroncash_plugins/ledger/__init__.py` — plugin description now points to the Radiant app (not stock Bitcoin) and explicitly warns users with pre-existing `m/44'/0'` funds that migration is required

Smoke tests (no RXD required):
- `py_compile` clean on all 4 files
- Standalone `bip44_derivation` call-site output verified:
  - software default: `m/44'/0'/0'`
  - hardware Radiant acc 0: `m/44'/512'/0'`
  - hardware Radiant acc 1: `m/44'/512'/1'`

## Phase 1 end-to-end hardware test (2026-04-15, continued)

### ✅ Everything before the signing step works

- Electron-Wallet setup in a venv (Qt, ecdsa, btchip). **Workaround needed**: btchip-python's setup.py is incompatible with modern setuptools (`extras_require` format error). Cloned `LedgerHQ/btchip-python` master and dropped the `btchip/` module directly into `venv/lib/python3.12/site-packages/`. This is OK for a dev session (same code pip would install, device screen is the trust anchor) but NOT a shipping strategy — need an upstream fix or vendoring as a v1 release prerequisite.
- Additional plugin fix: `DEVICE_IDS` list in `electroncash_plugins/ledger/ledger.py` was missing `(0x2c97, 0x5000)`. Nano S Plus keeps PID 0x5000 in many app-open configurations. Added the tuple. This is the piece the closed PR #1 had right from the start — detection-only, not a replacement for the signing work.
- Wizard flow: detected the device after the PID fix, showed **`m/44'/512'/0'`** as the derivation default (our `bip44_derivation(0, coin_type=512)` change in action), requested xpub from device, created the wallet.
- Wallet opens with `radiant-ledger-test [standard]` title, green Electrum connection.
- **1 RXD funded at `1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc`** from a source wallet (txid `3521c21125f9bdf0039bec54946ca7c911f4d38c23aef1786a85e9d98f6a8556`).
- Balance correctly discovered from the xpub the device produced.

### ❌ Sign + broadcast failed — major finding

Attempted a 1-in/2-out spend (0.5 RXD back to source wallet `16nqCDuBCQEcgRUZ3DCigtq18gfjEWUuyS`, change to our Ledger wallet). Electron Radiant built the tx, Ledger signed it, tx was broadcast — **Radiant node rejected with "script execution error."**

**Root cause:** Radiant's signature preimage is NOT byte-identical to BCH's. Original research assumption was wrong.

Radiant's preimage (from [`radiant-node/src/script/interpreter.cpp:2636-2650`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2636)):

```
ss << nVersion
ss << hashPrevouts
ss << hashSequence
ss << prevout
ss << scriptCode
ss << amount
ss << nSequence
ss << hashOutputHashes   ← NEW FIELD Radiant adds; not in BCH BIP143
ss << hashOutputs        ← standard BCH field
ss << nLockTime
ss << sigHashType
```

The sighash **type byte** (`SIGHASH_ALL|FORKID = 0x41`) is identical to BCH — which is what the original research found. But the preimage **construction** differs: Radiant inserts `hashOutputHashes` between `nSequence` and `hashOutputs`, and this field is in the preimage for **every** Radiant tx (including plain P2PKH — it carries zero-ref summaries when no Glyph push-refs are present).

Our Ledger app uses the stock BCH preimage code (inherited from `lib-app-bitcoin`), which doesn't compute or emit `hashOutputHashes`. So the device signs one preimage and the network verifies against a different one. OP_CHECKSIG fails.

### `hashOutputHashes` algorithm

Per-output summary (from [`radiant-node/src/primitives/transaction.h:475-492, 532-540`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h#L475)):

```
<nValue: 8 bytes LE>
<sha256(scriptPubKey): 32 bytes>
<totalRefs: 4 bytes LE>            (= 0 for plain P2PKH)
<refsHash: 32 bytes>               (= sha256(concatenated push-refs) or 32 zero bytes for no-refs)
```

All per-output summaries concatenated, then double-SHA256'd → `hashOutputHashes`.

For v1 plain P2PKH scope: `totalRefs=0` and `refsHash=0x00...00` for every output. Per-output summary is a deterministic 76 bytes.

### Walking-skeleton strategy vindicated

Discovery cost: 1 RXD value at risk, ~hours of iterative debugging. Had we shipped the plan as originally scoped, users would hit "script execution error" on their first send — after trusting us.

### Plan impact

Current plan assumed the C diff is ~58 lines. With `hashOutputHashes` the real scope is likely **150-300 lines** across:
- `handler/hash_input_start.c` — initialize a parallel hasher for `hashOutputHashes` (Radiant-only)
- `handler/hash_input_finalize_full.c` — for each output, compute `sha256(scriptPubKey)` + emit the 4-field summary into the parallel hasher
- `context.h` / `context.c` — store finalized `hashOutputHashes` on the context struct
- `handler/hash_sign.c` — insert `hashOutputHashes` into the preimage before `hashOutputs` when `COIN_KIND == COIN_KIND_RADIANT`
- Push-ref scanning scaffolding (for v2 bridge; v1 short-circuits to zero)

### Status check

| Step | Status |
|---|---|
| C diff (enum + gate extension + path-lock helper) | ✅ done |
| Makefile + icons + CI matrix (local↔CI reproducible) | ✅ done |
| Sideload + address derivation + path-lock defense | ✅ done |
| Plugin (Electron-Wallet branch `radiant-ledger-512`) | ✅ done |
| Wallet creation + balance discovery | ✅ done |
| **Sign preimage includes `hashOutputHashes`** | ❌ **not done — root cause of broadcast rejection** |

### Next step

Run `/workflows:brainstorm` focused on: "How do we properly extend our Radiant Ledger app's preimage to include `hashOutputHashes` without introducing new attack surface, and what else about Radiant's signature/script semantics might differ from BCH?" Then `/workflows:plan` against the finding.

User's 1 RXD is safe at the Ledger address until the fix ships. No rush.

---

## Phase 1.5.0 — Pre-implementation checklist (2026-04-15)

All 5 spec checks verified against canonical sources before any oracle / C code is written.

| # | Check | Source | Finding |
|---|---|---|---|
| 1 | `totalRefs` wire format | [`radiant-node/src/primitives/transaction.h:485`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h#L485) `uint32_t totalRefs` + [`radiantjs sighash.js:108`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L108) `writer.writeUInt32LE(pushRefs.size)` | **u32 LE, 4 bytes.** NOT a varint. |
| 2 | Tx-version branching | [`radiantjs sighash.js:200`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L200) `writer.writeInt32LE(transaction.version)` + [`radiant-node interpreter.cpp:2637`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2637) `ss << txTo.nVersion` | **No version-dependent branching** in the preimage. Oracle and device both emit whatever version came in. |
| 3 | Per-output summary byte layout | [`radiant-node/src/primitives/transaction.h:489-492`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h#L489) + [`radiantjs sighash.js:99-123`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L99) — two-source agreement | **76 bytes, order: `nValue(8 LE) + scriptPubKeyHash(32) + totalRefs(4 LE) + refsHash(32)`** |
| 4 | Final `hashOutputHashes` is double-SHA256 | [`radiantjs sighash.js:127`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L127) `Hash.sha256sha256(buf)` + [`radiant-node transaction.h:538`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h#L538) `CHashWriter.GetHash()` (double-SHA256 by Bitcoin convention) | **Double SHA256** |
| 5 | SIGHASH gate in our code | [`lib-app-bitcoin/handler/hash_sign.c:127`](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/handler/hash_sign.c#L127) `if (sighashType != (SIGHASH_ALL \| SIGHASH_FORKID))` | **Exact-equality `!= 0x41`**. Rejects 0x81 (ALL\|ANYONECANPAY\|FORKID), 0x42 (NONE\|FORKID), 0x43 (SINGLE\|FORKID). Already correct from Phase 1 C diff. |

All 5 checks green. Proceed to Phase 1.5.1.

---

## Phase 1.5.1 — Python oracle + triple self-validation (2026-04-15)

**Oracle:** [`scripts/radiant_preimage_oracle.py`](scripts/radiant_preimage_oracle.py) — Python port of `radiantjs/lib/transaction/sighash.js:91-237`. Pure stdlib + `ecdsa`. Pure functions.

**Self-validator:** [`scripts/oracle_self_validate.py`](scripts/oracle_self_validate.py) — runs all 3 checks, exits 0 only on all-green.

**Run:** `python3 scripts/oracle_self_validate.py` → PASS on 2026-04-15 (exit 0).

### Check A — known mainnet tx signature verification

- Tx: `3521c21125f9bdf0039bec54946ca7c911f4d38c23aef1786a85e9d98f6a8556` (our funding tx)
- Oracle-computed sighash for input 0: `c8554a48c5ff2bc404b1a16eaaa58bfaee6b992829cf963b2278687654e515d3`
- Published signature verifies against that sighash + published pubkey via `ecdsa.VerifyingKey.verify_digest`
- **Result:** PASS — oracle produces the same digest the signing node signed against.

### Check B.1 — hand-computed P2PKH preimage byte-diff

- Synthetic 1-in/1-out P2PKH tx, construction documented inline in `_manual_preimage_p2pkh()`
- Expected preimage hand-derived from spec (sha256d per-field, concat order, widths)
- Oracle-computed preimage **byte-identical** (214 bytes)
- Sighash: `f76d55eac5c91b5f289702037d92948b184dfbce770c1e57ff08ea8dfa68d1d1`
- **Result:** PASS — oracle matches hand-derivation from spec.

### Check B.2 — hand-computed OP_RETURN + P2PKH preimage byte-diff (closes Security H1)

- Synthetic 1-in/2-out tx: output 0 is `OP_RETURN <10 bytes>` (12B script), output 1 is standard P2PKH (25B script)
- Exercises the **varying-script-length path** in the per-output summary hasher — the monoculture gap Security H1 flagged
- Oracle-computed preimage **byte-identical** (214 bytes) to hand-derivation
- Sighash: `a63585c138965b399e6de785d6470d3099218d8de2270e8303647a7be0c99df3`
- **Result:** PASS — H1 closed.

### Check C — second mainnet tx independent-signer verification

- Tx: `841c66ac8f8639a65b1d7e004b3d87b2247e6dc050d73dd01a1e794ece4b48e3` (100-in/2-out consolidation by a different wallet)
- Sampled inputs 0, 1, 50, 99 — each signature verifies against oracle's sighash for that input
- **Result:** 4/4 PASS — oracle is not coupled to any single implementation quirk; produces correct digests across different signers and tx shapes.

### Combined confidence

Triple-check with two independent mainnet txs + two hand-derivations across two output-shape classes. Oracle is trusted as ground truth for Phase 1.5.4 device-compare harness.

Deferred: `FlipperHub blockchain_rpc.php` cross-check via SSH (originally plan'd as Check C) — made redundant by the stronger upgraded Check C against a truly different signer. Documented for completeness but not run.

---

## Phase 1.5.2 — Golden test vectors (2026-04-15)

**Fixtures:** [`scripts/fixtures/preimage-vectors.json`](scripts/fixtures/preimage-vectors.json)
**Builder:** [`scripts/build_fixtures.py`](scripts/build_fixtures.py) — runs once per oracle change
**Self-test:** [`scripts/test_oracle_against_vectors.py`](scripts/test_oracle_against_vectors.py) — exit 0 means fixtures align with current oracle

Four target tx shapes, all sourced from real mainnet-confirmed RXD transactions. Each fixture includes: signed tx hex, unsigned tx hex, per-input prevout data, oracle-computed expected sighash, and the published signature (for re-verification). Build-time validation: every sighash verified against the published signature via `ecdsa.VerifyingKey.verify_digest`.

| Name | Shape | Txid | Inputs verified |
|---|---|---|---|
| `sweep_1in_1out` | 1-in / 1-out (sweep, no change) | `48bcbdef…` | 1/1 |
| `standard_1in_2out` | 1-in / 2-out (with change) | `3521c21…` (our funding tx) | 1/1 |
| `multi_3in_2out` | 3-in / 2-out (multi-input) | `266fdbec…` | 3/3 |
| `consolidation_11in_1out` | 11-in / 1-out (per-output-hasher lifecycle stress) | `b4debc15…` | 11/11 |

**Total: 16 sighashes, 100% verified against published mainnet signatures.**

These fixtures drive Phase 1.5.4's device-compare harness: host sends the unsigned tx + per-input prevout data to the device, captures the device's DER signature, verifies that signature against `(expected_sighash, device_pubkey_at_m_44_512_0_0_0)`. If verify passes, device and oracle agree on preimage.

Note on device-vs-published-pubkey: the fixtures' `published_pubkey_hex` is documentary — it's the original signer's pubkey, different from our Ledger's. At compare-harness time we'll verify the device's signature against the device's own pubkey (queried via GetWalletPublicKey APDU) + the oracle-computed sighash. The oracle sighash depends only on tx-structure + prevout-data, not on who owns the UTXO, so this works cleanly.

---

## Phase 1.5.3 — C implementation (2026-04-15)

**~299 lines across 6 files in [`Zyrtnin-org/lib-app-bitcoin@radiant-v1@bd7085c`](https://github.com/Zyrtnin-org/lib-app-bitcoin/tree/radiant-v1).**

**Task 0 RAM measurement (ADR):**
- Before: `.bss.context` size was `0x3c8` = 968 bytes (Phase 1 baseline)
- After Phase 1.5.3 additions: `0x4b0` = 1200 bytes (+232B, ~24% growth)
- Plan target was ~240B. Within budget.
- **Layout choice:** peer struct members (plan's default). Union with dead `hashPrevouts` not needed — we have comfortable slack.

**Changes:**

| File | Purpose |
|---|---|
| `context.h` | Added `hashedOutputHashes[32]` to `segwit_cache_s`. Added `hashOutputHashesCtx`, `currentOutputScriptCtx`, `currentOutputBytesRemaining`, `currentOutputSatoshis`, `outputParsingSubstate` to `struct context_s`. New `radiant_output_substate_t` enum (AMOUNT / SCRIPT_LEN / SCRIPT). |
| `helpers.{h,c}` | Four new functions (all no-ops for non-Radiant): `radiant_output_hash_init()`, `_reset()`, `_feed_byte()`, `_finalize()`. The FSM accumulates each output's 76-byte summary (`nValue + sha256d(scriptPubKey) + totalRefs=0 + refsHash=zeros`) into `hashOutputHashesCtx`. Canonical-P2PKH enforcement at `SCRIPT_LEN` state (reject != 25). Added `#include "apdu/apdu_constants.h"`. |
| `handler/hash_input_start.c` | Calls `radiant_output_hash_init()` on first APDU. |
| `handler/hash_input_finalize_full.c` | Radiant FSM is fed per-output bytes at end of `handle_output_state` (before the discardSize memmove). Finalization alongside the existing `hashedOutputs` finalize. `hash_input_finalize_full_reset` calls `radiant_output_hash_reset()` for full cancel-path coverage. |
| `transaction.c:721-732` | Inserts `hashedOutputHashes` into `transactionHashFull.sha256` BEFORE `hashedOutputs` when Radiant. |

**Build + regression outcomes:**
- `COIN=radiant` builds clean. app.hex SHA256: `ecfab19af630dd2d1f06d951ffa2c37852508590af0ac96e3534d59a1c395d72`
- `COIN=bitcoin_cash` still builds clean (regression = build-only per plan acceptance criteria). SHA256 **differs from v0.0.2-bootstrap** because context struct is larger and Radiant helpers exist as symbols. Binary is larger but BCH runtime behavior is unchanged (all Radiant code guarded by `if (COIN_KIND == COIN_KIND_RADIANT)` runtime checks + compile-time constant folding should eliminate dead branches at `-Os`).
- CI [run 24477719717](https://github.com/Zyrtnin-org/app-radiant/actions/runs/24477719717): both variants green.

**Plugin pre-check ([`Zyrtnin-org/Electron-Wallet@radiant-ledger-512`](https://github.com/Zyrtnin-org/Electron-Wallet/tree/radiant-ledger-512), commit `6b6e2c7`):**

`electroncash_plugins/ledger/ledger.py` now pre-checks every output for canonical 25-byte P2PKH (hex matches `^76a914[0-9a-f]{40}88ac$`). If not, raises a clear wallet-UI error before any APDU dispatch. Pairs with device-side enforcement for defense-in-depth.

**Not yet tested on device.** Phase 1.5.4 compare harness is next — sideload, feed golden vectors, verify device signatures against oracle sighashes.

---

## Pins recorded for reproducibility

- `LedgerHQ/app-boilerplate` @ `ac10944e8bfed3d1e57af9a856dd6ab716a74a1b`
- `LedgerHQ/ledger-app-workflows` @ `2ddae7bf080353584b77bd1356c8909c5b8f8257` (still pinned for `guidelines_enforcer.yml` only)
- `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite` @ `sha256:b82bfff7862d890ea0c931f310ed1e9bce6efe2fac32986a2561aaa08bfc2834` (multi-arch index, resolved 2026-04-15)

## Phase 0 bootstrap — CI green

- Fork: [`Zyrtnin-org/app-radiant`](https://github.com/Zyrtnin-org/app-radiant) (from `LedgerHQ/app-bitcoin`)
- Fork: [`Zyrtnin-org/lib-app-bitcoin`](https://github.com/Zyrtnin-org/lib-app-bitcoin) (from `LedgerHQ/lib-app-bitcoin`)
- Submodule URL updated to point at our fork
- Tag: `v0.0.2-bootstrap` at commit `47125ea`
- First green CI: [run 24443131113](https://github.com/Zyrtnin-org/app-radiant/actions/runs/24443131113) (49s, COIN=bitcoin_cash)
- Artifact SHA256:
  - `bin/app.hex`: `cad2edf89307ca53de675ec14cc3bea8968f1357fa0cd3e8b7049c3ad40f117d`
  - `bin/app.elf`: `e9221f220eb710518ab310cba8b87d23187bfd60d711271e267856fbbf416f9d`
- `app.elf` verified as 32-bit ARM EABI5 ELF — correct target for the secure element

### CI deviation from the plan

The plan said "use `LedgerHQ/ledger-app-workflows` reusable workflow." We tried `@v1` and `@SHA` forms — both failed with `startup_failure` in a non-debuggable way on this fork. Replaced the build job with a direct workflow that pulls `ledger-app-builder-lite` by pinned digest. The guidelines_enforcer still uses the reusable workflow (pinned by SHA) because it's an app-quality gate, not the build step.

Unexpected upside: the direct workflow lets us pin the **builder image digest**, which the reusable workflow hardcodes to `:latest`. So reproducibility discipline is stronger than the original plan specified.
