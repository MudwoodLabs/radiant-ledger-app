# Electron-Wallet FT-Send Follow-Up — Brainstorm

**Date:** 2026-04-17
**Status:** Brainstorm complete — ready for `/workflows:plan` after resolving the one verification blocker.
**Scope:** Extending `Zyrtnin-org/Electron-Wallet` (Python fork of Electron-Cash, branch `radiant-ledger-512`) so users can not just *see* Radiant Glyph FT holdings but actually *send* them.

---

## What This Is Not

The preceding work landed **recognition**: commit `049765ef` on local branch `feat/glyph-classifier` adds `classify_glyph_output()` to `electroncash/glyph.py`, wires it into `get_address_from_output_script` in `transaction.py`, and extends `WalletData.add_tx` to track FT holders. After that PR merges, a user's Coins tab will display FT UTXOs with the right address + balance.

**But the wallet can't send them yet.** Naïve spend of a 75-byte FT input with a plain P2PKH change output violates Radiant's per-codeScriptHash photon-conservation rule and consensus rejects the tx. The send flow needs to build FT-preserving change outputs.

This document brainstorms that follow-up PR.

---

## The Four Facets

A 4-agent parallel brainstorm explored coin-chooser strategy, transaction-builder + change-output handling, GUI/UX, and test strategy. Full option tables in the raw agent outputs; the consolidated recommendations follow.

### Coin chooser

The wallet already has a protective wall: `get_spendable_coins(exclude_glyph=True)` at `wallet.py:1069` filters FT UTXOs out of normal RXD sends. That's already correct behaviour for the common case. The follow-up needs to **bypass** that filter deliberately when the user chooses "Send Token."

Recommended shape:

- **Send-flow entry point:** single Send tab with an Asset dropdown (RXD default, known tokens below) — mirrors Electron-Cash-SLP's pattern. Lowest GUI diff; matches the user's mental model of "I'm sending X."
- **Plain RXD send:** zero changes. The existing `exclude_glyph=True` filter already protects FT UTXOs.
- **Token send:** a new `GlyphTokenChooser(CoinChooserPrivacy)` subclass pre-partitions UTXOs into FT-X coins and plain-RXD coins, picks the minimum FT-X subset covering the send amount, then runs the parent chooser on the plain-RXD pool for the fee. Preserves Electron-Cash's privacy/bucket logic on the fee side.
- **Defence in depth:** type-tag each UTXO with `glyph_kind` at `get_utxos` time, assert at the `make_unsigned_transaction` boundary that no input has `glyph_kind` unless the caller opted in via a new `allow_glyph=True` kwarg. Catches any call path that bypasses the wallet-level filter.

**Forbid mixing token + RXD sends in one tx.** Known token wallets (SLP Edition, Photonic, Glyphium) forbid it. Two conservation constraints + two change outputs + user confusion is not worth the atomicity benefit.

### Transaction builder + change outputs

Key insight from reading the code: serialisation only cares about `addr.to_script()`, not the `TYPE_*` field. So the minimal-diff approach is:

- **Output representation:** `GlyphFTOutput(ScriptOutput)` subclass. Pre-computes the 75-byte script from `(pkh, ref, value)`; `to_script()` returns those bytes. `TYPE_SCRIPT` unchanged. `add_outputs` already accepts `ScriptOutput` instances — zero changes. Change-address detection (`is_mine`, `is_change`) needs extension.
- **Fee estimation:** automatic. `estimated_size()` calls `serialize_output` → `pay_script` → `to_script()`; the FT's 75B vs P2PKH's 25B is priced in for free. Only correct if change outputs are fully constructed before calling `estimated_size` — so the builder pre-computes both FT-change and RXD-change.
- **Change-output policy:** pre-compute both change outputs (FT-change via `GlyphFTOutput`, RXD-change as regular P2PKH) before calling `make_unsigned_transaction`. Skip the chooser's single-change-output path entirely. Caller computes fee: `rxd_inputs_total - rxd_fee - sum_rxd_outputs = rxd_change`.
- **Signing:** no changes expected. The FT holder's prologue is plain P2PKH; scriptSig is `<sig> <pubkey>`; consensus evaluates the FT conservation epilogue off-stack. **Verification required:** confirm Radiant's sighash cuts at `OP_STATESEPARATOR` so the signed preimage only covers the 25-byte P2PKH prefix, not the full 75 bytes. If it cuts at STATESEPARATOR, signing is zero-diff; if it covers the full script, signing grows a new path.
- **Pre-broadcast validation:** `testmempoolaccept` before the confirmation dialog. Catches builder bugs (off-by-one in FT value, wrong ref bytes, bad fee) before the user clicks Send. One extra RPC round-trip (~100 ms on a local node) is worth the safety net for a new consensus-critical code path.

### GUI / UX (Qt)

Mirror Electron-Cash-SLP's architecture, which is already partially scaffolded in this fork — `utxo_list.py` has `slp_token` DataRoles and `slpBG` colouring hook points.

- **Balance display:** separate **Tokens tab** alongside the Coins tab (add_optional_tab pattern). Main balance line stays "X.XX RXD" — untouched for users who don't hold tokens. Token holders tab-switch to see per-token rows (ticker / truncated ref hex / total photon balance).
- **Send entry:** Asset dropdown on the existing Send tab (Row 0 of the grid). Defaults to "RXD"; lists known tokens below. Selecting a token swaps the amount-field unit label and filters the "From" coins list to matching UTXOs.
- **Token metadata (v1):** raw truncated ref hex + user-editable label (stored in `wallet.storage` as `glyph_ref_labels`). No indexer dependency. Zero trust assumptions. A future v2 can add a lazy CBOR fetch or a bundled registry; v1 doesn't need either.
- **Dust protection:** muted colour for UTXOs of unknown refs — not auto-frozen. User keeps control.
- **Error messages:** map known consensus rejection strings to friendly text ("conservation violation → this transaction would destroy tokens..."). Unmapped errors surface raw in a collapsible section.
- **Decimals (v2):** respect CBOR `dec` when present, raw photons when absent. Parser not in scope for v1.
- **Confirmation dialog:** dedicated pre-send modal for token transfers. Shows: Token name / ref, Amount in token units, Recipient, Fee (in RXD), RXD change. Different from the plain RXD confirmation.

### Test strategy (3 layers)

1. **Unit tests** (pure Python, no node). Scenario-table tests for the coin chooser (send RXD-only, send FT-X-only, send RXD+FT-X — each asserts selected UTXOs + no cross-token contamination). Script-level output-structure assertions for the builder (not brittle hex comparisons). Reuse the 24 classifier vectors from `radiant-ledger-app/view-only-ui/fixtures/classifier-vectors.json` as the fixture base — extend the JSON with a new `tx_builder_vectors` array. Time-cheap, runs under `tox`.
2. **Regtest integration** (local node, CI-optional). New `docker-compose.test.yml` with a regtest Radiant node. Mint a test FT, exercise the full chooser-and-builder path, submit via `testmempoolaccept`. **One unverified assumption:** does Radiant regtest activate V2 from block 0, or does it mirror mainnet's height 410,000 requirement? Needs a few hours of source-reading to confirm before committing to this layer.
3. **Mainnet smoke test** (existing `radiant-mainnet` container on VPS). Build an FT send tx against a small controlled FT UTXO, sign, submit to the existing container's `testmempoolaccept`. Zero RXD cost. High consensus confidence. The tx hex + acceptance response go in the PR description as evidence.

**Minimum evidence bar for Radiant-Core maintainers:** unit tests pass under `tox`, one `testmempoolaccept` or mainnet txid cited in the PR description. Coverage percentage is not currently gated in the Electron-Wallet fork.

---

## The One Verification That Gates Everything

Before committing to the "signing is zero-diff" plan, confirm Radiant's sighash spec:

- Read `radiant-node/src/script/sighash.cpp` (or equivalent) and `interpreter.cpp` where the sighash preimage is assembled.
- Confirm whether `OP_STATESEPARATOR` (0xbd) causes the sighash to cut the scriptCode at that point, or whether the full 75-byte output script is hashed.
- If it cuts at STATESEPARATOR: signing is literally zero code changes. Carry on with the plan above.
- If it covers the full script: signing needs a new scriptCode derivation for FT inputs, which grows the PR scope by maybe 1-2 days and a new test file.

**Estimated research time: 2 hours.** Worth doing before anything else on the follow-up.

---

## Rough Sequencing for the Follow-Up PR

1. **Verify the sighash cut point** (2 hours) — reading radiant-node source.
2. **Implement `GlyphFTOutput` + pre-compute change outputs + `GlyphTokenChooser`** (~2-3 days).
3. **Unit tests** mirroring the existing `classifier-vectors.json` pattern (~1 day).
4. **Regtest V2 activation research** (a few hours). If regtest auto-activates V2, add regtest integration test. If not, skip this layer.
5. **Mainnet `testmempoolaccept` smoke test** as the final evidence (~a few hours).
6. **GUI layer** — Tokens tab + asset dropdown + labels (~2-3 days).

Total: roughly 1.5 weeks of focused work.

---

## Out of Scope for This Follow-Up

- Token metadata fetch (CBOR parser, indexer integration) — v2
- Decimals display — v2
- Mixed RXD + token atomic sends — explicitly forbidden
- dMint / container NFT minting — separate surface, not wallet-scope
- Full Ledger hardware signing of FT inputs — the Ledger firmware already signs P2PKH; confirming it works for the FT prologue follows once the wallet side is there.

---

## Relationship to Other Work

- **Preceding (done):** `feat/glyph-classifier` on `Zyrtnin-org/Electron-Wallet` — commit `049765ef`, local-only, 4 tests passing. Awaiting push + PR against `Radiant-Core/Electron-Wallet:master`.
- **Preceding (done):** `radiant-ledger-app/view-only-ui/` — browser demo with the same classifier, 24 golden vectors, server.js proxy. Pushed.
- **Parallel:** `radiant-glyph-guide` — community minting guide. Separate chat maintains.
- **Parallel:** FlipperHub PHP codebase — F1–F5 security fixes pushed (commits `89941c0`, `6c1b9b1`). Separate repo.
- **Future (longer-horizon):** architectural refactor of FlipperHub's signing path (PHP → dedicated signing service) — see memory `project_flipperhub_wallet_rpc_architecture_2026-04-17.md`.

---

## Agent Transcripts

The raw option tables from each of the four brainstorm agents are stored in the session workspace:

- `/tmp/claude-1000/.../ac30a63213abbbc72.output` — coin chooser
- `/tmp/claude-1000/.../a6270327ae9490aab.output` — tx builder
- `/tmp/claude-1000/.../a7fcf8a3f21249ff3.output` — UX / GUI
- `/tmp/claude-1000/.../a00928bfb87fe4fca.output` — test strategy

These include the 2-3 options explored per sub-question with tradeoffs, for readers who want to reconsider the consolidation.
