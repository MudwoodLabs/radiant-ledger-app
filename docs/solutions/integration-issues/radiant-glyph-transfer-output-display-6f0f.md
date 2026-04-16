---
name: Ledger Radiant Glyph transfer blocked by output-side display check (0x6F0F)
description: Transfer-preserving Glyph NFT spends returned SW_TECHNICAL_PROBLEM_2 (0x6F0F) during finalizeInput because output_script_is_regular() only matched plain 25-byte P2PKH outputs. Input-side Glyph support existed since v0.0.5, but the symmetric output-side check was never added — burn-spends worked, transfers didn't.
type: integration-issue
component: app-radiant, lib-app-bitcoin, radiant-ledger-app scripts
severity: high
resolved: 2026-04-16
release: v0.0.8-glyph-transfer
related:
  - docs/solutions/integration-issues/radiant-glyph-sign-device-vs-oracle-mismatch.md
  - docs/solutions/integration-issues/radiant-preimage-hashoutputhashes-missing.md
  - docs/solutions/integration-issues/radiant-glyph-spend-end-to-end-mainnet.md
  - docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md
  - docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md
mainnet_proof_tx: af0cd27d9cda2113cc9882274ff7015f09f759ffe8b71b0c17e86c64fb6201c9
prev_mint_tx: c16c513853653125ea12d10d01e7129c419038c6d07f889606d6e23abf307a8c
---

# Output-side Glyph-P2PKH display check blocked transfer-preserving NFT spends

## Symptom

A Ledger Nano S Plus running the Radiant app v0.0.7 could sign a burn-spend of a Glyph-bearing UTXO (Glyph input → plain 25-byte P2PKH output — the `spend_real_glyph_2in.py` pattern), but any attempt to *transfer* the Glyph to a new owner — keeping the singleton ref alive by encoding the output as `d8 <ref36> 75 76a914 <hash20> 88ac` — failed at `finalizeInput` with:

```
btchip.btchipException.BTChipException: Exception : Invalid status 6f0f
```

`0x6F0F` is `SW_TECHNICAL_PROBLEM_2`. The APDU sequence reached the output-streaming phase inside `INS_HASH_INPUT_FINALIZE_FULL` before failing, meaning the device had accepted the inputs and the change-path announce but choked when asked to hash the first Glyph-shaped output.

Observed symptom was consistent across output ordering (Glyph first, plain P2PKH first, Glyph-only with no change output) and across `changePath` values (matching vs non-matching the Glyph output's embedded P2PKH tail). The only configuration that succeeded was a pure burn — the shape `76a914 <hash20> 88ac` with `script_len=0x19`.

## Root Cause

`output_script_is_regular()` in [`lib-app-bitcoin/customizable_helpers.c`](https://github.com/Zyrtnin-org/lib-app-bitcoin) was checking output scripts against a hardcoded 25-byte P2PKH pattern via `memcmp` at offset 0. The `radiant-v1` branch already had one Radiant-specific relaxation (accept P2PKH-prefixed scripts of any length, for zen-style postfix bytes), but that branch required the P2PKH opcodes at `buffer[1..3]` — i.e. immediately after the `script_len` varint.

A Glyph-wrapped P2PKH output:

```
<script_len=0x3F> <d8|d0> <ref36> <75 OP_DROP> <76 A9 14 hash20 88 AC>
```

has `buffer[1] = 0xD8` (or `0xD0` for FT refs), not `0x76`. No branch matched. `check_output_displayable()` returned `-1`, and the finalize handler bailed with `SW_TECHNICAL_PROBLEM_2`. The input side of the same asymmetry was fixed months ago (see [radiant-glyph-sign-device-vs-oracle-mismatch.md](radiant-glyph-sign-device-vs-oracle-mismatch.md) Bug 1) — inputs with Glyph-wrapped P2PKH scriptCodes have signed correctly since v0.0.5. The output side was simply never wired up.

A secondary issue compounded the debugging: the display code in `customizable_ui.c` hardcoded `addressOffset = 4` when `output_script_is_regular()` returns true, implying the 20-byte hash lives at `buffer[4..23]`. Even if the classifier had been fixed to accept Glyph outputs, the displayed address would have been wrong — 20 bytes read from the middle of the 36-byte ref instead of the actual P2PKH tail at `buffer[42..61]`.

## Solution

Three edits in `lib-app-bitcoin` on the `radiant-v1` branch, committed as [`Zyrtnin-org/lib-app-bitcoin@5e45c75`](https://github.com/Zyrtnin-org/lib-app-bitcoin/commit/5e45c75). Total diff: 61 lines across 3 files.

### 1. `customizable_helpers.c` — second Radiant branch in `output_script_is_regular()`

```c
if (COIN_KIND == COIN_KIND_RADIANT) {
  // existing branch: P2PKH-prefixed of any length (zen-style) ...

  /* Radiant Glyph-wrapped P2PKH output (transfer-preserving NFT spend):
   *   <script_len=0x3F> <d8|d0> <ref36> <75 OP_DROP> <76 A9 14 hash20 88 AC>
   * 0xd8 = OP_PUSHINPUTREFSINGLETON (NFT); 0xd0 = OP_PUSHINPUTREF (FT).
   * Pin the layout strictly (exact 63-byte script, exact opcode positions at
   * the known offsets) so random bytes can't mis-classify as displayable. */
  if (buffer[0] == 0x3F &&
      (buffer[1] == 0xD8 || buffer[1] == 0xD0) &&
      buffer[38] == 0x75 &&
      buffer[39] == 0x76 && buffer[40] == 0xA9 && buffer[41] == 0x14 &&
      buffer[62] == 0x88 && buffer[63] == 0xAC) {
    return 1;
  }
}
```

### 2. New helper `output_script_p2pkh_offset()` with the offset table

```c
WEAK unsigned char output_script_p2pkh_offset(unsigned char *buffer) {
  /* Plain P2PKH: OP_DUP OP_HASH160 PUSH20 at start → hash at offset 4. */
  if (buffer[1] == 0x76 && buffer[2] == 0xA9 && buffer[3] == 0x14) {
    return 4;
  }
  /* Radiant Glyph-wrapped P2PKH: inner P2PKH starts at buffer[39], so the
   * 20-byte hash starts at buffer[42]. Pin the same strict layout used by
   * output_script_is_regular() above. */
  if (COIN_KIND == COIN_KIND_RADIANT && buffer[0] == 0x3F &&
      (buffer[1] == 0xD8 || buffer[1] == 0xD0) &&
      buffer[38] == 0x75 &&
      buffer[39] == 0x76 && buffer[40] == 0xA9 && buffer[41] == 0x14 &&
      buffer[62] == 0x88 && buffer[63] == 0xAC) {
    return 42;
  }
  return 0;
}
```

### 3. `customizable_ui.c` — UI uses the helper instead of hardcoded `4`

```c
if (output_script_is_regular(script)) {
  unsigned char computed = output_script_p2pkh_offset(script);
  addressOffset = (computed != 0) ? computed : 4;  // fall back to legacy
  version = COIN_P2PKH_VERSION;
}
```

### Shipping artifacts

- App.hex SHA256 after patch: `e02983fa753528bb113edf0c633d312142b1e878bfbca624650524185c4c01ee`
- Built with pinned `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:b82bfff...`
- Released as [`Zyrtnin-org/app-radiant@v0.0.8-glyph-transfer`](https://github.com/Zyrtnin-org/app-radiant/releases/tag/v0.0.8-glyph-transfer) with `app.hex` + `app.sha256` attached
- Submodule bump in `app-radiant`: [`58ef5ae`](https://github.com/Zyrtnin-org/app-radiant/commit/58ef5ae)
- Install command unchanged from v0.0.7 except `--appVersion "0.0.8-glyph-transfer"` — see README §2.

## Verification

Mainnet proof, 2026-04-16:

| step | tx | purpose |
|---|---|---|
| FlipperHub mint to Ledger path `0/3` | [`c16c5138…7a8c:0`](https://explorer.radiantblockchain.org/tx/c16c513853653125ea12d10d01e7129c419038c6d07f889606d6e23abf307a8c) | Produces a Glyph UTXO at a Ledger-derived P2PKH |
| Ledger-signed transfer to path `0/5` | [`af0cd27d…01c9`](https://explorer.radiantblockchain.org/tx/af0cd27d9cda2113cc9882274ff7015f09f759ffe8b71b0c17e86c64fb6201c9) | Output 0 carries the **same** 36-byte singleton ref as the input, now locked to a different pubkeyhash — the NFT survives the transfer |

Post-confirmation (`gettxout af0cd27d... 0`):

```json
{
  "value": 0.01880000,
  "scriptPubKey": {
    "type": "nonstandard",
    "hex": "d8649b6851df249b239c6c5ca0e85d8e4ea2335176d3bde26d3de3eb229c134854000000007576a914316f149bb7d6072230faadbda01680f49655253b88ac"
  }
}
```

Script byte breakdown confirms the Glyph wrapper preserved: `d8` opcode, identical 36-byte ref, `75 76a914 <new hash> 88ac` P2PKH tail pointing at path `0/5`. Host-side driver used: [`scripts/spend_glyph_2in_transfer.py`](../../scripts/spend_glyph_2in_transfer.py). Both device signatures verified against `radiant_preimage_oracle` before broadcast.

## Investigation timeline

What went wrong during debugging, for future sessions:

1. `finalizeInput` failed with `0x6D00` (not `0x6F0F`) on first attempt — `btchip.py`'s `finalizeInput` has a `try/except: pass` around the alternate-encoding path. When `0x6F0F` fired inside the try, the exception was swallowed and the fallback to the legacy `INS_HASH_INPUT_FINALIZE` APDU surfaced a `0x6D00` (unsupported instruction) instead. The real error was only visible after bypassing the helper and driving the APDUs directly.
2. Swapping output order, using `finalizeInputFull` to skip the change-path announce, and setting `changePath` to match the Glyph output's P2PKH tail — all tried, all failed with `0x6F0F`. None of them bypassed `output_script_is_regular()`.
3. Checked `test_device_glyph_sign.py` to compare against a known-working Glyph-output test. That test happened to pass because its output matched `changePath`, causing the device to treat it as change and skip the display check entirely. This is a test-coverage gap documented in the Prevention section.
4. Root cause was identified by reading `lib-app-bitcoin/customizable_helpers.c:72-103` — the existing `radiant-v1` branch checked P2PKH opcodes at the wrong offset for the Glyph-wrapped shape.

## Related documentation

- [`radiant-glyph-sign-device-vs-oracle-mismatch.md`](radiant-glyph-sign-device-vs-oracle-mismatch.md) — the **input-side** twin of this fix. `output_script_is_regular()`'s existing Radiant branch was added here to accept Glyph-wrapped scriptCodes on the input side. This output-side fix closes the symmetric gap.
- [`radiant-preimage-hashoutputhashes-missing.md`](radiant-preimage-hashoutputhashes-missing.md) — explains why Radiant's sighash preimage inserts `hashOutputHashes` between `hashSequence` and `hashOutputs`. Understanding the preimage layout is a prerequisite for reasoning about which output bytes the device must hash.
- [`radiant-glyph-spend-end-to-end-mainnet.md`](radiant-glyph-spend-end-to-end-mainnet.md) — the first Ledger-signed Glyph spend on mainnet (burn variant). Documents the `spend_real_glyph_2in.py` pattern this new transfer script extends.
- [`docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md`](../../docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md) — v1 plan that scoped the input-side work and deferred transfer-preserving spend as a "known limitation". This fix closes that limitation.
- [`docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md`](../../docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md) — discusses canonical P2PKH enforcement at the device level; this fix relaxes it in a tightly-pinned way for the Glyph wrapper.

### Upstream references

- `Zyrtnin-org/app-radiant#1` — Phase 2A (Glyph / GetPushRefs C implementation) backlog
- `Zyrtnin-org/app-radiant#6` — v2 roadmap (multi-device, Schnorr, Speculos CI, official Ledger listing)
- `Zyrtnin-org/lib-app-bitcoin@radiant-v1` — submodule branch carrying both the input-side (`hashOutputHashes`) and output-side (this patch) Radiant fixes

---

## Prevention & Testing

### Prevention

1. **Pair every input-side shape check with its output-side twin in the same patch.** The Radiant preimage hashes both `hashPrevoutScripts` and `hashOutputHashes`, so any relaxation of `input_script_is_regular` must be accompanied by matching changes to `output_script_is_regular` / `output_script_p2pkh_offset` in the same commit. Reviewers should reject PRs that touch only one side. Add a grep-based pre-commit guard that flags commits modifying `btchip_apdu_hash_input_finalize_full.c` without also touching the output-shape helpers in `customizable_helpers.c` (or a comment explaining why asymmetry is intentional).

2. **Maintain a "Glyph shape matrix" doc in `lib-app-bitcoin/doc/`** enumerating every wrapper pattern the Radiant protocol defines (P2PKH + `OP_PUSHINPUTREF`, P2PKH + `OP_REQUIREREF`, nested state pushes, NFT vs FT variants, burn shape). Each row lists: what it looks like on the wire, whether it's allowed as an input scriptPubKey, whether it's allowed as an output scriptPubKey, and the firmware function that recognises it. This makes asymmetry visible at a glance — a blank output-side column is an obvious red flag.

3. **Exercise both spend modes on every Glyph-touching release.** Define two canonical device regression scenarios: (a) burn-spend (Glyph input → plain P2PKH output) and (b) transfer-preserving spend (Glyph input → Glyph output, destination address ≠ changePath). Tag the release checklist so neither can be skipped. v0.0.5 shipped with only (a) covered, which is exactly how this slipped.

4. **Make the display path non-optional in tests.** When a test output matches `changePath`, the device suppresses confirmation UI and skips `output_script_is_regular` entirely. Regression tests should deliberately use a destination derived from a different path so the approval/display code runs. Document this requirement alongside the test as a one-liner: `# destination MUST != changePath or display code is bypassed`.

5. **Fuzz the output-shape classifier against the oracle.** The Python `radiant_preimage_oracle.py` already knows valid script shapes; have CI generate randomised scripts (plain P2PKH, P2PKH + assorted push-ref tails, malformed prefixes, truncated refs) and compare the oracle's verdict with the firmware's `output_script_is_regular` return value via a Speculos harness. Shape-check drift between oracle and firmware is the whole bug class.

### Regression Tests

Add `scripts/test_device_glyph_output_display.py` as a device-vs-oracle counterpart to `test_device_glyph_sign.py`. Setup: reuse the same PREV_TXID/UTXO, but construct the output's P2PKH-with-pushref destination hash160 from a **different derivation path** (e.g. `44'/512'/0'/0/3`) while keeping `changePath=44'/512'/0'/0/2`. Then run the full `startUntrustedTransaction` → `finalizeInput` → `untrustedHashSign` flow. Assert that `finalizeInput` does **not** raise `SW_TECHNICAL_PROBLEM_2` (0x6F0F), that the device displays a confirmation prompt (user must approve), and that the returned signature verifies against the oracle sighash. This reproduces the exact scenario v0.0.8 fixed and would have failed on v0.0.5–v0.0.7.

Also add `scripts/test_output_script_shapes.py` as an oracle-only unit test that doesn't need a device: a parameterised table of script hex → expected `(is_regular, p2pkh_offset)` tuples covering plain 25-byte P2PKH, P2PKH + 36B pushref, P2PKH + 37B pushref-singleton, P2PKH + multiple pushref tails, truncated tail, P2SH, and pure-pushref (burn-only). Port the firmware classifier logic into Python (or call a Speculos RAM-build harness) and assert every row. Ship it in CI so future shape-helper edits trigger the battery.

### Code Review Checklist

- Does the patch touch input-side parsing (`btchip_apdu_hash_input_finalize_full.c`, `btchip_apdu_hash_input_start.c`)? If yes, do output-side helpers (`output_script_is_regular`, `output_script_p2pkh_offset`, change-detection) get a matching update or an explicit "N/A because…" note?
- For any new allowed script shape, is there a row added to the Glyph shape matrix doc covering input AND output columns?
- Does every new test destination address differ from `changePath`, so the display/approval path is actually exercised? Reject tests that sign-to-self as coverage for output validation.
- Are shape checks length-agnostic in the right way? Confirm the classifier handles scripts longer than 25B when the 25B prefix is valid P2PKH, and rejects scripts where the first 25B only looks P2PKH-shaped by coincidence.
- Does the patch change what the user sees on the display (amount, address, warning)? Manually confirm on Speculos that Glyph-shaped outputs show the correct P2PKH address and flag the pushref tail.
- Are the oracle's expected values in `preimage-vectors.json` and `test_oracle_against_vectors.py` updated to match any new accepted shape, so oracle and firmware stay lockstep?
- Does `finalizeInput` return `SW_TECHNICAL_PROBLEM_2` (0x6F0F) anywhere in the patched path? If so, is it truly unreachable for all documented Glyph shapes, or is it a hidden "silently broken on transfer" trap?
- Is there a burn-spend test AND a transfer-preserving-spend test in the same PR? A Glyph-touching change with only one is incomplete by policy.
