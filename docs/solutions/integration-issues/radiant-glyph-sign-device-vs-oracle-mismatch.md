---
name: Ledger Radiant Glyph signing — four-bug device-vs-oracle sighash mismatch
description: Device signed a Glyph-shaped output, signature didn't verify against oracle. Turned out to be four bugs stacked: one device-side, two test-harness-side, one in the vendored btchip. Plain P2PKH kept working throughout, which masked the issues.
type: integration-issue
component: app-radiant, lib-app-bitcoin, Electron-Wallet, radiant-preimage-oracle
severity: medium
resolved: 2026-04-15
related:
  - docs/solutions/integration-issues/radiant-preimage-hashoutputhashes-missing.md
  - docs/plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md
---

# Glyph signing: device sig didn't verify against oracle

## Symptom

After extending the Ledger Radiant app's opcode walker to handle `OP_PUSHINPUTREF` (0xD0) in output scripts, a device-vs-oracle test harness produced:

- Device signs tx without error
- Oracle computes a sighash independently
- Device signature does NOT verify against oracle sighash
- None of 11 hypothesized sighash variants matched the device signature either

**Confusing signal**: plain P2PKH mainnet broadcast (`e10517b5…`) via Electron Radiant kept working on the same v0.0.5 firmware. So the device obviously produced valid Radiant sighashes for *something* — just not what the oracle computed.

## Investigation arc

First attempted fixes — all dead ends:

1. Added `enableAlternate2fa(False)` — Electron Radiant's plugin calls it, my test didn't. No change.
2. Changed version from 1 to 2 — matching regression tx. No change.
3. Set `trusted_input['witness'] = True` — triggers segwit code path (the one that actually inserts hashOutputHashes into the preimage). No change.
4. Added missing `startUntrustedTransaction(newTransaction=False, …)` segwit-continue call. No change.
5. Tried 11 sighash preimage variants (no-refs, BCH-style, single-sha vs double-sha, BE locktime, scriptCode-no-varint, script_len-included-in-scriptHash, etc.). None matched.

**Breakthrough**: ran the same APDU flow with a PLAIN P2PKH output (no Glyph). That test *also* failed verification — proving the bug was in the test harness, not the opcode walker. Then enabled btchip APDU-level debug logging (`getDongle(debug=True)`), captured every byte sent to device, hand-computed the preimage with those exact bytes, and found the discrepancy in `hashPrevouts`.

## Root causes

**Four bugs stacked.** Plain P2PKH mainnet broadcasts worked because Electron Radiant's own plugin avoids all four paths — Glyph required the test harness, which had the bugs.

### Bug 1: device — `output_script_is_regular` hardcoded 25-byte length

[lib-app-bitcoin/customizable_helpers.c:22-24](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/customizable_helpers.c#L22)

```c
const unsigned char TRANSACTION_OUTPUT_SCRIPT_PRE[] = {
    0x19, 0x76, 0xA9, 0x14}; // script length=25, OP_DUP, OP_HASH160, address length
```

The leading `0x19` is the script_len varint (25 decimal). `output_script_is_regular()` `memcmp`s this pattern at offset 0 of the output. A 62-byte Glyph-P2PKH script starts with `0x3E`, not `0x19`, so the memcmp fails. Result: `check_output_displayable()` returns -1 → `SW_TECHNICAL_PROBLEM_2` (0x6F0F) during `finalizeInput`.

### Bug 2: test harness — `prev_txid` double-reversed

[radiant_preimage_oracle.py:103-112](../../scripts/radiant_preimage_oracle.py)

```python
def get_prevout_hash(tx: Transaction) -> bytes:
    w = b""
    for inp in tx.inputs:
        w += inp.prev_txid[::-1]   # reverses to wire-format LE
        ...
```

The oracle's `Input.prev_txid` expects **internal byte order** (display hex). Oracle then reverses it back to LE for the preimage. My test passed `bytes.fromhex(PREV_TXID)[::-1]` — already LE — so it got reversed again and produced the wrong `hashPrevouts`.

### Bug 3: test harness — btchip version default

[btchip.py:202](Electron-Wallet/electroncash_plugins/ledger/vendor/btchip/btchip.py#L202)

```python
def startUntrustedTransaction(self, ..., version=0x01, ...):
```

Default is version=1. My test built a tx with version=2 in the oracle but never overrode btchip's default, so the device signed version=1 while the oracle hashed version=2.

### Bug 4: vendored btchip — `str(bytearray)` yields repr

[btchip.py:128](Electron-Wallet/electroncash_plugins/ledger/vendor/btchip/btchip.py#L128)

```python
result['address'] = str(response[...])  # gives "bytearray(b'19sSi…')"
```

Python 3 quirk. Made the address comparison in my test always fail with a confusing repr string.

## Fixes

### Bug 1 — [lib-app-bitcoin/customizable_helpers.c](https://github.com/Zyrtnin-org/lib-app-bitcoin/blob/radiant-v1/customizable_helpers.c)

Added a Radiant-specific branch inside `output_script_is_regular` that matches the P2PKH opcode pattern at fixed offsets, ignoring the script_len byte:

```c
if (COIN_KIND == COIN_KIND_RADIANT) {
  if (buffer[1] == 0x76 && buffer[2] == 0xA9 && buffer[3] == 0x14 &&
      buffer[24] == 0x88 && buffer[25] == 0xAC) {
    return 1;
  }
}
```

Rebuild + re-sideload → device accepts Glyph-P2PKH outputs.

### Bug 2 — test harness call site

```python
# Before:
Input(prev_txid=bytes.fromhex(PREV_TXID)[::-1], ...)

# After:
Input(prev_txid=bytes.fromhex(PREV_TXID), ...)  # internal byte order (display hex)
```

### Bug 3 — pass version explicitly

```python
app.startUntrustedTransaction(True, 0, chip_inputs, redeem_script, version=0x02)
app.startUntrustedTransaction(False, 0, chip_inputs, redeem_script, version=0x02)
```

### Bug 4 — vendored btchip

```python
# Before:
result['address'] = str(response[offset + 1 : offset + 1 + response[offset]])

# After:
result['address'] = bytes(response[offset + 1 : offset + 1 + response[offset]]).decode('ascii')
```

## Verification

After all four fixes, on v0.0.5 firmware (lib-app-bitcoin@93ec095):

- `test_device_plain_sign.py` — plain P2PKH device sig verifies against oracle ✓
- `test_device_glyph_sign.py` — Glyph output (P2PKH + OP_PUSHINPUTREF + 36-byte fake ref) device sig verifies against oracle sighash `bd9377ab5070d7fe…` ✓
- Electron Radiant plain-P2PKH mainnet broadcast still works (no regression)
- All 5 existing Python oracle fixtures still pass (4 plain P2PKH + 1 real Glyph mainnet tx)

## Prevention

### Write a "plain P2PKH isolation test" FIRST when adding new device features

Before concluding "the new feature is broken," run the same test harness with a known-working baseline input. If the baseline also fails, the harness has a bug. This flipped the entire debugging direction in this session.

### Enable APDU-level debug logging early

`getDongle(debug=True)` prints every APDU sent/received in hex. Five minutes of APDU trace reveals more than hours of guessing at sighash variants. When a sig doesn't verify against any oracle-computed variant, stop inventing more variants — **dump the actual bytes** the device received and compute the preimage from those.

### Make oracle input-format expectations impossible to get wrong

The `Input.prev_txid` ambiguity (internal vs wire byte order) bit me once for the test harness and could bite again. Options:
- Rename to `prev_txid_internal: bytes` and document the format in the type
- Add a `from_wire_bytes` classmethod that does the reversal
- Add a runtime assertion that the txid doesn't start with `00` (display-order txids typically start with leading zeros; wire-order doesn't)

### Don't silently swallow exceptions in vendored libraries

The original `finalizeInput` does `try: … except Exception: pass` around the alternate-encoding path. When it failed with SW 0x6F0F, the swallowed exception made the error invisible — device then fell through to a legacy path that didn't support the APDU, returning 0x6D00. The real error was masked.

Fix: at minimum, log swallowed exceptions. At best, re-raise them — silent fallbacks hide real bugs.

### Match the plugin flow exactly for raw-APDU tests

For future hardware-test harnesses that bypass the wallet GUI, start by reading the plugin's sign_transaction code and mirroring its APDU sequence including every `enableAlternate2fa`, every parameter default, every setup call. Don't skip steps — "should still work" frequently doesn't.

## Files touched

- `lib-app-bitcoin/customizable_helpers.c` — +10 lines, Radiant branch in `output_script_is_regular`
- `scripts/test_device_plain_sign.py` — new, 85 lines
- `scripts/test_device_glyph_sign.py` — new, 220 lines
- `scripts/diagnose_glyph_sig.py` — new, 165 lines (11-variant sighash matcher)
- `Electron-Wallet/electroncash_plugins/ledger/vendor/btchip/btchip.py` — 1-char fix for address decode

## Commits

- lib-app-bitcoin@93ec095 — `fix(radiant): allow P2PKH-prefixed scripts of any length in check_output_displayable`
- app-radiant@dd11364 — submodule pointer update
- radiant-ledger-app@3a11329 — `feat: add device-vs-oracle test harnesses for Glyph + plain P2PKH signing`
