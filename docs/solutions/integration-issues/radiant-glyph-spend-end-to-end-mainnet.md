---
name: Ledger Radiant Glyph-UTXO spend — end-to-end mainnet proof
description: How to drive the Ledger via direct APDU to spend a real mainnet Glyph NFT UTXO. Covers multi-input signing quirks, Radiant's fee minimum, and byte-level preimage construction. Result is mainnet-accepted tx 22d4e0e07200…
type: integration-issue
component: app-radiant, lib-app-bitcoin, btchip-python, radiant-preimage-oracle
severity: low
resolved: 2026-04-16
related:
  - docs/solutions/integration-issues/radiant-glyph-sign-device-vs-oracle-mismatch.md
  - docs/solutions/integration-issues/radiant-preimage-hashoutputhashes-missing.md
  - docs/plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md
---

# End-to-end Glyph-UTXO spend on Radiant mainnet with a Ledger

## Context

After fixing the opcode walker and validating device-vs-oracle for fake-ref Glyph outputs, we wanted mainnet-consensus proof: a Ledger-signed tx that SPENDS a real Glyph NFT UTXO, accepted by Radiant validators.

## The test

**Setup**: FlipperHub minted a photo Glyph NFT to Ledger address `1GT2rB99dRZd919Z1ZkFKZMRijDEu2D7DX` (path `m/44'/512'/0'/0/3`). Mint tx: `6c32fcbbd6834170b3afcb9bbed759eeb21db72fd509790a3cb804c6eb5c0630:0`.

The Glyph UTXO scriptPubKey (63 bytes) was:

```
d8                                                                        OP_PUSHINPUTREFSINGLETON
08480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed000000000  36B ref
75                                                                        OP_DROP
76a914 a9763e88160a63a3f03bf846268ed0fb8abd8b55 88ac                      P2PKH to 1GT2rB99...
```

**Test goal**: Ledger signs a tx spending this Glyph UTXO. Output is plain P2PKH (Glyph burned, ref discarded). Mainnet accepts it.

**Result**: mainnet tx [`22d4e0e07200437791b48651125a636b994593b215152241aef7113b24b71da3`](https://explorer.radiantblockchain.org/tx/22d4e0e07200437791b48651125a636b994593b215152241aef7113b24b71da3).

## Three practical gotchas

### Gotcha 1: Electron Radiant doesn't recognize Glyph UTXOs

Electron Cash's script classifier checks for standard scriptPubKey shapes (P2PKH, P2SH, OP_RETURN). A 63-byte Glyph-prefixed P2PKH doesn't match, so the wallet treats it as "unknown script type" and never associates the UTXO with the owning address. The UTXO doesn't appear in the Coins tab.

**Consequence**: you can't use the GUI to spend a Glyph UTXO. You need direct-APDU tooling.

**Fix** (beyond this doc): Electron Radiant's script parser needs a rule like "if script contains a valid P2PKH subsequence at offsets +38..+62 and the leading bytes are a standard Glyph wrapper (OP_PUSHINPUTREF* + ref36 + OP_DROP), treat the address as the P2PKH hash". Not done in this session — scope was Ledger-side support.

### Gotcha 2: Radiant's 10k sats/byte min relay is punishing for small UTXOs

Radiant's `getnetworkinfo` reports `relayfee: 0.1 RXD/kB`, which parses as 10,000 sats/byte. Extremely high vs Bitcoin's 1 sat/byte.

```
Our Glyph UTXO: 1,080,000 sats (0.0108 RXD)
1-input 1-output tx size: ~191 bytes
Required fee: 191 × 10,000 = 1,910,000 sats
Max possible output: 1,080,000 − 1,910,000 = NEGATIVE
```

**The Glyph UTXO alone cannot pay its own spend fee.** You need a second input to cover the fee gap.

```python
IN0_VALUE = 1_080_000    # Glyph UTXO (spends the ref)
IN1_VALUE = 5_000_000    # Plain P2PKH (covers fee)
FEE = 3_500_000          # ~10,355 sats/byte for 338-byte 2-in 1-out tx
OUTPUT = IN0_VALUE + IN1_VALUE - FEE   # 2_580_000
```

### Gotcha 3: btchip's `inputIndex` is position-within-list, not position-in-tx

When signing a multi-input tx via direct APDU, the per-input signing loop looks like:

```python
# Setup: all inputs passed once
app.startUntrustedTransaction(True, 0, [ti0, ti1], scriptCode0, version=0x02)
app.finalizeInput(b"", 0, 0, changePath, raw_unsigned)

# Sign each input separately — one input at a time in the list
for i in range(2):
    app.startUntrustedTransaction(False, 0, [chip_inputs[i]], scriptCode_i, version=0x02)
    #                                     ^-- inputIndex=0 (position in THIS list), NOT i
    sig = app.untrustedHashSign(paths[i], lockTime=0, sighashType=0x41)
```

Reading the btchip source ([btchip.py:242](Electron-Wallet/electroncash_plugins/ledger/vendor/btchip/btchip.py#L242)):

```python
currentIndex = 0
for passedOutput in outputList:
    ...
    if currentIndex != inputIndex:
        script = bytearray()  # empty — don't attach scriptCode
    writeVarint(len(script), params)
    ...
    currentIndex += 1
```

If you pass a list of one input but `inputIndex=1`, the loop's `currentIndex` is 0, the condition `0 != 1` is true, and the scriptCode silently becomes empty. The device then signs a broken preimage.

**Symptom**: signature doesn't verify against oracle for the second input, even though the first input worked.

**Fix**: always use `inputIndex=0` when passing a singleton list during per-input signing.

## Working multi-input Glyph spend harness

Full working script at [scripts/spend_real_glyph_2in.py](scripts/spend_real_glyph_2in.py). Key sequence:

```python
dongle = getDongle(debug=False)
app = btchip(dongle)

# Get trusted inputs for BOTH prev-txs (Glyph mint parent + plain P2PKH parent)
ti0 = app.getTrustedInput(glyph_mint_tx, 0)
ti0['sequence'] = "feffffff"; ti0['witness'] = True

ti1 = app.getTrustedInput(plain_p2pkh_tx, 0)
ti1['sequence'] = "feffffff"; ti1['witness'] = True

app.enableAlternate2fa(False)

# First pass: setup + finalizeInput over BOTH trusted inputs
app.startUntrustedTransaction(True, 0, [ti0, ti1], scriptCode0, version=0x02)
app.finalizeInput(b"", 0, 0, PATH_FOR_CHANGEPATH_SLOT, raw_unsigned_tx)

# Per-input sign. inputIndex=0 because list has 1 element at index 0.
app.startUntrustedTransaction(False, 0, [ti0], glyph_scriptpubkey_63B, version=0x02)
sig0 = app.untrustedHashSign(path0, lockTime=0, sighashType=0x41)

app.startUntrustedTransaction(False, 0, [ti1], plain_p2pkh_scriptpubkey, version=0x02)
sig1 = app.untrustedHashSign(path1, lockTime=0, sighashType=0x41)
```

**Oracle verification** (done before broadcast) confirms each sig against its expected sighash:

```python
vk = VerifyingKey.from_string(pubkey_compressed, curve=SECP256k1)
vk.verify_digest(sig_der, oracle_computed_sighash, sigdecode=sigdecode_der)
```

If both sigs verify → safe to broadcast.

## What this proves

| Assertion | Evidence |
|---|---|
| Ledger v0.0.5 signs scriptCode with Glyph opcodes correctly | Oracle sig verification for input 0 |
| Radiant consensus accepts the Ledger's signature | Tx entered mempool (txid `22d4e0e0…`) |
| Multi-input signing via direct APDU works | 338-byte 2-in 1-out tx accepted |
| Fee math for Radiant is 10,000 sats/byte | `3_500_000 / 338 ≈ 10_355` accepted |

Combined with earlier phase 1.5 work (hashOutputHashes insertion) and the device-vs-oracle test for output-side push-ref walking, this completes the Glyph v1.0 proof chain.

## Prevention / best practices

### Always verify sigs against oracle before broadcasting anything non-trivial

Broadcasting sends RXD to miners' fee pool and burns UTXOs. Mainnet doesn't give good feedback on *why* a tx is rejected — just "min relay fee not met" or "script-execution-error". Oracle verification catches bugs locally.

### Cap fees aggressively for test txs

Radiant's fee market is unusually high (10k sats/byte min relay). A "normal" 500-byte tx costs 5M sats = 0.05 RXD. Factor this into any test-value sizing: if you want to do 5 tests, keep 0.3 RXD+ on hand per test chain.

### Set up a clean privacy domain BEFORE mainnet experimentation

Our session linked `1GT2rB99` (FlipperHub-fundedx) with `19sSiN4eb` (traced to operator/main via Ledger UTXO chain) by combining them in a single tx input-set. If privacy matters, fund test addresses from sources that don't share a cluster with your main identity.

### Electron Radiant should learn Glyph shapes

For broader Glyph UX, the wallet needs a script parser rule:

```python
def glyph_p2pkh_address(script_bytes):
    if len(script_bytes) < 25: return None
    # Check for Glyph wrapper: (push-ref-opcode + 36B ref + OP_DROP)* + P2PKH
    p2pkh_offset = find_p2pkh_tail_offset(script_bytes)
    if p2pkh_offset is None: return None
    tail = script_bytes[p2pkh_offset:]
    if tail[:3] == b'\x76\xa9\x14' and tail[23:] == b'\x88\xac':
        return base58_encode_p2pkh(tail[3:23])
    return None
```

This would make Glyph UTXOs spendable via the normal Send UI.

## References

- Mainnet test result tx: [`22d4e0e07200437791b48651125a636b994593b215152241aef7113b24b71da3`](https://explorer.radiantblockchain.org/tx/22d4e0e07200437791b48651125a636b994593b215152241aef7113b24b71da3)
- Glyph UTXO spent: `6c32fcbbd6834170b3afcb9bbed759eeb21db72fd509790a3cb804c6eb5c0630:0` (0.0108 RXD)
- Fee-source UTXO: `e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e:0` (0.05 RXD)
- Device-vs-oracle validation: [scripts/spend_real_glyph_2in.py](scripts/spend_real_glyph_2in.py)
- Firmware: lib-app-bitcoin@93ec095 (v0.0.5)
- Related fix doc (4-bug sighash mismatch): [radiant-glyph-sign-device-vs-oracle-mismatch.md](radiant-glyph-sign-device-vs-oracle-mismatch.md)
