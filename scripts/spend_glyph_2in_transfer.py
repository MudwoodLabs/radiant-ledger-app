#!/usr/bin/env python3
"""2-input Glyph TRANSFER (ref-preserving): move a Glyph NFT from one Ledger
address to another Ledger address on the same device, keeping the singleton
ref on the output so the new owner still holds the NFT.

STATUS (2026-04-16): BLOCKED by Radiant Ledger app firmware (v0.0.7).
The device's `check_output_displayable()` / `output_script_is_regular()` only
accepts plain 25-byte P2PKH as a valid output shape. A Glyph-P2PKH output
(63 bytes starting with `d8 <ref36> 75 <P2PKH>`) fails the shape check and
the device returns SW_TECHNICAL_PROBLEM_2 (0x6F0F) during finalizeInput —
before any signing can occur. Even with `changePath` matching the Glyph
output's P2PKH tail, the shape check runs first.

See docs/solutions/integration-issues/radiant-glyph-sign-device-vs-oracle-mismatch.md
Bug 1 for the input-side equivalent and its patch. An analogous patch for
the output-side check (accept `d8 <ref> 75 <25B-P2PKH>` alongside plain
P2PKH) would unblock this script.

Once the firmware is updated and re-sideloaded, this script should run end
to end. Everything on the script side (sighash, signing, verification) is
correct — only the device display-approval check is rejecting.

Differs from spend_glyph_2in_v2.py (the "burn" variant) in the output layout:

  burn:      OUT0 = plain P2PKH                              (NFT destroyed)
  transfer:  OUT0 = d8 <ref36> 75 <P2PKH_dest>               (NFT moves)
             OUT1 = P2PKH change back to fee-source addr     (returns leftover)

Fee model (mainnet, post-V2): ~411-byte tx at 10,000 sats/byte = ~4.1M sats.
We budget 4.5M to leave safety margin.

Input 0: Glyph UTXO at 1GT2rB99... (path 0'/0/3), value 1,080,000 sats
         scriptPubKey = OP_PUSHINPUTREFSINGLETON <ref36> OP_DROP <P2PKH>
Input 1: Plain P2PKH UTXO at 19sSiN4e... (path 0'/0/2), value 5,000,000 sats

Output 0: Glyph-preserving at path 0'/0/5 (destination), value 10,000 sats
Output 1: P2PKH change at path 0'/0/2 (fee-source), value 1,570,000 sats
Fee: 4,500,000 sats

The 36-byte ref on OUT0 is the SAME ref as on IN0 — that's what makes this a
transfer rather than a burn. Radiant's singleton rules require exactly one
output in the tx to carry this ref for the spend to be valid.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "apps/Electron-Wallet/electroncash_plugins/ledger/vendor"))
from btchip.btchip import btchip
from btchip.btchipComm import getDongle
from btchip.bitcoinTransaction import bitcoinTransaction

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Transaction, Input, Output, compute_radiant_sighash,
    u32_le, u64_le, varint_encode,
)

# ----- Input 0: Glyph UTXO (new NFT) -----
IN0_TXID = "c16c513853653125ea12d10d01e7129c419038c6d07f889606d6e23abf307a8c"
IN0_VOUT = 0
IN0_VALUE = 1_080_000
IN0_SPK_HEX = (
    "d8"
    "649b6851df249b239c6c5ca0e85d8e4ea2335176d3bde26d3de3eb229c134854"  # 32-byte txid (reversed)
    "00000000"                                                          # 4-byte vout LE
    "75"                                                                # OP_DROP
    "76a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac"                # P2PKH for 1GT2rB99...
)
IN0_PATH = "44'/512'/0'/0/3"
IN0_EXPECTED_ADDR = "1GT2rB99dRZd919Z1ZkFKZMRijDEu2D7DX"
IN0_PREV_RAW_PATH = "/tmp/glyph_mint_raw_v3.hex"

# The 36-byte singleton ref (txid reversed + vout LE) — must appear verbatim on OUT0.
IN0_REF_HEX = "649b6851df249b239c6c5ca0e85d8e4ea2335176d3bde26d3de3eb229c13485400000000"
assert len(IN0_REF_HEX) == 72, "ref must be 72 hex chars (36 bytes)"

# ----- Input 1: plain P2PKH UTXO (fee source) -----
IN1_TXID = "0a0945778af57dcbba99c9968ac766ef2b3ce9ffc13ddf4606dae46766f6ac5a"
IN1_VOUT = 0
IN1_VALUE = 5_000_000
IN1_SPK_HEX = "76a914614b44c4786043c88bdd8a3c9df799ba090e3f6088ac"
IN1_PATH = "44'/512'/0'/0/2"
IN1_EXPECTED_ADDR = "19sSiN4eb526fLPUqgY23iiNKYjy7cmV33"
IN1_PREV_RAW_PATH = "/tmp/regtx_raw_v3.hex"

# ----- Destination (NFT goes here) -----
# Derived from Ledger at DEST_PATH at runtime; we verify the derived address
# looks sensible before signing.
DEST_PATH = "44'/512'/0'/0/5"

# ----- Change (fee-source leftover goes back here) -----
# Reuse the fee-source address (path 0/2) — avoids a third derivation.
CHANGE_HASH160_HEX = "614b44c4786043c88bdd8a3c9df799ba090e3f60"

# ----- Amounts -----
# Single-output transfer: all remaining value after fee goes into the NFT
# output. Skipping the P2PKH change output because the Radiant Ledger app's
# output display/approval path chokes with 6f0f when it sees 2 outputs —
# the working test_device_glyph_sign.py pattern uses exactly one Glyph output.
FEE = 4_200_000                                        # ~11,140 sats/byte for actual ~377-byte tx
NFT_OUTPUT_VALUE = IN0_VALUE + IN1_VALUE - FEE          # 3,080,000 locked into the NFT
CHANGE_VALUE = 0

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; END = "\033[0m"


def derive_pubkey(app, path):
    info = app.getWalletPublicKey(path)
    pk_raw = bytes(info['publicKey'])
    if pk_raw[0] == 0x04:
        y = pk_raw[33:65]
        pk_compressed = bytes([0x02 + (y[-1] & 1)]) + pk_raw[1:33]
    else:
        pk_compressed = pk_raw
    return info['address'], pk_compressed


def hash160(pk: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(pk).digest()).digest()


def main():
    if IN1_TXID == "REPLACE_WITH_FUNDING_TXID":
        print(f"{RED}ERROR: IN1_TXID still placeholder — fund 19sSiN4e... and patch this file before running.{END}")
        return 1

    print(f"Input 0 (Glyph):  {IN0_TXID}:{IN0_VOUT}  {IN0_VALUE} sats  @ {IN0_PATH}")
    print(f"Input 1 (P2PKH):  {IN1_TXID}:{IN1_VOUT}  {IN1_VALUE} sats  @ {IN1_PATH}")
    print(f"Output 0 (Glyph, preserving ref):  {NFT_OUTPUT_VALUE} sats → dest path {DEST_PATH}")
    print(f"Fee:                                {FEE} sats\n")

    dongle = getDongle(debug=False)
    app = btchip(dongle)

    addr0, pk0 = derive_pubkey(app, IN0_PATH)
    addr1, pk1 = derive_pubkey(app, IN1_PATH)
    addr_dest, pk_dest = derive_pubkey(app, DEST_PATH)
    if addr0 != IN0_EXPECTED_ADDR or addr1 != IN1_EXPECTED_ADDR:
        print(f"{RED}ERROR: input address mismatch{END}")
        return 1
    dest_h160 = hash160(pk_dest)
    print(f"Path 0/3 → {addr0}  pk={pk0.hex()}")
    print(f"Path 0/2 → {addr1}  pk={pk1.hex()}")
    print(f"Path 0/5 → {addr_dest}  pk={pk_dest.hex()}")
    print(f"          hash160={dest_h160.hex()}\n")

    # Build OUT0: Glyph-preserving. Same ref that's on IN0, new P2PKH tail.
    nft_out_script = bytes.fromhex(
        "d8" + IN0_REF_HEX + "75" + "76a914" + dest_h160.hex() + "88ac"
    )
    assert len(nft_out_script) == 63, f"unexpected NFT script length {len(nft_out_script)}"

    # Build OUT1: plain P2PKH change back to fee-source addr.
    change_script = bytes.fromhex(f"76a914{CHANGE_HASH160_HEX}88ac")

    # Single-output layout: the Radiant Ledger app only cleanly handles txs
    # where every output either matches changePath or is plain P2PKH/standard.
    # With 2 outputs (Glyph + change), even setting changePath to the Glyph
    # output's P2PKH tail still triggered 6f0f on the output-streaming APDU —
    # the app's display parser iterates all outputs. With 1 output that
    # matches changePath, the whole set is treated as change and no display
    # is attempted, which is the pattern `test_device_glyph_sign.py` uses.
    outputs = [
        Output(value=NFT_OUTPUT_VALUE, script_pubkey=nft_out_script),
    ]

    # Compute oracle sighashes for each input
    tx = Transaction(
        version=2,
        inputs=[
            Input(prev_txid=bytes.fromhex(IN0_TXID), prev_vout=IN0_VOUT,
                  script_sig=b"", sequence=0xfffffffe),
            Input(prev_txid=bytes.fromhex(IN1_TXID), prev_vout=IN1_VOUT,
                  script_sig=b"", sequence=0xfffffffe),
        ],
        outputs=outputs,
        locktime=0,
    )
    oracle_sh0 = compute_radiant_sighash(tx, 0, bytes.fromhex(IN0_SPK_HEX), IN0_VALUE, 0x41)
    oracle_sh1 = compute_radiant_sighash(tx, 1, bytes.fromhex(IN1_SPK_HEX), IN1_VALUE, 0x41)
    print(f"Oracle sighash input 0 (Glyph): {oracle_sh0.hex()}")
    print(f"Oracle sighash input 1 (P2PKH): {oracle_sh1.hex()}\n")

    # ---- Get trusted inputs ----
    # H-6 (audit 2026-04-25): verify the on-disk prev-tx hex actually hashes
    # to IN0_TXID / IN1_TXID before feeding it to getTrustedInput. A stale or
    # tampered hex file would silently produce a trusted-input over the wrong
    # UTXO; the round-trip sighash check at the end catches the resulting
    # broken signature, but failing here gives a clearer diagnosis and avoids
    # any USB exchange with the device for an obviously-wrong input.
    import hashlib as _h
    def _sha256d(b: bytes) -> bytes:
        return _h.sha256(_h.sha256(b).digest()).digest()

    prev0_raw = bytes.fromhex(open(IN0_PREV_RAW_PATH).read().strip())
    _calc_txid0 = _sha256d(prev0_raw)[::-1].hex()
    if _calc_txid0 != IN0_TXID.lower():
        print(f"{RED}✗ prev-tx integrity FAIL for input 0:{END}")
        print(f"  file {IN0_PREV_RAW_PATH} hashes to {_calc_txid0}")
        print(f"  expected {IN0_TXID}")
        print(f"  refusing to call getTrustedInput on a substituted prev-tx")
        return 1
    prev0_tx = bitcoinTransaction(prev0_raw)
    ti0 = app.getTrustedInput(prev0_tx, IN0_VOUT)
    ti0['sequence'] = "feffffff"
    ti0['witness'] = True

    prev1_raw = bytes.fromhex(open(IN1_PREV_RAW_PATH).read().strip())
    _calc_txid1 = _sha256d(prev1_raw)[::-1].hex()
    if _calc_txid1 != IN1_TXID.lower():
        print(f"{RED}✗ prev-tx integrity FAIL for input 1:{END}")
        print(f"  file {IN1_PREV_RAW_PATH} hashes to {_calc_txid1}")
        print(f"  expected {IN1_TXID}")
        return 1
    prev1_tx = bitcoinTransaction(prev1_raw)
    ti1 = app.getTrustedInput(prev1_tx, IN1_VOUT)
    ti1['sequence'] = "feffffff"
    ti1['witness'] = True

    app.enableAlternate2fa(False)

    chip_inputs = [ti0, ti1]

    # ---- finalizeInput: device hashes all outputs, prompts user ----
    app.startUntrustedTransaction(True, 0, chip_inputs, bytes.fromhex(IN0_SPK_HEX), version=0x02)

    raw_unsigned = (
        u32_le(2) +
        varint_encode(2) +                                     # input count
        bytes.fromhex(IN0_TXID)[::-1] + u32_le(IN0_VOUT) +
        varint_encode(0) + u32_le(0xfffffffe) +
        bytes.fromhex(IN1_TXID)[::-1] + u32_le(IN1_VOUT) +
        varint_encode(0) + u32_le(0xfffffffe) +
        varint_encode(1) +                                     # output count (single-output)
        u64_le(NFT_OUTPUT_VALUE) + varint_encode(len(nft_out_script)) + nft_out_script +
        u32_le(0)
    )

    # Drive the finalize APDUs directly (bypass btchip's try/except that
    # silently swallows errors and falls back to an unsupported old-style
    # instruction). The Radiant Ledger app wants DEST_PATH (whose pubkey
    # matches OUT0's P2PKH tail) announced as "change path" so OUT0 is
    # hashed silently; only OUT1 is shown to the user for approval.
    from btchip.bitcoinTransaction import bitcoinTransaction as _BTx
    from btchip.btchip import parse_bip32_path
    _parsed = _BTx(bytearray(raw_unsigned))
    _outputs_ser = _parsed.serializeOutputs()
    _change_path_bytes = parse_bip32_path(DEST_PATH)

    # (1) Announce change path — INS_HASH_INPUT_FINALIZE_FULL with p1=0xFF
    _apdu1 = [
        app.BTCHIP_CLA, app.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL,
        0xFF, 0x00,
    ]
    _params = list(_change_path_bytes)
    _apdu1.append(len(_params))
    _apdu1.extend(_params)
    print(f"  → change-path announce APDU ({len(_apdu1)} B)")
    _ = dongle.exchange(bytearray(_apdu1))

    # (2) Stream serialized outputs in chunks of scriptBlockLength
    print(f"{YELLOW}APPROVE on device: single output to {addr_dest} (matches changePath → treated as change, no user prompt expected), fee {FEE/1e8:.8f} RXD{END}")
    _block = app.scriptBlockLength
    _offset = 0
    _response = b""
    while _offset < len(_outputs_ser):
        _chunk_end = min(_offset + _block, len(_outputs_ser))
        _is_last = _chunk_end == len(_outputs_ser)
        _p1 = 0x80 if _is_last else 0x00
        _chunk = _outputs_ser[_offset:_chunk_end]
        _apdu2 = [
            app.BTCHIP_CLA, app.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL,
            _p1, 0x00, len(_chunk),
        ]
        _apdu2.extend(_chunk)
        _response = dongle.exchange(bytearray(_apdu2))
        _offset = _chunk_end
    output_data = {'outputData': _outputs_ser}

    # ---- Sign each input with its own scriptCode ----
    # C-1 + C-3 + H-9 (audit 2026-04-25):
    #   C-1: read the device-returned sighash byte, assert it matches what we
    #        asked for (0x41). Previously the assembly path hardcoded 0x41 in
    #        make_script_sig() regardless of what the device returned —
    #        a future firmware that returned a different byte would silently
    #        broadcast an invalid signature.
    #   H-9: a sig whose first byte isn't 0x30 used to be silently rewritten
    #        to start with 0x30. That masks corruption. Refuse instead.
    #   C-3: low-S normalization. Device firmware should return canonical
    #        low-S, but Radiant's STRICTENC consensus rule rejects high-S on
    #        broadcast — fail-and-broadcast costs a fee + a confusing debug.
    from ecdsa.util import sigdecode_der as _sigdecode_der, sigencode_der as _sigencode_der
    from ecdsa.curves import SECP256k1 as _C256
    _N = _C256.order
    _HALF_N = _N // 2

    def _process_device_sig(sig: bytes, expected_sighash: int = 0x41, label: str = "") -> tuple[bytes, int]:
        """Returns (canonical_low_S_der, device_sighash_byte). Aborts on protocol violations."""
        device_sighash = sig[-1]
        assert device_sighash == expected_sighash, (
            f"Device returned sighash 0x{device_sighash:02x} for {label}, expected 0x{expected_sighash:02x}. "
            f"Refusing to silently rewrite — investigate firmware version or wrong-app-open."
        )
        sig_der = bytes(sig[:-1])
        if sig_der[0] != 0x30:
            raise RuntimeError(
                f"Non-DER signature from device for {label} (first byte 0x{sig_der[0]:02x}); "
                f"refusing to fabricate prefix."
            )
        # Low-S normalization
        r, s = _sigdecode_der(sig_der, _N)
        if s > _HALF_N:
            print(f"  ! device returned high-S sig for {label}; flipping to canonical low-S")
            s = _N - s
            sig_der = _sigencode_der(r, s, _N)
        assert s <= _HALF_N, "low-S invariant violated after flip"
        return sig_der, device_sighash

    # Input 0: Glyph UTXO, scriptCode = 63-byte Glyph-P2PKH (Constraint C)
    app.startUntrustedTransaction(False, 0, [chip_inputs[0]], bytes.fromhex(IN0_SPK_HEX), version=0x02)
    sig0 = app.untrustedHashSign(IN0_PATH, lockTime=0, sighashType=0x41)
    sig0_der, sig0_sighash = _process_device_sig(sig0, expected_sighash=0x41, label="input 0 (Glyph)")
    print(f"Device sig input 0: {sig0_der.hex()} (sighash 0x{sig0_sighash:02x})")

    # Input 1: plain P2PKH, scriptCode = 25-byte P2PKH
    app.startUntrustedTransaction(False, 0, [chip_inputs[1]], bytes.fromhex(IN1_SPK_HEX), version=0x02)
    sig1 = app.untrustedHashSign(IN1_PATH, lockTime=0, sighashType=0x41)
    sig1_der, sig1_sighash = _process_device_sig(sig1, expected_sighash=0x41, label="input 1 (P2PKH)")
    print(f"Device sig input 1: {sig1_der.hex()} (sighash 0x{sig1_sighash:02x})")

    dongle.close()

    # ---- Verify against oracle ----
    import ecdsa
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.util import sigdecode_der
    for i, (sig, sh, pk, label) in enumerate([(sig0_der, oracle_sh0, pk0, "Glyph"), (sig1_der, oracle_sh1, pk1, "P2PKH")]):
        vk = VerifyingKey.from_string(pk, curve=SECP256k1)
        try:
            vk.verify_digest(sig, sh, sigdecode=sigdecode_der)
            print(f"{GREEN}✓ input {i} ({label}) sig verifies against oracle sighash{END}")
        except ecdsa.BadSignatureError:
            print(f"{RED}✗ input {i} ({label}) sig FAILS against oracle{END}")
            return 1

    # ---- Assemble signed tx ----
    # C-1: append the *device-returned* sighash byte (already asserted == 0x41
    # in _process_device_sig). Previously hardcoded 0x41 — see C-1 comment above.
    def make_script_sig(sig, pk, sighash_byte):
        swh = sig + bytes([sighash_byte])
        return varint_encode(len(swh)) + swh + varint_encode(len(pk)) + pk

    ss0 = make_script_sig(sig0_der, pk0, sig0_sighash)
    ss1 = make_script_sig(sig1_der, pk1, sig1_sighash)

    signed_tx = (
        u32_le(2) +
        varint_encode(2) +
        bytes.fromhex(IN0_TXID)[::-1] + u32_le(IN0_VOUT) +
        varint_encode(len(ss0)) + ss0 + u32_le(0xfffffffe) +
        bytes.fromhex(IN1_TXID)[::-1] + u32_le(IN1_VOUT) +
        varint_encode(len(ss1)) + ss1 + u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(NFT_OUTPUT_VALUE) + varint_encode(len(nft_out_script)) + nft_out_script +
        u32_le(0)
    )

    print(f"\n--- Signed tx ({len(signed_tx)} bytes) ---")
    print(signed_tx.hex())

    # H-3 (audit 2026-04-25): post-assembly sighash round-trip check.
    # Re-parse the assembled signed_tx bytes and recompute the sighash for each
    # input. If it doesn't match the oracle sighash that the device signed, the
    # tx we're about to broadcast is NOT the tx that was approved — refuse to
    # write it out. Catches assembly bugs that would otherwise produce a valid-
    # looking signature over bytes that differ from the broadcast payload.
    # Already shipped in spend_real_glyph_2in.py:198+ via commit bfc8b0f; this
    # is the matching port to the canonical mainnet-tested transfer script.
    from radiant_preimage_oracle import parse_transaction as _parse_tx
    reparsed = _parse_tx(signed_tx)
    rt_sh0 = compute_radiant_sighash(reparsed, 0, bytes.fromhex(IN0_SPK_HEX), IN0_VALUE, 0x41)
    rt_sh1 = compute_radiant_sighash(reparsed, 1, bytes.fromhex(IN1_SPK_HEX), IN1_VALUE, 0x41)
    if rt_sh0 != oracle_sh0 or rt_sh1 != oracle_sh1:
        print(f"\n{RED}✗ ROUND-TRIP SIGHASH MISMATCH — REFUSING TO BROADCAST{END}")
        if rt_sh0 != oracle_sh0:
            print(f"  input 0: oracle {oracle_sh0.hex()}  reparsed {rt_sh0.hex()}")
        if rt_sh1 != oracle_sh1:
            print(f"  input 1: oracle {oracle_sh1.hex()}  reparsed {rt_sh1.hex()}")
        print(f"  the assembled tx is NOT the tx the device approved")
        return 1
    print(f"{GREEN}✓ Round-trip: re-parsed signed_tx produces identical sighashes for both inputs{END}")

    Path("/tmp/glyph_transfer_signed.hex").write_text(signed_tx.hex() + "\n")
    print(f"\nSaved to /tmp/glyph_transfer_signed.hex")
    print(f"\nTo broadcast:")
    print(f"  ssh $VPS 'docker exec radiant-mainnet radiant-cli -datadir=/home/radiant/.radiant sendrawtransaction {signed_tx.hex()[:60]}...'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
