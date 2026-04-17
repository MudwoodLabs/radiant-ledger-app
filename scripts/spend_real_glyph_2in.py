#!/usr/bin/env python3
"""2-input Glyph spend: Glyph UTXO (too small for fees) + plain P2PKH UTXO (covers fees).

Input 0: Glyph UTXO at 1GT2rB99... (path 0'/0/3), value 0.0108 RXD
         scriptPubKey = OP_PUSHINPUTREFSINGLETON <ref36> OP_DROP <P2PKH>
Input 1: Plain P2PKH UTXO at 19sSiN4e... (path 0'/0/2), value 0.05 RXD

Output: Plain P2PKH to 1LkYcHBg... (path 0'/0/0). Fee ~3.5M sats covers
        Radiant's 10k sats/byte min relay for ~340-byte tx.

Glyph NFT is burned (output doesn't carry the ref forward). This test
proves the Ledger correctly signs an input whose scriptCode includes
Glyph opcodes, and mainnet accepts the result.
"""

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

# ----- Input 0: Glyph UTXO -----
IN0_TXID = "6c32fcbbd6834170b3afcb9bbed759eeb21db72fd509790a3cb804c6eb5c0630"
IN0_VOUT = 0
IN0_VALUE = 1_080_000
IN0_SPK_HEX = (
    "d8" +
    "08480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed000000000" +
    "7576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac"
)
IN0_PATH = "44'/512'/0'/0/3"
IN0_EXPECTED_ADDR = "1GT2rB99dRZd919Z1ZkFKZMRijDEu2D7DX"
IN0_PREV_RAW_PATH = "/tmp/glyph_mint_raw.hex"

# ----- Input 1: plain P2PKH UTXO (fee source) -----
IN1_TXID = "e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e"
IN1_VOUT = 0
IN1_VALUE = 5_000_000
IN1_SPK_HEX = "76a914614b44c4786043c88bdd8a3c9df799ba090e3f6088ac"
IN1_PATH = "44'/512'/0'/0/2"
IN1_EXPECTED_ADDR = "19sSiN4eb526fLPUqgY23iiNKYjy7cmV33"
IN1_PREV_RAW_PATH = "/tmp/regtx_raw.hex"

# ----- Output: burn the Glyph, send remainder to 1LkYcHBg -----
DEST_HASH160_HEX = "d8a6a957b97bf1071502e635f4f4ae74e0a279ec"  # 1LkYcHBg (path 0'/0/0)
TOTAL_INPUT = IN0_VALUE + IN1_VALUE  # 6_080_000
FEE = 3_500_000  # ~10k sats/byte for 340-byte tx
OUTPUT_VALUE = TOTAL_INPUT - FEE  # 2_580_000 sats

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


def main():
    print(f"Input 0 (Glyph):  {IN0_TXID}:{IN0_VOUT}  {IN0_VALUE} sats  @ {IN0_PATH}")
    print(f"Input 1 (P2PKH):  {IN1_TXID}:{IN1_VOUT}  {IN1_VALUE} sats  @ {IN1_PATH}")
    print(f"Output: {OUTPUT_VALUE} sats → 1LkYcHBg... ({DEST_HASH160_HEX})")
    print(f"Fee: {FEE} sats\n")

    dongle = getDongle(debug=False)
    app = btchip(dongle)

    addr0, pk0 = derive_pubkey(app, IN0_PATH)
    addr1, pk1 = derive_pubkey(app, IN1_PATH)
    if addr0 != IN0_EXPECTED_ADDR or addr1 != IN1_EXPECTED_ADDR:
        print(f"{RED}ERROR: address mismatch{END}")
        return 1
    print(f"Path 0/3 → {addr0}  pk={pk0.hex()}")
    print(f"Path 0/2 → {addr1}  pk={pk1.hex()}\n")

    # Build dest output
    dest_script = bytes.fromhex(f"76a914{DEST_HASH160_HEX}88ac")

    # Compute oracle sighashes for each input
    tx = Transaction(
        version=2,
        inputs=[
            Input(prev_txid=bytes.fromhex(IN0_TXID), prev_vout=IN0_VOUT,
                  script_sig=b"", sequence=0xfffffffe),
            Input(prev_txid=bytes.fromhex(IN1_TXID), prev_vout=IN1_VOUT,
                  script_sig=b"", sequence=0xfffffffe),
        ],
        outputs=[Output(value=OUTPUT_VALUE, script_pubkey=dest_script)],
        locktime=0,
    )
    oracle_sh0 = compute_radiant_sighash(tx, 0, bytes.fromhex(IN0_SPK_HEX), IN0_VALUE, 0x41)
    oracle_sh1 = compute_radiant_sighash(tx, 1, bytes.fromhex(IN1_SPK_HEX), IN1_VALUE, 0x41)
    print(f"Oracle sighash input 0 (Glyph): {oracle_sh0.hex()}")
    print(f"Oracle sighash input 1 (P2PKH): {oracle_sh1.hex()}\n")

    # ---- Get trusted inputs ----
    prev0_tx = bitcoinTransaction(bytes.fromhex(open(IN0_PREV_RAW_PATH).read().strip()))
    ti0 = app.getTrustedInput(prev0_tx, IN0_VOUT)
    ti0['sequence'] = "feffffff"
    ti0['witness'] = True

    prev1_tx = bitcoinTransaction(bytes.fromhex(open(IN1_PREV_RAW_PATH).read().strip()))
    ti1 = app.getTrustedInput(prev1_tx, IN1_VOUT)
    ti1['sequence'] = "feffffff"
    ti1['witness'] = True

    app.enableAlternate2fa(False)

    chip_inputs = [ti0, ti1]

    # ---- finalizeInput: device hashes all outputs, prompts user ----
    # First pass uses input 0's scriptCode (though for segwit this just establishes hashedOutputs)
    app.startUntrustedTransaction(True, 0, chip_inputs, bytes.fromhex(IN0_SPK_HEX), version=0x02)

    raw_unsigned = (
        u32_le(2) +
        varint_encode(2) +
        bytes.fromhex(IN0_TXID)[::-1] + u32_le(IN0_VOUT) +
        varint_encode(0) + u32_le(0xfffffffe) +
        bytes.fromhex(IN1_TXID)[::-1] + u32_le(IN1_VOUT) +
        varint_encode(0) + u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(OUTPUT_VALUE) + varint_encode(len(dest_script)) + dest_script +
        u32_le(0)
    )

    print(f"{YELLOW}APPROVE on device: 0.0258 RXD → 1LkYcHBg... (fee 0.035 RXD){END}")
    output_data = app.finalizeInput(b"", 0, 0, IN1_PATH, raw_unsigned)

    # ---- Sign each input with its own scriptCode ----
    # Input 0: Glyph UTXO, scriptCode = 63-byte Glyph-P2PKH
    app.startUntrustedTransaction(False, 0, [chip_inputs[0]], bytes.fromhex(IN0_SPK_HEX), version=0x02)
    sig0 = app.untrustedHashSign(IN0_PATH, lockTime=0, sighashType=0x41)
    sig0_der = bytes(sig0[:-1])
    if sig0_der[0] != 0x30: sig0_der = bytes([0x30]) + sig0_der[1:]
    print(f"Device sig input 0: {sig0_der.hex()}")

    # Input 1: plain P2PKH, scriptCode = 25-byte P2PKH
    # inputIndex is position within passedOutputList — list has 1 element at index 0
    app.startUntrustedTransaction(False, 0, [chip_inputs[1]], bytes.fromhex(IN1_SPK_HEX), version=0x02)
    sig1 = app.untrustedHashSign(IN1_PATH, lockTime=0, sighashType=0x41)
    sig1_der = bytes(sig1[:-1])
    if sig1_der[0] != 0x30: sig1_der = bytes([0x30]) + sig1_der[1:]
    print(f"Device sig input 1: {sig1_der.hex()}")

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
    def make_script_sig(sig, pk):
        swh = sig + bytes([0x41])
        return varint_encode(len(swh)) + swh + varint_encode(len(pk)) + pk

    ss0 = make_script_sig(sig0_der, pk0)
    ss1 = make_script_sig(sig1_der, pk1)

    signed_tx = (
        u32_le(2) +
        varint_encode(2) +
        bytes.fromhex(IN0_TXID)[::-1] + u32_le(IN0_VOUT) +
        varint_encode(len(ss0)) + ss0 + u32_le(0xfffffffe) +
        bytes.fromhex(IN1_TXID)[::-1] + u32_le(IN1_VOUT) +
        varint_encode(len(ss1)) + ss1 + u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(OUTPUT_VALUE) + varint_encode(len(dest_script)) + dest_script +
        u32_le(0)
    )

    print(f"\n--- Signed tx ({len(signed_tx)} bytes) ---")
    print(signed_tx.hex())

    # -------------------------------------------------------------------------
    # A1 — post-assembly sighash round-trip check (both inputs).
    # Re-parse the assembled tx and recompute each input's sighash. If it does
    # not match the oracle sighash the device signed, refuse to write out the
    # hex. Catches assembly bugs that would produce a valid-looking signature
    # over bytes that differ from the broadcast payload.
    # -------------------------------------------------------------------------
    from radiant_preimage_oracle import parse_transaction as _parse_tx
    reparsed = _parse_tx(signed_tx)
    rt_sh0 = compute_radiant_sighash(reparsed, 0, bytes.fromhex(IN0_SPK_HEX), IN0_VALUE, 0x41)
    rt_sh1 = compute_radiant_sighash(reparsed, 1, bytes.fromhex(IN1_SPK_HEX), IN1_VALUE, 0x41)
    mismatch = []
    if rt_sh0 != oracle_sh0:
        mismatch.append(f"  vin[0]: oracle={oracle_sh0.hex()} reparsed={rt_sh0.hex()}")
    if rt_sh1 != oracle_sh1:
        mismatch.append(f"  vin[1]: oracle={oracle_sh1.hex()} reparsed={rt_sh1.hex()}")
    if mismatch:
        print(f"\n\033[91m✗ ROUND-TRIP SIGHASH MISMATCH — REFUSING TO WRITE TX\033[0m")
        for m in mismatch: print(m)
        print("  the assembled tx is NOT the tx the device approved")
        return 1
    print(f"\033[92m✓ Round-trip: both inputs re-parse to identical sighashes\033[0m")

    Path("/tmp/glyph_spend_signed_2in.hex").write_text(signed_tx.hex() + "\n")
    print(f"\nSaved to /tmp/glyph_spend_signed_2in.hex")

    return 0


if __name__ == "__main__":
    sys.exit(main())
