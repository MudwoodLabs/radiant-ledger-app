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

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Transaction, Input, Output, compute_radiant_sighash,
    u32_le, u64_le, varint_encode,
)
from _spend_helpers import (
    GREEN, RED, YELLOW, END,
    derive_pubkey, load_trusted_input, process_device_sig,
    make_script_sig, verify_oracle_sigs, check_round_trip_sighash,
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

    # ---- Get trusted inputs (H-6: integrity check before USB exchange) ----
    ti0 = load_trusted_input(app, IN0_PREV_RAW_PATH, IN0_TXID, IN0_VOUT, "input 0 (Glyph)")
    if ti0 is None:
        return 1
    ti1 = load_trusted_input(app, IN1_PREV_RAW_PATH, IN1_TXID, IN1_VOUT, "input 1 (P2PKH)")
    if ti1 is None:
        return 1

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

    # ---- Sign each input (C-1 + C-3 + H-9 enforced inside process_device_sig) ----
    # Input 0: Glyph UTXO, scriptCode = 63-byte Glyph-P2PKH
    app.startUntrustedTransaction(False, 0, [chip_inputs[0]], bytes.fromhex(IN0_SPK_HEX), version=0x02)
    sig0 = app.untrustedHashSign(IN0_PATH, lockTime=0, sighashType=0x41)
    sig0_der, sig0_sighash = process_device_sig(sig0, label="input 0 (Glyph)")
    print(f"Device sig input 0: {sig0_der.hex()} (sighash 0x{sig0_sighash:02x})")

    # Input 1: plain P2PKH, scriptCode = 25-byte P2PKH
    app.startUntrustedTransaction(False, 0, [chip_inputs[1]], bytes.fromhex(IN1_SPK_HEX), version=0x02)
    sig1 = app.untrustedHashSign(IN1_PATH, lockTime=0, sighashType=0x41)
    sig1_der, sig1_sighash = process_device_sig(sig1, label="input 1 (P2PKH)")
    print(f"Device sig input 1: {sig1_der.hex()} (sighash 0x{sig1_sighash:02x})")

    dongle.close()

    # ---- Verify against oracle ----
    if not verify_oracle_sigs([
        (sig0_der, oracle_sh0, pk0, "Glyph"),
        (sig1_der, oracle_sh1, pk1, "P2PKH"),
    ]):
        return 1

    # ---- Assemble signed tx ----
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
        u64_le(OUTPUT_VALUE) + varint_encode(len(dest_script)) + dest_script +
        u32_le(0)
    )

    print(f"\n--- Signed tx ({len(signed_tx)} bytes) ---")
    print(signed_tx.hex())

    # ---- A1: round-trip sighash check before writing ----
    if not check_round_trip_sighash(
        signed_tx,
        [IN0_SPK_HEX, IN1_SPK_HEX],
        [IN0_VALUE, IN1_VALUE],
        [oracle_sh0, oracle_sh1],
    ):
        return 1

    Path("/tmp/glyph_spend_signed_2in.hex").write_text(signed_tx.hex() + "\n")
    print(f"\nSaved to /tmp/glyph_spend_signed_2in.hex")

    return 0


if __name__ == "__main__":
    sys.exit(main())
