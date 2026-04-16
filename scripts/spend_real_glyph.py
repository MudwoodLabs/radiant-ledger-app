#!/usr/bin/env python3
"""End-to-end mainnet test: spend a real Glyph UTXO held by the Ledger.

Parent mint tx: 6c32fcbbd6834170b3afcb9bbed759eeb21db72fd509790a3cb804c6eb5c0630
  vout[0]: value=0.0108 RXD, spk = OP_PUSHINPUTREFSINGLETON <ref36> OP_DROP <P2PKH to 1GT2rB99...>
  Ledger path for 1GT2rB99...: m/44'/512'/0'/0/3

We spend that UTXO back to 1LkYcHBg... (another Ledger address at m/44'/512'/0'/0/0).
The OUTPUT is plain P2PKH — no Glyph opcodes. The Glyph ref is dropped (burned)
when this tx confirms.

What this proves if mainnet accepts:
  - The Ledger can correctly sign a spend where the PREV OUTPUT's scriptPubKey
    has Glyph opcodes (OP_PUSHINPUTREFSINGLETON + ref + OP_DROP) before the P2PKH tail
  - The device's preimage computation handles the 63-byte scriptCode correctly
  - Radiant mainnet consensus accepts the Ledger's signature
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

# ----- Glyph UTXO we're spending -----
MINT_TXID = "6c32fcbbd6834170b3afcb9bbed759eeb21db72fd509790a3cb804c6eb5c0630"
MINT_VOUT = 0
MINT_VALUE = 1_080_000   # 0.0108 RXD in sats
# Full 63-byte Glyph-P2PKH scriptPubKey (OP_PUSHINPUTREFSINGLETON + ref36 + OP_DROP + P2PKH)
MINT_SPK_HEX = (
    "d8" +
    "08480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed000000000" +
    "7576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac"
)
LEDGER_PATH = "44'/512'/0'/0/3"
LEDGER_ADDR_SOURCE = "1GT2rB99dRZd919Z1ZkFKZMRijDEu2D7DX"

# ----- Spend output: plain P2PKH back to another Ledger address -----
DEST_ADDR = "1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc"  # m/44'/512'/0'/0/0
DEST_HASH160_HEX = "d8a6a957b97bf1071502e635f4f4ae74e0a279ec"
OUTPUT_VALUE = 980_000  # leaves 100_000 sats fee (Radiant min relay = 100 sats/byte ≈ 19k for 191B)


def main():
    print(f"Spending Glyph UTXO {MINT_TXID}:{MINT_VOUT} ({MINT_VALUE} sats)")
    print(f"  parent spk: {MINT_SPK_HEX}")
    print(f"  source path: {LEDGER_PATH} = {LEDGER_ADDR_SOURCE}")
    print(f"Output: {OUTPUT_VALUE} sats → {DEST_ADDR} (plain P2PKH)")
    print(f"Fee: {MINT_VALUE - OUTPUT_VALUE} sats\n")

    dongle = getDongle(debug=False)
    app = btchip(dongle)

    # Verify derivation matches the UTXO's address
    info = app.getWalletPublicKey(LEDGER_PATH)
    pk_raw = bytes(info['publicKey'])
    addr = info['address']
    if addr != LEDGER_ADDR_SOURCE:
        print(f"ERROR: device derives {addr}, expected {LEDGER_ADDR_SOURCE}")
        return 1
    if pk_raw[0] == 0x04:
        y = pk_raw[33:65]
        pk_compressed = bytes([0x02 + (y[-1] & 1)]) + pk_raw[1:33]
    else:
        pk_compressed = pk_raw
    print(f"Device pubkey: {pk_compressed.hex()}\n")

    # Build the output: plain P2PKH to DEST
    dest_script = bytes.fromhex(f"76a914{DEST_HASH160_HEX}88ac")

    # Oracle sighash (independent check)
    tx = Transaction(
        version=2,
        inputs=[Input(
            prev_txid=bytes.fromhex(MINT_TXID),  # internal byte order
            prev_vout=MINT_VOUT,
            script_sig=b"",
            sequence=0xfffffffe,
        )],
        outputs=[Output(value=OUTPUT_VALUE, script_pubkey=dest_script)],
        locktime=0,
    )
    oracle_sighash = compute_radiant_sighash(
        tx, 0, bytes.fromhex(MINT_SPK_HEX), MINT_VALUE, 0x41
    )
    print(f"Oracle sighash: {oracle_sighash.hex()}")

    # Sign via device
    prev_raw = open('/tmp/glyph_mint_raw.hex').read().strip()
    prev_tx = bitcoinTransaction(bytes.fromhex(prev_raw))
    trusted_input = app.getTrustedInput(prev_tx, MINT_VOUT)
    trusted_input['sequence'] = "feffffff"
    trusted_input['witness'] = True

    app.enableAlternate2fa(False)

    chip_inputs = [trusted_input]
    redeem_script = bytes.fromhex(MINT_SPK_HEX)  # full 63-byte Glyph-P2PKH as scriptCode
    app.startUntrustedTransaction(True, 0, chip_inputs, redeem_script, version=0x02)

    # Build unsigned raw tx for finalizeInput
    raw_unsigned = (
        u32_le(2) +
        varint_encode(1) +
        bytes.fromhex(MINT_TXID)[::-1] + u32_le(MINT_VOUT) +
        varint_encode(0) +
        u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(OUTPUT_VALUE) + varint_encode(len(dest_script)) + dest_script +
        u32_le(0)
    )

    print("\nSending to device for signing. APPROVE on-device when prompted.")
    output_data = app.finalizeInput(b"", 0, 0, LEDGER_PATH, raw_unsigned)
    app.startUntrustedTransaction(False, 0, chip_inputs, redeem_script, version=0x02)
    signature = app.untrustedHashSign(LEDGER_PATH, lockTime=0, sighashType=0x41)

    # Signature from device: raw_sig + 0x41 sighash byte at end
    sig_der = bytes(signature[:-1])
    if sig_der[0] != 0x30:
        sig_der = bytes([0x30]) + sig_der[1:]
    dongle.close()
    print(f"Device signature: {sig_der.hex()}")

    # Verify against oracle
    import ecdsa
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.util import sigdecode_der
    vk = VerifyingKey.from_string(pk_compressed, curve=SECP256k1)
    try:
        vk.verify_digest(sig_der, oracle_sighash, sigdecode=sigdecode_der)
        print("\n\033[92m✓ Device signature verifies against oracle sighash\033[0m")
    except ecdsa.BadSignatureError:
        print("\n\033[91m✗ Signature does NOT verify against oracle\033[0m")
        return 1

    # Build signed tx: input with scriptSig = <sig_with_hashtype> <pubkey>
    sig_with_hashtype = sig_der + bytes([0x41])
    script_sig = (
        varint_encode(len(sig_with_hashtype)) + sig_with_hashtype +
        varint_encode(len(pk_compressed)) + pk_compressed
    )

    signed_tx = (
        u32_le(2) +
        varint_encode(1) +
        bytes.fromhex(MINT_TXID)[::-1] + u32_le(MINT_VOUT) +
        varint_encode(len(script_sig)) + script_sig +
        u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(OUTPUT_VALUE) + varint_encode(len(dest_script)) + dest_script +
        u32_le(0)
    )

    print(f"\n--- Signed tx ({len(signed_tx)} bytes) ---")
    print(signed_tx.hex())

    # Save to file for broadcast
    out_path = Path("/tmp/glyph_spend_signed.hex")
    out_path.write_text(signed_tx.hex() + "\n")
    print(f"\nSaved to {out_path}")
    print("Ready to broadcast. Review the tx structure above, then run:")
    print(f"  cat /tmp/glyph_spend_signed.hex | ssh root@89.117.20.219 'xargs docker exec radiant-mainnet radiant-cli -datadir=/home/radiant/.radiant sendrawtransaction'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
