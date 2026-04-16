#!/usr/bin/env python3
"""Isolation test: sign a plain P2PKH output using the SAME APDU flow that
fails for Glyph output. If this test also fails, the bug is in the test
harness. If it succeeds, the bug is in the opcode walker."""

import sys
from pathlib import Path

import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

sys.path.insert(0, str(Path.home() / "apps/Electron-Wallet/electroncash_plugins/ledger/vendor"))
from btchip.btchip import btchip
from btchip.btchipComm import getDongle
from btchip.bitcoinTransaction import bitcoinTransaction

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Transaction, Input, Output, compute_radiant_sighash,
    u32_le, u64_le, varint_encode,
)

PREV_TXID = "e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e"
PREV_VOUT = 0
PREV_VALUE = 5_000_000
PREV_SCRIPT_HEX = "76a914614b44c4786043c88bdd8a3c9df799ba090e3f6088ac"
PATH = "44'/512'/0'/0/2"
DEST_HASH160_HEX = "614b44c4786043c88bdd8a3c9df799ba090e3f60"  # self


def main():
    dongle = getDongle(debug=True)
    app = btchip(dongle)
    info = app.getWalletPublicKey(PATH)
    pk = bytes(info['publicKey'])
    if pk[0] == 0x04:
        pk_compressed = bytes([0x02 + (pk[33:65][-1] & 1)]) + pk[1:33]
    else:
        pk_compressed = pk
    print(f"pubkey: {pk_compressed.hex()}")

    # Plain P2PKH output — NO glyph opcodes
    p2pkh_script = bytes.fromhex(f"76a914{DEST_HASH160_HEX}88ac")
    print(f"Plain P2PKH output ({len(p2pkh_script)}B): {p2pkh_script.hex()}")

    output_value = 4_000_000

    tx = Transaction(
        version=2,
        inputs=[Input(
            prev_txid=bytes.fromhex(PREV_TXID), prev_vout=PREV_VOUT,  # internal byte order (display hex)
            script_sig=b"", sequence=0xfffffffe)],
        outputs=[Output(value=output_value, script_pubkey=p2pkh_script)],
        locktime=0,
    )
    oracle_sighash = compute_radiant_sighash(
        tx, 0, bytes.fromhex(PREV_SCRIPT_HEX), PREV_VALUE, 0x41)
    print(f"Oracle sighash: {oracle_sighash.hex()}")

    # Sign via device (SAME flow as Glyph test)
    prev_raw = open('/tmp/regtx_raw.hex').read().strip()
    prev_tx = bitcoinTransaction(bytes.fromhex(prev_raw))
    trusted_input = app.getTrustedInput(prev_tx, PREV_VOUT)
    trusted_input['sequence'] = "feffffff"
    trusted_input['witness'] = True

    app.enableAlternate2fa(False)

    chip_inputs = [trusted_input]
    redeem_script = bytes.fromhex(PREV_SCRIPT_HEX)
    app.startUntrustedTransaction(True, 0, chip_inputs, redeem_script, version=0x02)

    raw_unsigned = (
        u32_le(2) + varint_encode(1) +
        bytes.fromhex(PREV_TXID)[::-1] + u32_le(PREV_VOUT) +
        varint_encode(0) + u32_le(0xfffffffe) +
        varint_encode(1) +
        u64_le(output_value) + varint_encode(len(p2pkh_script)) + p2pkh_script +
        u32_le(0)
    )

    output_data = app.finalizeInput(b"", 0, 0, PATH, raw_unsigned)
    app.startUntrustedTransaction(False, 0, chip_inputs, redeem_script, version=0x02)
    signature = app.untrustedHashSign(PATH, lockTime=0, sighashType=0x41)
    sig_der = bytes(signature[:-1])
    if sig_der[0] != 0x30:
        sig_der = bytes([0x30]) + sig_der[1:]
    dongle.close()
    print(f"Device sig:     {sig_der.hex()}")

    vk = VerifyingKey.from_string(pk_compressed, curve=SECP256k1)
    try:
        vk.verify_digest(sig_der, oracle_sighash, sigdecode=sigdecode_der)
        print("\n\033[92m✓ Plain P2PKH device sig MATCHES oracle → test harness is correct.\033[0m")
        print("\033[92m  → The Glyph bug is in the opcode walker / hashOutputHashes.\033[0m")
        return 0
    except ecdsa.BadSignatureError:
        print("\n\033[91m✗ Plain P2PKH also FAILS. Test harness has a bug, not the walker.\033[0m")
        return 1


if __name__ == "__main__":
    sys.exit(main())
