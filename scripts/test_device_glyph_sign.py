#!/usr/bin/env python3
"""Device-vs-oracle Glyph signing test.

Builds an unsigned tx whose OUTPUT contains OP_PUSHINPUTREF + a fake 36-byte
ref — exercising the device's new opcode walker for hashOutputHashes. Sends
the tx through btchip APDUs for signing. Verifies the returned signature
against the oracle's independently-computed sighash.

If this passes, the device's hashOutputHashes computation for Glyph outputs
is byte-correct vs. the radiantjs-derived oracle — same validation methodology
as Phase 1.5.4 for plain P2PKH, now covering the push-ref path.

Previous tx (spent input): e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e
  vout[0]: 0.05 RXD → 19sSiN4eb526fLPUqgY23iiNKYjy7cmV33 (m/44'/512'/0'/0/2)
    we spend THIS input

Output we construct (Glyph-shaped):
  value: 4000000 sats (0.04 RXD, fee ~0.01 RXD — generous)
  script: 76a914 <hash160 of m/44'/512'/0'/0/2> 88ac d0 <36 fake ref bytes>
            |---- P2PKH to our own address ----|  |--- OP_PUSHINPUTREF + fake ref ---|

The fake ref points to a txid/vout that doesn't exist — if we broadcast this
tx, mainnet would reject it at consensus. We DO NOT broadcast. We only check
whether the device produces a signature that the oracle verifies against.

Usage:
  python3 test_device_glyph_sign.py

Exit 0 = device sig verifies against oracle → push-ref opcode walker works.
"""

import hashlib
import sys
from pathlib import Path

import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

# Use the vendored btchip from Electron-Wallet
sys.path.insert(0, str(Path.home() / "apps/Electron-Wallet/electroncash_plugins/ledger/vendor"))
from btchip.btchip import btchip
from btchip.btchipComm import getDongle
from btchip.bitcoinTransaction import bitcoinTransaction

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Transaction, Input, Output, compute_radiant_sighash,
    parse_transaction, u32_le, u64_le, varint_encode,
)

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; END = "\033[0m"


# ----- Configuration: the UTXO we're spending (from regression tx) -----
PREV_TXID = "e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e"
PREV_VOUT = 0
PREV_VALUE = 5_000_000  # 0.05 RXD in sats
PREV_SCRIPT_HEX = "76a914614b44c4786043c88bdd8a3c9df799ba090e3f6088ac"
PREV_ADDRESS = "19sSiN4eb526fLPUqgY23iiNKYjy7cmV33"
PATH = "44'/512'/0'/0/2"


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def get_hash160_of_address(address):
    """Decode base58check address → 20-byte hash160."""
    import hashlib
    ALPHA = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in address.encode():
        n = n * 58 + ALPHA.index(c)
    decoded = n.to_bytes(25, 'big')
    # version byte + 20-byte hash + 4-byte checksum
    return decoded[1:21]


def main():
    # ---- Step 1: derive pubkey + address from device, verify they match ----
    print("Step 1: verify device derivation path matches expected address")
    dongle = getDongle(debug=False)
    app = btchip(dongle)
    pubkey_info = app.getWalletPublicKey(PATH)
    pk_raw = pubkey_info['publicKey']
    pk_hex = bytes(pk_raw).hex() if isinstance(pk_raw, (bytes, bytearray)) else pk_raw
    addr_raw = pubkey_info['address']
    addr = bytes(addr_raw).decode() if isinstance(addr_raw, (bytes, bytearray)) else addr_raw
    print(f"  device returned address: {addr}")
    print(f"  expected:                {PREV_ADDRESS}")
    if addr != PREV_ADDRESS:
        print(f"{RED}MISMATCH — cannot proceed.{END}")
        sys.exit(1)
    print(f"  {GREEN}✓ match{END}")

    pubkey_raw = bytes.fromhex(pk_hex)
    # compress
    if len(pubkey_raw) == 65 and pubkey_raw[0] == 0x04:
        x = pubkey_raw[1:33]; y = pubkey_raw[33:65]
        pubkey_compressed = bytes([0x02 + (y[-1] & 1)]) + x
    else:
        pubkey_compressed = pubkey_raw
    print(f"  compressed pubkey: {pubkey_compressed.hex()}")

    # ---- Step 2: build the Glyph-shaped output script ----
    our_h160 = get_hash160_of_address(PREV_ADDRESS)
    fake_ref = bytes.fromhex("deadbeef" * 8 + "00000000")  # 32B "txid" + 4B vout
    assert len(fake_ref) == 36

    # Script: P2PKH + OP_PUSHINPUTREF + 36-byte ref
    # 76 a9 14 <20B hash> 88 ac d0 <36B ref>
    glyph_script = (
        b"\x76\xa9\x14" + our_h160 + b"\x88\xac"
        + b"\xd0" + fake_ref
    )
    print(f"\nStep 2: Glyph output script built ({len(glyph_script)} bytes)")
    print(f"  hex: {glyph_script.hex()}")

    # ---- Step 3: build unsigned tx ----
    output_value = 4_000_000  # 0.04 RXD (fee = 0.01 RXD)
    # Match the working regression tx: version=2, sequence=0xfffffffe (RBF-flag)
    unsigned_tx = Transaction(
        version=2,
        inputs=[Input(
            prev_txid=bytes.fromhex(PREV_TXID),  # internal byte order (display hex)
            prev_vout=PREV_VOUT,
            script_sig=b"",  # empty for unsigned
            sequence=0xfffffffe,
        )],
        outputs=[Output(value=output_value, script_pubkey=glyph_script)],
        locktime=0,
    )

    # ---- Step 4: oracle-compute expected sighash ----
    print("\nStep 3: compute expected sighash via Python oracle")
    oracle_sighash = compute_radiant_sighash(
        unsigned_tx, input_index=0,
        prev_output_script=bytes.fromhex(PREV_SCRIPT_HEX),
        prev_output_value=PREV_VALUE,
        sighash_type=0x41,
    )
    print(f"  oracle sighash: {oracle_sighash.hex()}")

    # ---- Step 5: sign on device ----
    print("\nStep 4: send APDUs to device for signing")
    print(f"{YELLOW}  (approve on device when prompted — 0.04 RXD to {PREV_ADDRESS} with Glyph tail){END}")

    # Fetch prev-tx raw hex
    prev_raw = open('/tmp/regtx_raw.hex').read().strip()
    prev_tx = bitcoinTransaction(bytes.fromhex(prev_raw))

    trusted_input = app.getTrustedInput(prev_tx, PREV_VOUT)
    trusted_input['sequence'] = "feffffff"  # 0xfffffffe LE, matches working regression tx
    trusted_input['witness'] = True  # CRITICAL: tells device to use BIP143-style segwit sighash (Radiant preimage path)

    # Match plugin flow exactly
    app.enableAlternate2fa(False)

    # Use compressed pubkey scriptCode for P2PKH
    # scriptCode for P2PKH input = 76 a9 14 <hash160> 88 ac (same as scriptPubKey)
    chip_inputs = [trusted_input]
    redeem_script = bytes.fromhex(PREV_SCRIPT_HEX)

    app.startUntrustedTransaction(True, 0, chip_inputs, redeem_script, version=0x02)

    # Build FULL unsigned raw tx for finalizeInput (which parses it as bitcoinTransaction)
    # Format: version(4 LE) | vin_count(varint) | {prev_txid(32 BE) + prev_vout(4 LE) + script_sig_len(varint)
    #         + script_sig + sequence(4 LE)} per input | vout_count(varint)
    #         | {value(8 LE) + script_len(varint) + script} per output | locktime(4 LE)
    raw_unsigned = (
        u32_le(2) +                                              # version=2 (match working tx)
        varint_encode(1) +                                       # vin count
        bytes.fromhex(PREV_TXID)[::-1] + u32_le(PREV_VOUT) +    # prevout in WIRE format (LE, reversed)
        varint_encode(0) +                                       # empty script_sig
        u32_le(0xfffffffe) +                                     # sequence (RBF flag)
        varint_encode(1) +                                       # vout count
        u64_le(output_value) +
        varint_encode(len(glyph_script)) + glyph_script +
        u32_le(0)                                                # locktime
    )
    print(f"  raw unsigned tx ({len(raw_unsigned)}B): {raw_unsigned.hex()}")

    # Pass PATH as changePath — device expects a derivation to be set up first
    # even though we're not actually using the change-output detection
    try:
        output_data = app.finalizeInput(b"", 0, 0, PATH, raw_unsigned)
    except Exception as e:
        print(f"{RED}✗ finalizeInput raised: {e}{END}")
        import traceback; traceback.print_exc()
        dongle.close()
        sys.exit(1)

    # Segwit-style per-input re-start before signing (what plugin does at ledger.py:487)
    app.startUntrustedTransaction(False, 0, chip_inputs, redeem_script, version=0x02)

    # Hash-sign: returns (signature, sighashType)
    signature = app.untrustedHashSign(PATH, lockTime=0, sighashType=0x41)
    # Ledger returns sig in form: raw_sig + sighash_type byte
    sig_der = bytes(signature[:-1])  # strip trailing sighash type byte
    # Force DER prefix 0x30 (Ledger 1.4.9+ convention)
    if sig_der[0] != 0x30:
        sig_der = bytes([0x30]) + sig_der[1:]

    dongle.close()
    print(f"  device signature: {sig_der.hex()}")

    # ---- Step 6: verify signature against oracle sighash ----
    print("\nStep 5: verify device signature against oracle sighash")
    vk = VerifyingKey.from_string(pubkey_compressed, curve=SECP256k1)
    try:
        vk.verify_digest(sig_der, oracle_sighash, sigdecode=sigdecode_der)
        print(f"\n{GREEN}✓ DEVICE SIGNATURE VERIFIES AGAINST ORACLE SIGHASH{END}")
        print(f"{GREEN}  → Device's hashOutputHashes computation for Glyph outputs is byte-correct.{END}")
        print(f"{GREEN}  → Opcode walker handles OP_PUSHINPUTREF correctly on-device.{END}")
        return 0
    except ecdsa.BadSignatureError as e:
        print(f"\n{RED}✗ Signature DOES NOT verify.{END}")
        print(f"  ({e})")
        print(f"  → device sighash differs from oracle — opcode walker has a bug")
        return 1


if __name__ == "__main__":
    sys.exit(main())
