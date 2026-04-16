#!/usr/bin/env python3
"""Validate the new push-ref oracle path against a real Glyph mainnet tx.

Tx 72eb90d570807eb9ccf4ac99edc8a7c3e807f694dfde9fac37dc95a1118f04e8 (block 420794)
contains outputs with OP_PUSHINPUTREF (0xd0) and OP_PUSHINPUTREFSINGLETON (0xd8),
so its hashOutputHashes is non-trivial. Vin[1] is a standard P2PKH spend.

Acid test: take vin[1]'s published signature + pubkey from its scriptSig,
compute the expected sighash via the oracle (which now has to walk push-refs),
and verify the signature. If it verifies, the entire chain matches what
Radiant mainnet itself accepted.
"""

import sys
from pathlib import Path

import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    parse_transaction, compute_radiant_sighash, sha256,
)

GREEN = "\033[92m"; RED = "\033[91m"; END = "\033[0m"

# Tx 72eb…04e8 (block 420794, mainnet)
RAW_TX_HEX = open('/tmp/glyph_raw.hex').read().strip()

# vin[1] spends b01cc9ef…1cb0:3 — value 16313653000 sats, P2PKH spk
PREV_VOUT_VALUE = 16313653000
PREV_VOUT_SCRIPT = bytes.fromhex("76a914800d0414e758f790a48ad0f2960d566ef56cd5bf88ac")
INPUT_INDEX = 1


def main():
    raw = bytes.fromhex(RAW_TX_HEX)
    tx = parse_transaction(raw)

    print(f"Tx parsed: {len(tx.inputs)} inputs, {len(tx.outputs)} outputs, version {tx.version}")
    for i, o in enumerate(tx.outputs):
        has_pushref = any(b in (0xd0, 0xd8) for b in o.script_pubkey[:2] + o.script_pubkey[40:60])
        # crude byte presence check across script
        has_pushref = (b'\xd0' in o.script_pubkey) or (b'\xd8' in o.script_pubkey)
        print(f"  out[{i}] value={o.value:>13} sats spk={len(o.script_pubkey):>3}B push-ref-bytes-present={has_pushref}")

    # Extract sig + pubkey from vin[1] scriptSig: <sig-with-hashtype> <pubkey>
    script_sig = tx.inputs[INPUT_INDEX].script_sig
    print(f"\nvin[{INPUT_INDEX}] script_sig length: {len(script_sig)} bytes")

    # First push: signature
    sig_len = script_sig[0]
    sig_with_hashtype = script_sig[1:1 + sig_len]
    sig_der = sig_with_hashtype[:-1]
    hashtype = sig_with_hashtype[-1]
    print(f"  sig_len={sig_len} hashtype=0x{hashtype:02x}")

    # Next push: pubkey
    off = 1 + sig_len
    pk_len = script_sig[off]
    pubkey = script_sig[off + 1:off + 1 + pk_len]
    print(f"  pubkey ({pk_len}B): {pubkey.hex()}")

    if hashtype != 0x41:
        print(f"{RED}vin[{INPUT_INDEX}] uses hashtype 0x{hashtype:02x}, not 0x41 — cannot validate with v1 oracle{END}")
        sys.exit(2)

    # Compute sighash via oracle (this exercises the new push-ref path)
    sighash = compute_radiant_sighash(
        tx,
        input_index=INPUT_INDEX,
        prev_output_script=PREV_VOUT_SCRIPT,
        prev_output_value=PREV_VOUT_VALUE,
        sighash_type=0x41,
    )
    print(f"\nOracle sighash: {sighash.hex()}")

    # Verify
    vk = VerifyingKey.from_string(pubkey, curve=SECP256k1, hashfunc=lambda d: __import__('hashlib').sha256(d))
    try:
        vk.verify_digest(sig_der, sighash, sigdecode=sigdecode_der)
        print(f"\n{GREEN}✓ Mainnet signature verifies against oracle sighash.{END}")
        print(f"{GREEN}  Push-ref scanner produces correct hashOutputHashes for real Glyph tx.{END}")
        sys.exit(0)
    except ecdsa.BadSignatureError as e:
        print(f"\n{RED}✗ Signature does NOT verify. Oracle output is wrong.{END}")
        print(f"  ({e})")
        sys.exit(1)


if __name__ == "__main__":
    main()
