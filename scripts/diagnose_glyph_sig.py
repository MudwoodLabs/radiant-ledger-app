#!/usr/bin/env python3
"""Compute alternative sighashes to see which one the device actually signed.
If the 'no-refs' sighash matches, the device opcode walker didn't fire.
If the 'correct' sighash matches, this script has a bug.
If neither matches, the opcode walker fired but produced a wrong refsHash.
"""

import hashlib
import sys
from pathlib import Path

import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Transaction, Input, Output, compute_radiant_sighash,
    sha256d, u32_le, u64_le, varint_encode,
)

# Device returned this signature
DEVICE_SIG_HEX = "3045022100bfe8ff14a17916e4d5b341fe5f9b24e78b03f71aea45b5f495d6160aa25c91af022008040633bc422abe1cb48db2102ae5911487f5058f5a6ef3f0b3d38fe047bfe6"
PUBKEY_HEX = "03ab6b41bfa4bfbab10a69575b989d62b4275ba9339115a763e5c54364fbb2b1d9"

PREV_TXID = "e10517b534db04d20817a75d8c9522a4046ce167808d46b7b6de2eacf1e5ba9e"
PREV_VOUT = 0
PREV_VALUE = 5_000_000
PREV_SCRIPT_HEX = "76a914614b44c4786043c88bdd8a3c9df799ba090e3f6088ac"

ZERO_32 = bytes(32)


def get_hash160_of_address(address):
    ALPHA = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in address.encode():
        n = n * 58 + ALPHA.index(c)
    decoded = n.to_bytes(25, 'big')
    return decoded[1:21]


def try_verify(sighash, label):
    vk = VerifyingKey.from_string(bytes.fromhex(PUBKEY_HEX), curve=SECP256k1)
    try:
        vk.verify_digest(bytes.fromhex(DEVICE_SIG_HEX), sighash, sigdecode=sigdecode_der)
        print(f"  \033[92m✓ MATCH: {label}\033[0m")
        print(f"    → sighash: {sighash.hex()}")
        return True
    except ecdsa.BadSignatureError:
        print(f"  ✗ no match: {label}  ({sighash.hex()[:16]}…)")
        return False


def main():
    our_h160 = get_hash160_of_address("19sSiN4eb526fLPUqgY23iiNKYjy7cmV33")
    fake_ref = bytes.fromhex("deadbeef" * 8 + "00000000")

    glyph_script = (
        b"\x76\xa9\x14" + our_h160 + b"\x88\xac"
        + b"\xd0" + fake_ref
    )
    output_value = 4_000_000

    tx = Transaction(
        version=2,
        inputs=[Input(
            prev_txid=bytes.fromhex(PREV_TXID)[::-1],
            prev_vout=PREV_VOUT,
            script_sig=b"",
            sequence=0xfffffffe,
        )],
        outputs=[Output(value=output_value, script_pubkey=glyph_script)],
        locktime=0,
    )

    # --- Variant A: oracle's computed (correct) sighash ---
    sighash_correct = compute_radiant_sighash(
        tx, 0, bytes.fromhex(PREV_SCRIPT_HEX), PREV_VALUE, 0x41
    )
    try_verify(sighash_correct, "Variant A: correct (totalRefs=1, refsHash=sha256d(fake_ref))")

    # --- Variant B: device thought totalRefs=0, refsHash=zeros (walker didn't fire) ---
    # Replicate the per-output summary with no refs
    scriptHash = sha256d(glyph_script)
    summary_B = u64_le(output_value) + scriptHash + u32_le(0) + ZERO_32
    hashOutputHashes_B = sha256d(summary_B)

    # Re-compute full sighash with this tweaked hashOutputHashes
    inp = tx.inputs[0]
    hashPrevouts = sha256d(inp.prev_txid + u32_le(inp.prev_vout))
    hashSequence = sha256d(u32_le(inp.sequence))
    hashOutputs = sha256d(u64_le(output_value) + varint_encode(len(glyph_script)) + glyph_script)
    preimage = (
        u32_le(tx.version) +
        hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(len(bytes.fromhex(PREV_SCRIPT_HEX))) + bytes.fromhex(PREV_SCRIPT_HEX) +
        u64_le(PREV_VALUE) +
        u32_le(inp.sequence) +
        hashOutputHashes_B +
        hashOutputs +
        u32_le(tx.locktime) +
        u32_le(0x41)
    )
    sighash_B = sha256d(preimage)
    try_verify(sighash_B, "Variant B: no-refs (walker missed OP_PUSHINPUTREF)")

    # --- Variant C: device thought hashOutputHashes itself is empty/zero ---
    sighash_C_preimage = (
        u32_le(tx.version) +
        hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(len(bytes.fromhex(PREV_SCRIPT_HEX))) + bytes.fromhex(PREV_SCRIPT_HEX) +
        u64_le(PREV_VALUE) +
        u32_le(inp.sequence) +
        ZERO_32 +  # hashOutputHashes = zeros
        hashOutputs +
        u32_le(tx.locktime) +
        u32_le(0x41)
    )
    sighash_C = sha256d(sighash_C_preimage)
    try_verify(sighash_C, "Variant C: hashOutputHashes = zeros (device skipped field entirely)")

    # --- Variant D: BCH-style preimage (no hashOutputHashes field at all) ---
    sighash_D_preimage = (
        u32_le(tx.version) +
        hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(len(bytes.fromhex(PREV_SCRIPT_HEX))) + bytes.fromhex(PREV_SCRIPT_HEX) +
        u64_le(PREV_VALUE) +
        u32_le(inp.sequence) +
        hashOutputs +  # no hashOutputHashes
        u32_le(tx.locktime) +
        u32_le(0x41)
    )
    sighash_D = sha256d(sighash_D_preimage)
    try_verify(sighash_D, "Variant D: BCH-style (no hashOutputHashes in preimage)")

    # --- Variant E: device saw script_len=25 only (old canonical-P2PKH behavior) ---
    # If it only hashed 25 bytes, scriptHash differs
    p2pkh_only = glyph_script[:25]
    summary_E = u64_le(output_value) + sha256d(p2pkh_only) + u32_le(0) + ZERO_32
    hashOutputHashes_E = sha256d(summary_E)
    sighash_E_preimage = (
        u32_le(tx.version) +
        hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(len(bytes.fromhex(PREV_SCRIPT_HEX))) + bytes.fromhex(PREV_SCRIPT_HEX) +
        u64_le(PREV_VALUE) +
        u32_le(inp.sequence) +
        hashOutputHashes_E +
        hashOutputs +
        u32_le(tx.locktime) +
        u32_le(0x41)
    )
    sighash_E = sha256d(sighash_E_preimage)
    try_verify(sighash_E, "Variant E: device hashed only first 25 bytes (stale v0.0.3 code path?)")

    # --- Variant F: refsHash = single sha256(ref) instead of sha256d ---
    import hashlib
    refs_hash_single = hashlib.sha256(fake_ref).digest()
    summary_F = u64_le(output_value) + scriptHash + u32_le(1) + refs_hash_single
    hashOutputHashes_F = sha256d(summary_F)
    sighash_F_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(25) + bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +
        u32_le(inp.sequence) + hashOutputHashes_F + hashOutputs +
        u32_le(tx.locktime) + u32_le(0x41)
    )
    try_verify(sha256d(sighash_F_preimage), "Variant F: refsHash = single sha256 of ref")

    # --- Variant G: hashOutputHashes = single sha256 ---
    summary_correct = u64_le(output_value) + scriptHash + u32_le(1) + sha256d(fake_ref)
    hashOutputHashes_single = hashlib.sha256(summary_correct).digest()
    sighash_G_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(25) + bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +
        u32_le(inp.sequence) + hashOutputHashes_single + hashOutputs +
        u32_le(tx.locktime) + u32_le(0x41)
    )
    try_verify(sha256d(sighash_G_preimage), "Variant G: hashOutputHashes = single sha256 of summary")

    # --- Variant H: scriptHash = single sha256 (not double) ---
    script_hash_single = hashlib.sha256(glyph_script).digest()
    summary_H = u64_le(output_value) + script_hash_single + u32_le(1) + sha256d(fake_ref)
    hashOutputHashes_H = sha256d(summary_H)
    sighash_H_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(25) + bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +
        u32_le(inp.sequence) + hashOutputHashes_H + hashOutputs +
        u32_le(tx.locktime) + u32_le(0x41)
    )
    try_verify(sha256d(sighash_H_preimage), "Variant H: scriptHash = single sha256 (not double)")

    # --- Variant I: locktime different (BE issue in untrustedHashSign) ---
    import struct
    sighash_I_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(25) + bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +
        u32_le(inp.sequence) +
        sha256d(u64_le(output_value) + sha256d(glyph_script) + u32_le(1) + sha256d(fake_ref)) +
        hashOutputs +
        struct.pack(">I", 0) +  # BE locktime
        u32_le(0x41)
    )
    try_verify(sha256d(sighash_I_preimage), "Variant I: locktime in BE instead of LE")

    # --- Variant J: no varint for scriptCode (raw script, no length prefix) ---
    sighash_J_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +  # NO varint!
        u32_le(inp.sequence) +
        sha256d(u64_le(output_value) + sha256d(glyph_script) + u32_le(1) + sha256d(fake_ref)) +
        hashOutputs +
        u32_le(tx.locktime) + u32_le(0x41)
    )
    try_verify(sha256d(sighash_J_preimage), "Variant J: no varint prefix on scriptCode")

    # --- Variant K: script len byte included in sha256d(scriptPubKey) ---
    script_with_len = bytes([len(glyph_script)]) + glyph_script
    summary_K = u64_le(output_value) + sha256d(script_with_len) + u32_le(1) + sha256d(fake_ref)
    hashOutputHashes_K = sha256d(summary_K)
    sighash_K_preimage = (
        u32_le(tx.version) + hashPrevouts + hashSequence +
        inp.prev_txid + u32_le(inp.prev_vout) +
        varint_encode(25) + bytes.fromhex(PREV_SCRIPT_HEX) + u64_le(PREV_VALUE) +
        u32_le(inp.sequence) + hashOutputHashes_K + hashOutputs +
        u32_le(tx.locktime) + u32_le(0x41)
    )
    try_verify(sha256d(sighash_K_preimage), "Variant K: sha256d(scriptPubKey) includes script_len byte")


if __name__ == "__main__":
    main()
