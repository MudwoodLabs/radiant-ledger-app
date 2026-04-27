"""Shared utilities for Radiant Ledger spend scripts.

Extracted from spend_glyph_2in_transfer.py and spend_real_glyph_2in.py to
eliminate copy-paste of the security-critical helpers (H-6 prev-tx integrity,
C-1/C-3/H-9 device-sig validation, A1 round-trip sighash check).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
END    = "\033[0m"


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def derive_pubkey(app, path: str) -> tuple[str, bytes]:
    """Return (address, compressed_pubkey) for `path` from the connected device."""
    info = app.getWalletPublicKey(path)
    pk_raw = bytes(info["publicKey"])
    if pk_raw[0] == 0x04:
        y = pk_raw[33:65]
        pk_compressed = bytes([0x02 + (y[-1] & 1)]) + pk_raw[1:33]
    else:
        pk_compressed = pk_raw
    return info["address"], pk_compressed


def load_trusted_input(app, raw_hex_path: str, expected_txid: str, vout: int, label: str):
    """Verify the on-disk prev-tx hashes to `expected_txid`, then return a
    getTrustedInput dict (sequence=feffffff, witness=True).

    H-6: integrity check before any USB exchange with the device.
    Returns None on failure; callers must propagate (return 1).
    """
    from btchip.bitcoinTransaction import bitcoinTransaction

    raw = bytes.fromhex(Path(raw_hex_path).read_text().strip())
    calc = sha256d(raw)[::-1].hex()
    if calc != expected_txid.lower():
        print(f"{RED}✗ prev-tx integrity FAIL for {label}:{END}")
        print(f"  {raw_hex_path} hashes to {calc}")
        print(f"  expected {expected_txid}")
        print(f"  refusing getTrustedInput on a substituted prev-tx")
        return None
    ti = app.getTrustedInput(bitcoinTransaction(raw), vout)
    ti["sequence"] = "feffffff"
    ti["witness"] = True
    return ti


def process_device_sig(
    sig: bytes,
    expected_sighash: int = 0x41,
    label: str = "",
) -> tuple[bytes, int]:
    """Validate and canonicalise a raw device signature.

    C-1: assert the trailing sighash byte matches `expected_sighash`.
    H-9: refuse a non-0x30 DER prefix rather than fabricating one.
    C-3: apply low-S normalization (Radiant STRICTENC rejects high-S on broadcast).

    Returns (canonical_der_bytes, sighash_byte).
    Raises AssertionError / RuntimeError on protocol violations.
    """
    from ecdsa.curves import SECP256k1
    from ecdsa.util import sigdecode_der, sigencode_der

    N = SECP256k1.order
    HALF_N = N // 2

    device_sighash = sig[-1]
    if device_sighash != expected_sighash:
        raise AssertionError(
            f"Device returned sighash 0x{device_sighash:02x} for {label}, "
            f"expected 0x{expected_sighash:02x}. "
            f"Check firmware version / app selection."
        )
    sig_der = bytes(sig[:-1])
    if sig_der[0] != 0x30:
        raise RuntimeError(
            f"Non-DER signature from device for {label} "
            f"(first byte 0x{sig_der[0]:02x}); refusing to fabricate prefix."
        )
    r, s = sigdecode_der(sig_der, N)
    if s > HALF_N:
        print(f"  ! high-S sig for {label}; normalising to low-S")
        s = N - s
        sig_der = sigencode_der(r, s, N)
    assert s <= HALF_N, "low-S invariant violated after normalization"
    return sig_der, device_sighash


def make_script_sig(sig_der: bytes, pk: bytes, sighash_byte: int) -> bytes:
    """Build a P2PKH scriptSig: <push sig+sighash_byte> <push pubkey>."""
    from radiant_preimage_oracle import varint_encode

    swh = sig_der + bytes([sighash_byte])
    return varint_encode(len(swh)) + swh + varint_encode(len(pk)) + pk


def verify_oracle_sigs(
    entries: Sequence[tuple[bytes, bytes, bytes, str]],
) -> bool:
    """Verify device sigs against oracle sighashes.

    `entries`: sequence of (sig_der, oracle_sighash, compressed_pubkey, label).
    Returns True if all pass; prints and returns False on first failure.
    """
    import ecdsa
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.util import sigdecode_der

    for i, (sig, sh, pk, label) in enumerate(entries):
        vk = VerifyingKey.from_string(pk, curve=SECP256k1)
        try:
            vk.verify_digest(sig, sh, sigdecode=sigdecode_der)
            print(f"{GREEN}✓ input {i} ({label}) verifies against oracle sighash{END}")
        except ecdsa.BadSignatureError:
            print(f"{RED}✗ input {i} ({label}) FAILS oracle sighash verification{END}")
            return False
    return True


def check_round_trip_sighash(
    signed_tx: bytes,
    spk_hexes: Sequence[str],
    values: Sequence[int],
    oracle_sighashes: Sequence[bytes],
) -> bool:
    """A1: re-parse `signed_tx`, recompute each input's sighash, compare to
    `oracle_sighashes`. Returns True if all match; prints details and returns
    False on any mismatch. Always call before writing or broadcasting.
    """
    from radiant_preimage_oracle import compute_radiant_sighash, parse_transaction

    reparsed = parse_transaction(signed_tx)
    mismatches = []
    for i, (spk_hex, value, oracle_sh) in enumerate(
        zip(spk_hexes, values, oracle_sighashes)
    ):
        rt_sh = compute_radiant_sighash(
            reparsed, i, bytes.fromhex(spk_hex), value, 0x41
        )
        if rt_sh != oracle_sh:
            mismatches.append(
                f"  vin[{i}]: oracle={oracle_sh.hex()}  reparsed={rt_sh.hex()}"
            )
    if mismatches:
        print(f"\n{RED}✗ ROUND-TRIP SIGHASH MISMATCH — REFUSING TO BROADCAST{END}")
        for m in mismatches:
            print(m)
        print("  the assembled tx is NOT the tx the device approved")
        return False
    print(f"{GREEN}✓ Round-trip: re-parsed signed tx produces identical sighashes{END}")
    return True
