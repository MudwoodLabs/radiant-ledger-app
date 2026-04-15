#!/usr/bin/env python3
"""
Phase 1 derive-address utility.

Sends a GetWalletPublicKey APDU to the Ledger Radiant app and prints:
- the derived public key (hex)
- the P2PKH base58 address
- the BIP32 chain code

Usage:
    python3 derive-address.py [--display]

  --display  Tells the device to show the address on-screen for user
             confirmation before returning. Recommended for receive flows.

The path is hardcoded to m/44'/512'/0'/0/0 (Radiant SLIP-44 first receive
address). The Radiant app's runtime path-lock will refuse anything else.
"""

import sys
import argparse
import struct
from ledgerblue.comm import getDongle


def encode_path(path_str):
    """Encode a path string like m/44'/512'/0'/0/0 into Ledger APDU format."""
    parts = path_str.lstrip("m/").split("/")
    out = bytes([len(parts)])
    for p in parts:
        if p.endswith("'"):
            n = int(p[:-1]) | 0x80000000
        else:
            n = int(p)
        out += struct.pack(">I", n)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--display", action="store_true",
                    help="Ask device to show address on-screen for confirmation")
    ap.add_argument("--path", default="m/44'/512'/0'/0/0",
                    help="BIP32 path (default Radiant first receive address)")
    args = ap.parse_args()

    path_data = encode_path(args.path)

    # CLA=0xe0 INS=0x40 (GetWalletPublicKey) P1=display? P2=0x00 legacy
    p1 = 0x01 if args.display else 0x00
    p2 = 0x00  # legacy / base58
    apdu = bytes([0xe0, 0x40, p1, p2, len(path_data)]) + path_data

    dongle = getDongle(debug=False)
    try:
        resp = dongle.exchange(apdu)
    finally:
        dongle.close()

    # Response format (per app-bitcoin):
    # 0x41 (65 bytes pubkey: 0x04 || X || Y)
    # 0x?? address_len
    # address_bytes
    # 32 bytes chain_code
    pubkey_len = resp[0]
    pubkey = resp[1:1 + pubkey_len]
    addr_len = resp[1 + pubkey_len]
    address = resp[1 + pubkey_len + 1:1 + pubkey_len + 1 + addr_len]
    chain_code = resp[1 + pubkey_len + 1 + addr_len:1 + pubkey_len + 1 + addr_len + 32]

    print(f"Path:     {args.path}")
    print(f"Pubkey:   {pubkey.hex()}")
    print(f"Address:  {address.decode()}")
    print(f"ChainCode: {chain_code.hex()}")
    if args.display:
        print()
        print("(Address was shown on the device screen — verify it matches above)")


if __name__ == "__main__":
    main()
