#!/usr/bin/env python3
"""
Phase 1.5.2 — self-consistency test for the golden-vector fixtures.

Loads scripts/fixtures/preimage-vectors.json and re-runs the oracle
against each fixture. Confirms oracle output still matches the
`expected_sighash_hex` recorded at build time.

Run this:
  - After any change to scripts/radiant_preimage_oracle.py
  - Before trusting the fixtures in Phase 1.5.4 compare harness

Exit 0 = all vectors still consistent; 1 = drift.

Phase 1.5.4 will use this same fixture format, feeding each (tx, input)
pair to the Ledger device and verifying the device's returned signature
against `expected_sighash_hex` + device's own pubkey at m/44'/512'/0'/0/0.
"""

import json
import sys
from pathlib import Path

import ecdsa
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Input,
    Output,
    Transaction,
    compute_radiant_sighash,
    parse_transaction,
)

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def main() -> int:
    fixtures_path = Path(__file__).parent / "fixtures" / "preimage-vectors.json"
    if not fixtures_path.exists():
        print(f"{RED}✗{RESET} fixtures file not found: {fixtures_path}", file=sys.stderr)
        print(f"   Run build_fixtures.py first.", file=sys.stderr)
        return 1

    data = json.load(open(fixtures_path))
    print(f"Loaded {data['num_vectors']} vectors from {fixtures_path}")
    print()

    all_pass = True

    for v in data["vectors"]:
        print(f"== {v['name']} ({v['shape']}) ==")

        signed_tx = parse_transaction(bytes.fromhex(v["signed_tx_hex"]))
        # Reconstruct unsigned tx (scriptSigs empty)
        unsigned_inputs = [
            Input(prev_txid=inp.prev_txid, prev_vout=inp.prev_vout, script_sig=b"", sequence=inp.sequence)
            for inp in signed_tx.inputs
        ]
        unsigned_tx = Transaction(
            version=signed_tx.version,
            inputs=unsigned_inputs,
            outputs=signed_tx.outputs,
            locktime=signed_tx.locktime,
        )

        input_pass = True
        for inp_spec in v["inputs"]:
            idx = inp_spec["input_index"]
            prev_spk = bytes.fromhex(inp_spec["prev_scriptpubkey_hex"])
            prev_value = inp_spec["prev_value_sats"]
            expected_sighash = bytes.fromhex(inp_spec["expected_sighash_hex"])

            # Rerun oracle
            actual_sighash = compute_radiant_sighash(
                unsigned_tx, input_index=idx,
                prev_output_script=prev_spk, prev_output_value=prev_value,
            )

            # Diff
            if actual_sighash != expected_sighash:
                print(f"  {RED}✗{RESET} input {idx}: oracle drift — expected {expected_sighash.hex()}, got {actual_sighash.hex()}")
                input_pass = False
                continue

            # Also re-verify published signature for full coverage (skip if non-standard scriptSig)
            if "published_signature_der_hex" not in inp_spec:
                continue
            sig_der = bytes.fromhex(inp_spec["published_signature_der_hex"])
            pubkey = bytes.fromhex(inp_spec["published_pubkey_hex"])
            try:
                vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
                vk.verify_digest(sig_der, actual_sighash, sigdecode=sigdecode_der)
            except ecdsa.BadSignatureError:
                print(f"  {RED}✗{RESET} input {idx}: published sig does not verify against oracle sighash")
                input_pass = False
                continue

        if input_pass:
            print(f"  {GREEN}✓{RESET} {len(v['inputs'])}/{len(v['inputs'])} inputs verify")
        else:
            all_pass = False
        print()

    if all_pass:
        print(f"{GREEN}All {data['num_vectors']} vectors consistent with current oracle.{RESET}")
        print("Fixtures are safe to use in Phase 1.5.4 device compare harness.")
        return 0
    else:
        print(f"{RED}Oracle has drifted from fixtures. Either oracle changed or fixtures stale.{RESET}")
        print("Re-run scripts/oracle_self_validate.py to confirm oracle is still correct,")
        print("then re-run scripts/build_fixtures.py to regenerate fixtures.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
