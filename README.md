# Radiant Ledger App — Planning & Verification

Docs, brainstorm, plan, Python oracle, golden-vector fixtures, and investigation notes for the community [**Radiant Ledger Nano S Plus app**](https://github.com/Zyrtnin-org/app-radiant).

The code lives in separate repos (see below). This repo is the paper trail — how it was designed, how its correctness was verified before touching mainnet, and the full arc of what went right and what went wrong.

---

## Status

**v1 walking skeleton landed 2026-04-15.** First mainnet-confirmed Radiant tx signed by a Ledger Nano S Plus: [`de3574979f…56893743`](https://explorer.radiantblockchain.org/tx/de3574979f986616b4152c4294b85562318292490d3587d8fe32aff456893743). Beta; looking for testers.

Live deliverables:

| Repo | What's there | Branch / Tag |
|---|---|---|
| [`Zyrtnin-org/app-radiant`](https://github.com/Zyrtnin-org/app-radiant) | Main Ledger app — fork of LedgerHQ/app-bitcoin with a `radiant` Makefile variant | `v0.0.3-sighash-fix` |
| [`Zyrtnin-org/lib-app-bitcoin`](https://github.com/Zyrtnin-org/lib-app-bitcoin) | Submodule with the on-device C diff (`hashOutputHashes` computation, strict path-lock, canonical-P2PKH enforcement) | `radiant-v1` |
| [`Zyrtnin-org/Electron-Wallet`](https://github.com/Zyrtnin-org/Electron-Wallet) | Host-side wallet plugin — patched derivation path + non-P2PKH pre-check + device-ID fix | `radiant-ledger-512` |
| **This repo** | Planning artifacts + verification tools | `main` |

---

## What lives here

```
docs/
  brainstorms/
    2026-04-14-radiant-ledger-app-v1-brainstorm.md       # v1 scoping: SLIP-44 decision, fork strategy, distribution model
    2026-04-15-hashoutputhashes-remediation-brainstorm.md # mid-v1 discovery: Radiant's sighash isn't byte-identical to BCH
  plans/
    2026-04-14-feat-radiant-ledger-app-v1-plan.md        # master v1 plan (6 phases)
    2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md # 1.5.x remediation plan after the sighash finding

scripts/
  radiant_preimage_oracle.py         # Python port of radiantjs sighash.js — the canonical preimage oracle
  oracle_self_validate.py            # 3-way self-validation (mainnet tx sig + hand-computed byte-diff + second mainnet tx)
  build_fixtures.py                  # generates scripts/fixtures/preimage-vectors.json from real mainnet txs
  test_oracle_against_vectors.py     # re-verifies the oracle against the fixtures
  derive-address.py                  # direct APDU harness to ask the device for a pubkey at any path
  task-0.0-runbook.md                # Phase 0.0 LSB-014 path-lock verification steps

  fixtures/
    preimage-vectors.json            # 4 golden test vectors — 16 sighashes, every one verified against published mainnet sigs

INVESTIGATION.md                     # full arc: every Phase 0–1.5.5 finding, SHA256s, txids, bugs found, fixes
```

---

## Quick verification (no hardware needed)

Confirm the Python oracle still produces correct Radiant sighashes:

```bash
cd scripts
python3 oracle_self_validate.py
# Exit 0 = 3-way validation PASS. Oracle is trusted as ground truth.

python3 test_oracle_against_vectors.py
# Exit 0 = oracle output matches all 16 sighashes in the fixture set.
```

Anyone running these on a clean clone gets the same result — pure Python + stdlib + `ecdsa`.

## Verifying a device build on your own hardware

See the main app's [`BUILDER.md`](https://github.com/Zyrtnin-org/app-radiant/blob/main/BUILDER.md) for reproducibility, or the `scripts/task-0.0-runbook.md` for the Phase 0.0 sideload-test procedure.

---

## How v1 got built

1. **Brainstorm** (`/workflows:brainstorm`) — "community Ledger Nano S Plus app for RXD." Decided fork vs rewrite, SLIP-44 512 vs 0, which devices to target. ([doc](docs/brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md))
2. **Plan** (`/workflows:plan`) — 6 phases: bootstrap → C app → plugin → first sign → hardening → community validation → release. ([doc](docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md))
3. **Phase 0 bootstrap** — repo scaffolding, CI pinned by digest, LSB-014 path-lock verification on-device.
4. **Phase 1 walking skeleton** — C diff + plugin change + sideload + first address derivation. Got as far as "device signs tx, mainnet rejects it with script-execution-error."
5. **Diagnosis** — traced the rejection to `hashOutputHashes`, a new 32-byte field Radiant inserts in the preimage that BCH's signing path doesn't produce. Walking-skeleton strategy paid off — caught the issue at 1 RXD of risk rather than post-release.
6. **Remediation brainstorm + plan** (`2026-04-15-*`) — Strategy A (device independently computes `hashOutputHashes`), canonical P2PKH enforcement as v1 simplification, Python oracle first for byte-level verification.
7. **Phase 1.5.0 pre-check** — verified 5 spec details against canonical sources before writing code.
8. **Phase 1.5.1 oracle** — ported [`radiantjs sighash.js:91-237`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L91) to Python. Triple-validated: mainnet tx sig + hand-computed byte-diff + second-signer mainnet tx. 16 sighashes verified against real mainnet signatures.
9. **Phase 1.5.2 golden vectors** — 4 real mainnet RXD txs curated as test fixtures; every sighash verified at build time.
10. **Phase 1.5.3 C implementation** — ~300 lines across lib-app-bitcoin. Per-output streaming FSM, hashOutputHashes accumulator, preimage insertion, reset-path coverage, plugin pre-check, runtime assertion.
11. **Phase 1.5.4 device-vs-oracle** — device-signed tx signature verifies locally against oracle sighash + device pubkey via secp256k1. Caught and fixed a byte-feeder placement bug (inside OUTPUT case, not post-switch).
12. **Phase 1.5.5 mainnet broadcast** — [`de3574979f…56893743`](https://explorer.radiantblockchain.org/tx/de3574979f986616b4152c4294b85562318292490d3587d8fe32aff456893743) confirmed in block 420762.

Full per-phase findings, SHA256s, commit hashes, and diagnoses: [`INVESTIGATION.md`](INVESTIGATION.md).

---

## v2 scope (tracked, not started)

- Real `GetPushRefs` opcode scan → enables Glyph / NFT signing, P2SH destinations, OP_RETURN memos
- `SIGHASH_SINGLE` + `SIGHASH_ANYONECANPAY` support
- Schnorr signature emission (shorter sigs → lower fees)
- Speculos / Ragger emulator CI
- Nano X, Stax, Flex device support
- Official Ledger listing (post community validation)

See [v1 plan Future Considerations](docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md) and [remediation v2 Tracking](docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md) for details.

---

## Looking for testers

Have a Nano S Plus and some spare RXD? Open an issue here (or in the [`app-radiant` repo](https://github.com/Zyrtnin-org/app-radiant)) to help validate across firmware versions and tx shapes before v1.0 release.

---

## License

Docs and Python scripts: MIT-ish / CC0. Referenced upstream projects (`app-bitcoin`, `radiantjs`, `radiant-node`) retain their own licenses.
