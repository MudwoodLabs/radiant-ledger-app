---
title: "feat: Radiant Ledger App v1 (RXD signing on Nano S Plus)"
type: feat
date: 2026-04-14
last_revision: 2026-04-15
---

# Radiant Ledger App v1 — Implementation Plan

> ## 📣 Scope expansion — 2026-04-15 (late)
>
> **Glyph / NFT signing is now in-scope for v1.0** (originally deferred to v2). Reasoning: FlipperHub already signs Glyph mints on mainnet via `blockchain_rpc.php`, which gives us real mainnet Glyph txs as test vectors. The scaffolding we built for Phase 1.5 (oracle, FSM, preimage insertion) extends cleanly to push-refs. Estimated additional work: 3–7 focused days.
>
> Tracked as GitHub issue [`Zyrtnin-org/app-radiant#1`](https://github.com/Zyrtnin-org/app-radiant/issues/1) (Phase 2A — Glyph / GetPushRefs C implementation).
>
> v1.0 scope now: **hardware signing for all standard Radiant txs, including Glyph NFT mint/transfer**. What remains deferred to a true v2: multi-device (Nano X, Stax, Flex), Schnorr signatures, Speculos CI, official Ledger listing. See [Zyrtnin-org/app-radiant#6](https://github.com/Zyrtnin-org/app-radiant/issues/6).
>
> All remaining v1 work is tracked as GitHub issues on `Zyrtnin-org/app-radiant`:
> - #1 Phase 2A — Glyph / GetPushRefs C impl
> - #2 Phase 2B — Hardening & edge-case tx shapes
> - #3 Phase 3 — Community testing & reproducibility
> - #4 Phase 4 — v1.0.0 release prep
> - #5 Dependency cleanup (btchip-python packaging)
>
> ## ⚠️ Scope revision — 2026-04-15
>
> Phase 1 hardware testing discovered that Radiant's signature preimage is NOT byte-identical to BCH, contradicting the original research assumption. Radiant inserts a new `hashOutputHashes` field into the preimage between `nSequence` and `hashOutputs` (see [`radiant-node/src/script/interpreter.cpp:2636-2650`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2636)). This field is present for **every** Radiant tx, including plain P2PKH, carrying zero-ref summaries when no Glyph push-refs are present.
>
> The C diff originally scoped at ~58 lines is sufficient for address derivation and path-lock defense (both verified working on real hardware), but insufficient for signing — Radiant's node rejects our BCH-preimage signatures with "script execution error."
>
> **Real v1 scope now includes**: on-device `hashOutputHashes` computation (~150-300 additional C lines across `hash_input_start.c`, `hash_input_finalize_full.c`, `hash_sign.c`, and `context.{h,c}`). Full details in [`INVESTIGATION.md`](../../INVESTIGATION.md#phase-1-end-to-end-hardware-test-2026-04-15-continued).
>
> Walking-skeleton strategy caught this at ~1 RXD cost, before shipping. Remediation will be scoped via a new `/workflows:brainstorm` pass and a v1-revision plan.

## Overview

Build a sideloadable Ledger Nano S Plus app that signs plain Radiant (RXD) transactions, plus the matching Electron Radiant plugin updates. Distributed as a community fork via reproducible GitHub Actions builds. **v1 = plain P2PKH transfers only; Glyph/NFT support deferred to v2.**

Builds on the brainstorm at [`docs/brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md`](../brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md).

---

## Problem Statement

RXD holders today have no hardware-wallet option. The closed [Electron-Wallet PR #1](https://github.com/Radiant-Core/Electron-Wallet/pull/1) tried to enable Ledger by aligning USB device IDs against the stock Ledger **Bitcoin** app. That cannot work: Bitcoin's signing path produces signatures without `SIGHASH_FORKID`, which Radiant rejects (Radiant inherits BCH-style sighash via [`radiant-node src/script/sighashtype.h:17`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/sighashtype.h#L17)). A **dedicated Radiant Ledger app** is required.

A community member already pointed at the right approach: fork an existing Ledger app (BCH is the obvious candidate because of sighash compatibility), modify the constants and signing dispatch, sideload via `ledgerblue`. This plan executes that path.

---

## Proposed Solution

Fork [`LedgerHQ/app-bitcoin`](https://github.com/LedgerHQ/app-bitcoin) into `Radiant-Core/app-radiant`. Add a `radiant` Makefile variant + a small C diff (one new enum value + two condition extensions). Pair with a plugin-side derivation-path bump in `Radiant-Core/Electron-Wallet`. Distribute as a community sideload via reproducible CI.

**Derivation-path decision:** v1 ships at SLIP-44 coin type **512** (`m/44'/512'/0'`). Two constraints force this:

1. **SLIP-0044 registry** — RXD is registered as 512. Using 0 would conflict with the standard.
2. **App-slot collision** — both the stock Bitcoin app and a Radiant app declaring coin_type 0 would derive identical keys from `m/44'/0'`, allowing accidental cross-chain signing when a host targets the wrong app.

**Note on LSB-014:** The original plan cited Ledger's LSB-014 install-time path lock as a third reason. Phase 0 Task 0.0 testing (2026-04-15) empirically showed that current Nano S Plus firmware does **not** block unsigned community apps from declaring `--path "44'/0'"` at install time. Enforcement is runtime-only (and per-app), which is why the plan's runtime path-lock defense in `get_wallet_public_key.c` matters — it's the *actual* defense, not LSB-014.

This breaks compatibility with existing Radiant wallets (Samara, Electron, Chainbow) which all use `m/44'/0'/0'` — see [How to recover a wallet in Radiant](https://radiant-community.medium.com/how-to-recover-a-wallet-in-radiant-3db3638331a5). v1 ships with **migration documentation**: existing RXD holders send funds from their software-wallet `m/44'/0'` address to a new Ledger-derived `m/44'/512'` address. No automated sweep tool in v1.

---

## Technical Approach

### Architecture

```
┌─────────────────────────────────┐         ┌──────────────────────┐
│ Electron Radiant (Python)        │  USB    │ Ledger Nano S Plus    │
│  electroncash_plugins/ledger/    │ ◄─────► │ ┌─────────────────┐  │
│   - btchip-python (vendored)     │ APDU    │ │ Radiant App     │  │
│   - derivation: m/44'/512'/0'    │  HID    │ │ (forked from    │  │
│   - sighashType=0x41             │         │ │  app-bitcoin)   │  │
│   - reads xpub, builds tx,       │         │ │ - SIGHASH_FORKID│  │
│     sends unsigned for signing   │         │ │ - base58 P2PKH  │  │
└─────────────────────────────────┘         │ │ - on-screen     │  │
                                            │ │   confirmation  │  │
                                            │ └─────────────────┘  │
                                            └──────────────────────┘
```

### The C diff (the "surgical blend")

`lib-app-bitcoin/` (submodule of `app-bitcoin`) is structured around runtime dispatch on a single `COIN_KIND` integer plus a `COIN_FORKID` macro, both injected as `-D` defines from the top-level `Makefile`. **No `#ifdef` gates exist** — the blend is just three small edits.

Concrete changes to the submodule:

```c
// lib-app-bitcoin/context.h — coin_kind_e enum
typedef enum coin_kind_e {
    COIN_KIND_BITCOIN_TESTNET,
    COIN_KIND_BITCOIN,
    COIN_KIND_BITCOIN_CASH,
    // ... existing entries ...
    COIN_KIND_HYDRA,
    COIN_KIND_RADIANT,        // NEW
    COIN_KIND_UNUSED
} coin_kind_t;
```

```c
// lib-app-bitcoin/handler/hash_sign.c  (L120-127)
// EXTEND the gate to include Radiant
if ((COIN_KIND == COIN_KIND_BITCOIN_CASH)
    || (COIN_KIND == COIN_KIND_RADIANT)      // NEW
    || (COIN_FORKID != 0)) {
    #define SIGHASH_FORKID 0x40
    if (sighashType != (SIGHASH_ALL | SIGHASH_FORKID)) { /* error */ }
    sighashType |= (COIN_FORKID << 8);  // 0 for Radiant — same as BCH
}
```

```c
// lib-app-bitcoin/handler/get_wallet_public_key.c  (L100)
// TIGHTEN P2_CASHADDR rejection — explicit Radiant arm, not fall-through.
// Relying on default behavior risks silent inheritance of future upstream changes.
if (p2 == P2_CASHADDR) {
    if (COIN_KIND == COIN_KIND_RADIANT) return SW_INCORRECT_P1_P2;
    if (COIN_KIND != COIN_KIND_BITCOIN_CASH) return SW_INCORRECT_P1_P2;
}
```

```c
// lib-app-bitcoin/handler/get_wallet_public_key.c — runtime path-lock defense
// LSB-014 is enforced at install time. This adds runtime defense-in-depth:
// any derivation outside Radiant's BIP44 coin_type (512) is refused, so a
// compromised host cannot request Bitcoin-namespace keys under this app.
if (COIN_KIND == COIN_KIND_RADIANT) {
    // First unhardened child of m/44'/... must be 512 (0x80000200)
    if (bip32_path[0] == HARDEN(44) && bip32_path[1] != HARDEN(512)) {
        return SW_INCORRECT_DATA;
    }
}
```

Top-level `app-bitcoin/Makefile` — add a new variant stanza:

```makefile
else ifeq ($(COIN),radiant)
APPNAME = "Radiant"
APPVERSION = "1.0.0"
BIP44_COIN_TYPE = 512
BIP44_COIN_TYPE_2 = 512
COIN_P2PKH_VERSION = 0
COIN_P2SH_VERSION = 5
COIN_FAMILY = 1
COIN_COINID = "Radiant"
COIN_COINID_NAME = "Radiant"
COIN_COINID_SHORT = "RXD"
COIN_KIND = COIN_KIND_RADIANT
COIN_FORKID = 0
DEFINES += BIP44_COIN_TYPE_2=$(BIP44_COIN_TYPE_2)
ICONNAME = icons/nanos_app_radiant.gif
endif
```

Custom Radiant icon (`glyphs/nanos_app_radiant.gif`, `glyphs/nanox_app_radiant.gif`, `icons/nanos_app_radiant.gif`) sourced from the existing Radiant brand assets. **Branding only — no code logic depends on it.**

### Named design decisions

Decisions that would otherwise be discovered during testing. Name them now to make the walking-skeleton phase mechanical.

- **Change-output detection.** The host (Electron Radiant plugin) tells the device which output is change by flagging the output's BIP32 path in the `TRUSTED_INPUT` / `FINALIZE_INPUT` APDUs — same mechanism the `bitcoin_cash` variant uses. Change outputs are not shown on-device. Recipient outputs are always shown.
- **APDU buffer limit / max inputs.** Inherits the upstream `app-bitcoin` limit (~20 inputs is the practical ceiling on Nano S Plus before APDU chunking edge cases appear). Document this as a hard max in `INSTALL.md`; the plugin rejects txs exceeding it client-side with a clear error. No device-side chunking rework in v1.
- **Fee display unit.** RXD with 8 decimal places (e.g. `0.00012345 RXD`). Uses the same `format_sats_as_RXD` formatter pattern as `bitcoin_cash` uses for BCH, with `COIN_COINID_SHORT="RXD"` threaded through.
- **"Not genuine" banner UX.** Ledger OS shows it on every app launch for any unsigned community app — not under our control. The plugin displays a one-time wizard notice on first pairing explaining the banner is expected. No per-launch dismissal state maintained.
- **Upstream rebase cadence.** The `Radiant-Core/lib-app-bitcoin` fork rebases onto upstream `LedgerHQ/lib-app-bitcoin` at each minor upstream release, behind a feature branch; maintainer reviews and merges to `main`. Not automated in v1.

### Plugin diff (minimal)

`Radiant-Core/Electron-Wallet/electroncash_plugins/ledger/ledger.py`:

```python
# Line 590 — was: "m/44'/0'/0'"  comment "BIP44 coin type 0 (Bitcoin/Radiant)"
client.get_xpub("m/44'/512'/0'", 'standard')  # SLIP-44 RXD

# Line 96 docstring — was: "44'/0'/1'"
# 44'/512'/x' for hardware wallets only; software wallets remain on 44'/0'/x'
```

Plus:
- Update plugin description in `electroncash_plugins/ledger/__init__.py` to say "Hardware wallets use BIP44 path m/44'/512'/0' (RXD); software-wallet seeds at m/44'/0' must be migrated."
- Add a guard in the wizard flow that warns the user if their seed already has UTXOs at `m/44'/0'` (informational only — Electron Radiant's existing scan logic can detect this).

**Already correct, no change:** CLA byte `0xe0` (line 134), `sighashType=0x41` (line 473), USB PIDs covering Nano S Plus (line 549), `witness: True` on inputs (lines 439, 445).

### Implementation Phases

#### Phase 0: Repo bootstrap & build reproducibility (~3 days)

Goal: a CI-built `bin/app.hex` that two contributors building from the same tag get the same SHA256 for. Also: confirm before any code that the Ledger OS will actually let us ship at `m/44'/512'`.

**Task 0.0 (BLOCKING) — Verify Ledger OS allows `--path "44'/512'"` for unsigned community apps.**

Before any code work: take any existing community Ledger app (e.g. `LedgerHQ/app-boilerplate` built unmodified) and sideload it to a Nano S Plus with `--path "44'/512'"` instead of its native path. Three outcomes:

- **Pass**: device prompts the standard "Allow unsafe manager / Install unverified app" flow and the app launches. Project proceeds.
- **Fail (path lock)**: device or `loadApp` rejects with a path-related error. **Stop. The plan as written is infeasible.** Re-evaluate: is there a different SLIP-44 number Ledger permits? Is the only option pursuing official Ledger sponsorship?
- **Warn**: install succeeds but device shows an additional/unexpected warning. Document the warning, decide whether it's user-acceptable, then proceed.

This is a ~2-hour task that can prevent ~5 weeks of wasted work. Do it first.

**Task 0.1 (BLOCKING) — Verify `radiantjs` derivation at `m/44'/512'/0'/0/0` is mathematically equivalent to a stock BTC Ledger deriving at `m/44'/0'/0'/0/0` (modulo coin_type).**

~30-minute check. With the same test seed: (a) use `radiantjs` (or any BIP32 library) to derive a pubkey at `m/44'/512'/0'/0/0`. (b) Install stock Ledger Bitcoin app, derive pubkey at `m/44'/0'/0'/0/0`. Both should produce the same extended-key math (different coin_type → different keys, but the derivation algorithm should be identical — test by swapping the coin_type integer in a script and verifying the Ledger pubkey matches). Confirms no surprise BIP32 divergence before any C work.

Tasks (after 0.0 and 0.1 pass):
- Create `Radiant-Core/app-radiant` as a fork of `LedgerHQ/app-bitcoin` (preserve fork relationship for upstream rebase later).
- Fork [`LedgerHQ/lib-app-bitcoin`](https://github.com/LedgerHQ/lib-app-bitcoin) to `Radiant-Core/lib-app-bitcoin`. The C diff lives in this fork; the `app-radiant` repo's submodule pin points here. Upstream PR is best-effort and orthogonal to shipping.
- Initialize submodule at `lib-app-bitcoin/` pinned to a specific commit on the `Radiant-Core` fork (record the SHA in `BUILDER.md`).
- Wire CI by **using the `LedgerHQ/ledger-app-workflows` reusable workflow directly** (don't copy-modify boilerplate). Reference it by commit SHA, not tag (`uses: LedgerHQ/ledger-app-workflows/.github/workflows/reusable_build.yml@<sha>`). Record SHA in `.github/WORKFLOWS_PIN`.
- Configure the reusable workflow with:
  - Pinned `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:<digest>` (record digest in `.github/BUILDER_DIGEST`).
  - Build only the `radiant` variant (`make COIN=radiant`).
  - `SOURCE_DATE_EPOCH`, `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1` env.
  - Uploads `bin/app.hex`, `bin/app.elf`, and `BUILD_INFO.txt` (the printed `APP_LOAD_PARAMS` line + `sha256sum`).
- Add `BUILDER.md` with: how to reproduce the build locally on Linux/macOS (Apple Silicon needs `--platform linux/amd64`), how to verify the SHA256 matches a release.
- Tag a `v0.0.1-bootstrap` to validate the workflow end-to-end (no Radiant code yet — produce the unmodified `bitcoin_cash` variant just to prove the pipeline).

Deliverables:
- Task 0.0 and 0.1 pass (recorded in an `INVESTIGATION.md` note — delete after Phase 1 ships)
- Green CI on every push
- At least 1 non-author verifies they get the same SHA256 from a clean clone of the bootstrap tag
- `BUILDER.md` checked in

#### Phase 1: Walking skeleton — first confirmed mainnet tx (~7 days)

Goal: the crudest possible end-to-end signing pipeline working on mainnet. C diff + plugin change + first sign all in one interleaved phase so integration surprises surface immediately, not after weeks of sunk cost.

Tasks (interleave; don't finish all C before touching the plugin):

*C app changes:*
- Add `COIN_KIND_RADIANT` to `lib-app-bitcoin/context.h`. Submit best-effort upstream PR to `LedgerHQ/lib-app-bitcoin`, but ship from our fork pin.
- Extend `lib-app-bitcoin/handler/hash_sign.c:120` gate with `COIN_KIND_RADIANT`.
- Explicit `COIN_KIND_RADIANT` arm in `get_wallet_public_key.c` rejecting `P2_CASHADDR` (not fall-through).
- Add runtime path-lock defense in `get_wallet_public_key.c`: refuse any derivation outside `m/44'/512'/…` with `SW_INCORRECT_DATA`.
- Add `radiant` variant block to top-level `Makefile`.
- Convert Radiant logo to GIF formats for `glyphs/` and `icons/`.
- Update `ledger_app.toml` to declare the `radiant` variant.
- First clean build: `make COIN=radiant`. Resolve any `DEFINES` gaps (e.g. `COIN_FORKID` not threaded when the `bitcoin_cash` stanza assumes it).

*Plugin changes:*
- Fork or branch `electroncash_plugins/ledger/`.
- Derivation-path change at line 590: `m/44'/0'/0'` → `m/44'/512'/0'`.
- Update `__init__.py` description.
- Add migration warning surface in the wizard (text-only).
- Smoke-test: plugin imports succeed, wizard renders, plugin appears in hardware-wallet list.

*First sign:*
- Sideload the built `app.hex` to a Nano S Plus: `python -m ledgerblue.loadApp --targetId 0x33100004 --apiLevel <pinned> --tlv --curve secp256k1 --path "44'/512'" --appFlags 0x000 --fileName bin/app.hex --icon "$(python3 -m ledgerblue.icon3 --hexbitmaponly icons/nanos_app_radiant.gif)" --appName "Radiant" --appVersion "1.0.0" --dataSize 0 --delete`. Record the exact command.
- Pair with Electron Radiant. Derive an address. Cross-check against `radiantjs` derivation from the same seed at `m/44'/512'/0'/0/0`.
- Send a small amount of RXD from another wallet to the derived address.
- Build a 1-input/1-output send in Electron Radiant. Sign on device. Capture every device screen. Broadcast.
- Verify mainnet acceptance via `getrawtransaction <txid>`.

Deliverables:
- `make COIN=radiant` produces `bin/app.hex` reproducibly via CI
- One confirmed mainnet RXD tx signed by Ledger
- Annotated screenshots of every device screen
- Plugin branch merged to its feature branch
- The exact `loadApp` command, recorded for INSTALL docs
- C diff <50 lines excluding Makefile / assets

#### Phase 2: Hardening & edge cases (~5 days)

Goal: handle the tx shapes real users will hit. Drive every surfaced flow gap to a tested, documented behavior.

Test cases (each must produce a confirmed mainnet tx OR a documented rejection):
- 1-in / 2-out (with change)
- 5-in / 2-out (multi-input consolidation)
- 10-in / 1-out (large consolidation; stresses APDU buffer)
- Spending a coinbase UTXO (RXD mining payout; verify mature-coinbase rule)
- Tx with OP_RETURN output
- Tx where one input is a Glyph-bearing UTXO spent as plain RXD (should sign as opaque script; if device chokes, **document the limitation, do not fix in v1**)

Per failure / rejection, decide: fix in v1, document as known limitation, or defer to v2.

Plugin-side flow handling:
- Device rejection (user presses ✗ during signing) → plugin shows a clear error, doesn't leave the wallet stuck.
- Device disconnect mid-sign → plugin surfaces a clean error.
- "Not genuine" banner — one-time wizard notice explaining it is expected on community apps.

Display verification:
- Fee unit on device: RXD with 8 decimals (not satoshis).
- Address rendering: base58 (`1...` prefix), not CashAddr.

Deliverables:
- Tested tx-shape evidence (txids) captured in the README test-matrix section
- Documented known limitations
- Plugin handles all rejection paths gracefully

#### Phase 3: Community validation (~2 weeks calendar)

Goal: independently verify reproducibility and broaden firmware/device coverage. Small cohort, focused signals.

Tasks:
- Recruit 3-5 community testers from the Radiant Discord. Provide each with: `INSTALL.md`, the release `bin/app.hex`, the published SHA256, and the `loadApp` command.
- **Reproducibility**: at least 1 non-author runs `docker run` against the pinned digest + `make COIN=radiant` and confirms the SHA256 matches the release. (Post-release verifications happen organically and do not block shipping.)
- **Firmware coverage**: collect at least 2 distinct Nano S Plus firmware versions across the cohort.
- **Host coverage**: Linux + macOS primary in v1. Windows is best-effort only — accept reports but don't block release on Windows issues (Zadig/WinUSB landscape is a v1.1 problem).
- Each tester sends one small mainnet tx (assigned shape).
- Collect: device screen photos, txids, errors, install issues.

Assigned shapes:
| Tester | Firmware | Tx shape | OS |
|---|---|---|---|
| #1 (lead dev) | current | 1-in/1-out | Linux |
| #2 | current | 1-in/2-out (change) | Linux or macOS |
| #3 | previous | 5-in/2-out | any |
| #4 | any | coinbase input | any |
| #5 | any | sweep from old m/44'/0' (migration test) | any |

Release gate: all testers' txids confirmed on mainnet + ≥1 non-author reproducibility match + zero reports of stuck or lost funds.

Deliverables:
- All testers' txids confirmed
- ≥1 independent reproducibility match
- Issues filed for any divergence

#### Phase 4: Release & docs (~3 days)

Tasks:
- Tag `v1.0.0` on `Radiant-Core/app-radiant` and the plugin branch on `Radiant-Core/Electron-Wallet`.
- GitHub release on `app-radiant` includes: `app.hex`, `app.elf`, `BUILD_INFO.txt`, `SHA256SUMS`, the `loadApp` command, link to `INSTALL.md`.
- Record the submodule SHA of `Radiant-Core/lib-app-bitcoin` as a release artifact (`SUBMODULE_PIN.txt`) so anyone rebuilding can pin correctly.
- `INSTALL.md` published (prereqs, install command, on-device prompts walkthrough, "not genuine" banner explained, mid-way install recovery).
- `BUILDER.md` published (reproducibility steps).
- `README.md` published as the single home for: what this is, migration guide (m/44'/0' → m/44'/512'), tested tx-shape evidence (txids), security model ("private keys stay on device; BCH-seed replay warning; don't trust unofficial binaries").
- Announce in Radiant Discord + Medium post.

Deliverables:
- v1.0.0 tagged and released
- `README.md`, `INSTALL.md`, `BUILDER.md` published
- Public announcement

---

## Alternative Approaches Considered

**Clean-slate app from `LedgerHQ/app-boilerplate`.** Cleaner code, newer SDK, easier maintenance long-term. Rejected: requires re-implementing the BIP143-style sighash with `SIGHASH_FORKID` from scratch — a meaningful amount of additional C work and on-device debugging for no new capability. The BCH signing path in `app-bitcoin` is battle-tested across dozens of variants. Revisit for v3+ when Glyph parser work might justify a clean break.

**Modify the stock Ledger Bitcoin app via host-side workaround.** What the closed PR #1 implicitly attempted. Rejected: the BTC app does not set `SIGHASH_FORKID` on its signatures (only the `bitcoin_cash` variant does). No host-side patching can make BTC signatures valid for Radiant.

**Use coin_type 0 (`m/44'/0'`) to maintain ecosystem compatibility.** Rejected because both the BTC and Radiant apps would derive the same keys from the same seed under `m/44'/0'`, allowing accidental cross-chain signing when a host targets the wrong app. Empirically Ledger OS does not prevent us from *declaring* this path (Phase 0 Task 0.0 showed install succeeds), but the app-slot collision risk is unbounded — host software could send a Radiant-shaped APDU to the Bitcoin app and obtain a BCH-style signature over a Radiant preimage, or vice versa.

**Dual-path support (accept both 0' and 512' during transition).** Considered. Rejected for v1 because it just enshrines the app-slot collision risk across two paths instead of one, doubling the confusion surface with no compensating benefit. Reconsider in v2 only if the ecosystem converges on 512.

---

## Acceptance Criteria

### Functional Requirements

- [ ] `make COIN=radiant` against the pinned builder image produces `bin/app.hex` with a SHA256 reproducible across machines
- [ ] Sideloading via `python -m ledgerblue.loadApp` on a stock Nano S Plus succeeds and the app launches
- [ ] App derives a P2PKH address at `m/44'/512'/0'/0/0` matching what `radiantjs` derives from the same seed
- [ ] App displays the receive address on-device for user confirmation, in base58 format (no CashAddr)
- [ ] App **refuses** derivation requests outside `m/44'/512'/…` (runtime path-lock defense), returning `SW_INCORRECT_DATA`
- [ ] App signs a 1-in/1-out RXD spend; signature accepted by Radiant mainnet
- [ ] App signs a 1-in/2-out spend with change; mainnet-confirmed
- [ ] App signs a multi-input consolidation (5+ inputs); mainnet-confirmed
- [ ] App signs a coinbase-input spend (mining payout); mainnet-confirmed
- [ ] On-device fee display shows RXD with 8-decimal precision, not satoshis
- [ ] Electron Radiant plugin completes the "Use a hardware device" wizard end-to-end with the new app

### Non-Functional Requirements

- [x] CI on every push produces an artifact whose SHA256 matches a separately-built local artifact (reproducible build) — *Phase 0 v0.0.2-bootstrap build green; CI artifact sha256 published in SHA256SUMS*
- [ ] ≥1 non-author verifies reproducibility from clean clone
- [ ] ≥2 distinct Nano S Plus firmware versions tested
- [ ] App fits in default Nano S Plus app-flash budget (no `dataSize` overflow)
- [x] No regression to the upstream `app-bitcoin` variants (`bitcoin_cash` still builds — build-only smoke test) — *COIN=bitcoin_cash built green in CI run 24443131113*
- [x] `ledger-app-workflows` referenced by commit SHA, not tag — *guidelines_enforcer.yml pinned at 2ddae7bf; build step switched to direct workflow with pinned builder-image digest (stronger than SHA-pinning the wrapper)*

### Quality Gates

- [ ] `INSTALL.md` walks a non-developer Nano S Plus owner through install in <10 minutes (Linux + macOS)
- [x] `BUILDER.md` lets a contributor reproduce the release artifact byte-for-byte — *initial version published in app-radiant, Phase 0*
- [ ] `README.md` includes: migration guide (m/44'/0' → m/44'/512' with screenshots), tested tx-shape evidence (txids), security model (device protections + BCH-history replay warning)
- [ ] Migration warning surfaces in the Electron Radiant wizard before users commit funds

---

## Success Metrics

Leading indicators that matter:

- **Reproducibility verified by a non-author** — the strongest signal that distribution is trustworthy
- **Zero reports of stuck funds, wrong-network signing, or signing of unintended addresses** — the only bug class that actually threatens user value

Adoption counters (installs / mainnet-txs-per-month) are explicitly **not** release gates. They're Discord noise, not correctness signals.

---

## Dependencies & Prerequisites

- **Hardware**: at least 2 Nano S Plus devices for the core dev (one stable test device, one for upgrade/firmware experiments). Estimated $160.
- **Upstream**: `LedgerHQ/lib-app-bitcoin` accepts a `COIN_KIND_RADIANT` enum addition (or we ship from a fork pin indefinitely — both viable).
- **GitHub org**: ability to create a new repo under `Radiant-Core` (org admin access required).
- **Radiant node**: a working mainnet node to broadcast test transactions and query confirmations. Existing FlipperHub `radiant-mainnet` Docker container suffices.
- **Builder image stability**: `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite` continues to be published and signed by Ledger.

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LSB-014 path lock blocks `44'/512'` for unsigned apps | **Disproven 2026-04-15** | — | Task 0.0 confirmed install-time path lock is NOT enforced for unsigned apps on current Nano S Plus firmware. Runtime path-lock defense in `get_wallet_public_key.c` remains the correct protection |
| Cross-chain signature replay — a Radiant signature is bit-identical to a BCH signature over the same preimage (both `SIGHASH_ALL\|FORKID=0x41`, forkid=0). Any user whose seed has BCH history is exposed | Medium (given BCH is widely supported) | High for affected user | Runtime path-lock defense (refuse non-512 paths) helps *for this app's signing requests*, but cannot stop a user from importing a BCH-exposed seed. Prominent warning in README security section: "do not import a seed with BCH history" |
| Supply-chain compromise of `Radiant-Core` org or `ledger-app-workflows` reusable workflow | Low | Very high | Pin `ledger-app-workflows` by commit SHA (not tag). Pin builder image by digest. Reproducible builds mean any tester can detect divergence post-release. Consider GPG signatures on release artifacts in v1.1 |
| Malicious evil-twin `.hex` distributed via phishing (fake repo, fake Medium post) | Medium | Very high for affected users | Canonical release URL pinned in Radiant node README / chainparams commit / Discord pins. README states: "only install from `github.com/Radiant-Core/app-radiant/releases`. Verify SHA256 before running `loadApp`." No technical fix; defense is education + canonical source |
| Upstream `app-bitcoin` is deprecated mid-project (Ledger pushes everyone to a new SDK) | Low | High | Pin submodule SHA. Worst case: keep building from the pin; revisit clean-slate fork in v2 |
| Reproducible builds fail intermittently due to unpinned dependency in `ledger-app-builder-lite` | Medium | Medium | Pin by digest, not tag. Document the digest in `BUILDER_DIGEST`. If digest changes, re-verify reproducibility before bumping |
| User installs and sends RXD to Ledger address before reading migration docs, then loses access to old `m/44'/0'` funds | Medium | High for affected user | The old funds are not lost — they remain in the software wallet at the original path. Migration docs and in-wizard warning emphasize this |
| Community tester finds a tx shape the device can't sign (e.g. APDU buffer overflow on huge consolidation) | High | Low — falls back to "use software wallet for that tx" | Document tx-shape limits in `TESTING.md`. v1 ships with known limits, not zero |
| Glyph-bearing UTXOs can't be spent as plain RXD via v1 app | Medium | Low — niche use case | Document as known limitation. v2 will fix when adding Glyph parser |
| The "not genuine" banner scares users into not using the app | Medium | Medium for adoption | Address head-on in `INSTALL.md` and the wizard notice. Compare to BCH/BTG community apps that lived with this for years |
| Single maintainer departure | Low | Medium | Reproducible CI + Radiant-Core org ownership = anyone can pick up. No personal signing keys |

---

## Resource Requirements

- **People**: 1 developer comfortable with C and Python (the lead), 3-5 community testers
- **Time**: ~3 weeks of focused dev work + ~2 weeks calendar for community testing = ~5 weeks total
- **Infra**: GitHub Actions minutes (free for public repo), Radiant mainnet node (existing), 2x Nano S Plus

---

## Future Considerations

**v2 — Glyph / NFT support.** Will require teaching the C app's script parser to recognize Radiant's V2 opcodes (`OP_PUSHINPUTREFSINGLETON` = `0xd8`, K12, BLAKE3, etc.). Significant work in `lib-app-bitcoin/transaction.c` parser. Test fixtures will come from FlipperHub's `blockchain_rpc.php` (golden unsigned-tx → expected-sig pairs) — see [v1→v2 Bridge in brainstorm](../brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md#v1-→-v2-bridge).

**Additional v2 items surfaced during Phase 1 hardware testing** (full list in [2026-04-15 remediation brainstorm "v2 Tracking" section](../brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md#v2-tracking-items-surfaced-during-this-brainstorm)):

- Real `GetPushRefs` opcode-aware scanning of output scriptPubKeys (replaces v1's canonical-P2PKH short-circuit)
- Relax canonical-P2PKH output check — enables sends to P2SH addresses and OP_RETURN memos
- `SIGHASH_SINGLE` preimage path (Radiant's SINGLE construction differs from ALL/NONE)
- `SIGHASH_ANYONECANPAY` support
- Schnorr signature emission (shorter sigs → lower fees)
- Speculos / Ragger emulator CI test harness
- Device UX for Glyph-specific signing (show token name? ref ID?)

**v3 — Device coverage expansion.** Nano X (BLE complexity), Stax/Flex (NBGL UI rewrite). Demand-driven.

**v4 — Official Ledger listing.** Submit through Ledger's review process. Requires security audit (~$30-80k budget per audit firm) and a formal Ledger relationship. Justified only after sustained adoption.

**Possible never:** WebHID web-wallet integration. Not on roadmap unless a Radiant web wallet emerges.

---

## Documentation Plan

Collapsed to three documents. Split further only if size demands it.

To be created in this repo:
- `README.md` — single home for: what this is, who it's for, migration guide (m/44'/0' → m/44'/512' with screenshots), tested tx-shape evidence (txids), security model ("private keys stay on device; BCH-seed replay warning; only install from the canonical release URL; verify SHA256")
- `INSTALL.md` — step-by-step sideload instructions for Linux + macOS (primary). Windows is best-effort only in v1
- `BUILDER.md` — reproducibility instructions for contributors

To be updated in `Radiant-Core/Electron-Wallet`:
- `Ledger.md` — new install path, derivation-path change, link to the README migration section
- `electroncash_plugins/ledger/__init__.py` — plugin description string

---

## References & Research

### Internal References

- Brainstorm: [`docs/brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md`](../brainstorms/2026-04-14-radiant-ledger-app-v1-brainstorm.md)
- Closed PR that started this: [`Radiant-Core/Electron-Wallet#1`](https://github.com/Radiant-Core/Electron-Wallet/pull/1)

### Radiant Ecosystem

- Network constants: [`radiant-node/src/chainparams.cpp:193-198`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/chainparams.cpp#L193)
- Sighash: [`radiant-node/src/script/sighashtype.h:17`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/sighashtype.h#L17)
- Ecosystem derivation paths (Samara, Electron, Chainbow): [How to recover a wallet in Radiant](https://radiant-community.medium.com/how-to-recover-a-wallet-in-radiant-3db3638331a5)
- SLIP-44 registry entry for RXD: [`satoshilabs/slips slip-0044.md`](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) — `512 | 0x80000200 | RXD | Radiant`
- Existing plugin: [`Radiant-Core/Electron-Wallet/electroncash_plugins/ledger/ledger.py`](https://github.com/Radiant-Core/Electron-Wallet/blob/master/electroncash_plugins/ledger/ledger.py)
- Glyph protocol context (for v2 planning later): [`Zyrtnin-org/radiant-glyph-nft-guide`](https://github.com/Zyrtnin-org/radiant-glyph-nft-guide)
- Reference signing implementation: [`Zyrtnin-org/Flipperhub/blockchain_rpc.php`](https://github.com/Zyrtnin-org/Flipperhub/blob/master/blockchain_rpc.php)

### Ledger Tooling

- App template to fork: [`LedgerHQ/app-bitcoin`](https://github.com/LedgerHQ/app-bitcoin) (with submodule [`LedgerHQ/lib-app-bitcoin`](https://github.com/LedgerHQ/lib-app-bitcoin))
- Reference wiring for CI: [`LedgerHQ/app-boilerplate`](https://github.com/LedgerHQ/app-boilerplate)
- Reusable workflows: [`LedgerHQ/ledger-app-workflows`](https://github.com/LedgerHQ/ledger-app-workflows)
- Builder image: [`ghcr.io/ledgerhq/ledger-app-builder`](https://github.com/LedgerHQ/ledger-app-builder)
- Sideloader: [`LedgerHQ/blue-loader-python`](https://github.com/LedgerHQ/blue-loader-python)
- Path-lock constraint: [LSB-014 (Ledger Donjon)](https://donjon.ledger.com/lsb/014/)
- Developer portal — app permissions / curves / paths: [https://developers.ledger.com/docs/device-app/references/app-permissions](https://developers.ledger.com/docs/device-app/references/app-permissions)
- Linux udev rules: [`LedgerHQ/udev-rules`](https://github.com/LedgerHQ/udev-rules)

### Reference Community Forks (for reproducibility patterns)

- [`Zondax/ledger-tezos`](https://github.com/Zondax/ledger-tezos)
- [`Concordium/concordium-ledger-app`](https://github.com/Concordium/concordium-ledger-app)
- [`hhanh00/zcash-ledger`](https://github.com/hhanh00/zcash-ledger) — example Nano S Plus loadApp command
- [`wavesplatform/ledger-app-waves`](https://github.com/wavesplatform/ledger-app-waves) — Makefile `--dataSize` handling
