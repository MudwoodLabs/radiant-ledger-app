# Phase 0 investigation log

Transient doc. Delete after Phase 1 ships.

## Task 0.0 — LSB-014 path-lock verification

**Runbook:** [`scripts/task-0.0-runbook.md`](scripts/task-0.0-runbook.md)

**Status:** ✅ **PASS**

**Date:** 2026-04-15
**Operator:** eric
**Device:** Nano S Plus (USB 2c97:5000, home-screen state)
**Host:** Linux 6.17.0-20-generic, Ubuntu 24.04

**Outcome:** PASS — Ledger OS permitted an unsigned community app to declare `--path "44'/512'"` at install time. Coin type 512 is usable for the Radiant app.

**Method:**
- Built unmodified `LedgerHQ/app-boilerplate` @ `ac10944e` inside `ledger-app-builder-lite@sha256:b82bfff7...` (Nano S Plus target).
- Sideloaded via `ledgerblue.loadApp` with explicit `--path "44'/512'"` override:
  ```
  python3 -m ledgerblue.loadApp \
    --targetId 0x33100004 --targetVersion="" --apiLevel 25 --tlv \
    --curve secp256k1 --path "44'/512'" --appFlags 0x0 \
    --fileName bin/app.hex --appName "Path512Test" --appVersion "0.0.1" \
    --dataSize 512 --installparamsSize 67 --delete
  ```

**Evidence:**
- User approved "Allow unsafe manager" prompt on device (one-time for session).
- `loadApp` completed without exception; computed `Application full hash : 08d7bcbb887c2e9912ad633a51567e8f5adee486dbbab7b8bbc4f976b05c5e5b`.
- `ledgerblue.listApps` confirmed the installed app, hash matches: `{'name': 'Boilerplate', 'hash': b'\x08\xd7\xbc\xbb\x88|.\x99...'}` — same 32 bytes.
- No additional "this app may sign Bitcoin transactions" or other cross-chain warning observed during install.

**Negative control (attempted `--path "44'/0'"`):** ⚠️ **FAILED TO BLOCK — Bitcoin-path unsigned app installed cleanly.**

Sequence: prior Boilerplate uninstalled → loadApp invoked with `--path "44'/0'"` → device prompted user to approve install → user approved → app installed and runs. No additional Bitcoin-specific warning. No path-related error from loadApp.

**Conclusion:** On current Nano S Plus firmware (2026-04-15), Ledger OS does **NOT** enforce LSB-014 at install time for unsigned community apps. An unsigned app can legitimately declare `--path "44'/0'"` and be sideloaded. Either LSB-014 has been relaxed for unsigned apps, enforcement is runtime-only, or the constraint was never as strict as the research agent claimed.

**Plan impact:**

- The brainstorm and plan listed three reasons for choosing SLIP-44 coin type 512 over 0. Reason #1 (**LSB-014 blocks 44'/0' at install time**) is now empirically falsified and should be removed.
- Reasons #2 (**SLIP-0044 registry standard for RXD**) and #3 (**app-slot collision: both the BTC and Radiant apps would derive identical keys from 44'/0', allowing accidental cross-chain signing**) still fully justify the 512 choice.
- The plan's **runtime path-lock defense** (refusing derivations outside `m/44'/512'/…` in `get_wallet_public_key.c`) becomes even more important now — it's the actual defense against a misbehaving host, not LSB-014.
- Custom-CLA defense-in-depth (deferred to v2) gets slightly more attractive now that app-confusion is empirically possible.

**Main Task 0.0 PASS is unaffected** — 44'/512' still installs cleanly, which is what we need to ship v1.

**Implication:** Phase 1 C work can proceed. The Radiant app's declared path `m/44'/512'/…` will install on end-user devices under the same flow tested here.

---

## Task 0.1 — Derivation cross-check

**Script:** [`scripts/task-0.1-derivation-crosscheck.js`](scripts/task-0.1-derivation-crosscheck.js)

**Status:** ✅ **PASS**

**Date:** 2026-04-15

**Test seed:** standard BIP39 public test vector — `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`. Canonical reference seed; no real funds; widely used to verify BIP32 implementations.

**Script output:**
- `m/44'/0'/0'/0/0` → `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` (PKH `d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa`)
- `m/44'/512'/0'/0/0` → `18qiat9Kff5niCcincht6efD8HhFfzL1AJ` (PKH `55ff8f32c1a7e6a5664609e9f1e07ca396de3fb7`)

**Cross-check:** `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` is the well-known canonical derivation of this public BIP39 vector at `m/44'/0'/0'/0/0`, produced identically by Electrum, Bitcoin Core, iancoleman.io/bip39, Trezor, Ledger, and every other conformant BIP32 implementation. Our script matches. No device derivation needed — the independence comes from using a widely-verified public vector.

**Outcome:** PASS — BIP32/BIP44 math is as expected. No custom entropy handling, no non-standard hardening. `m/44'/512'/0'/0/0` for our Radiant app will derive what `radiantjs` (and any BIP32-compliant lib) computes for the same seed.

**Notes:**
- Using a public test vector instead of the user's real seed avoided a destructive device-wipe just to cross-check math.
- The 512-row address (`18qiat9K...`) is the reference address that Phase 1 integration test will check against when the user loads this seed on the finished Radiant app.

---

## Phase 1 walking skeleton — milestone (2026-04-15)

**Radiant Ledger app live on real hardware.**

C diff: ~58 lines across 5 files in `lib-app-bitcoin@radiant-v1` (commit `6e4228a`):
- `context.h` — new `COIN_KIND_RADIANT` enum value
- `helpers.{h,c}` — `is_radiant_path_allowed()` strict path-lock helper
- `handler/hash_sign.c` — extend SIGHASH_FORKID gate; refuse signing outside m/44'/512'
- `handler/get_wallet_public_key.c` — explicit Radiant arm rejecting CashAddr; refuse derivation outside m/44'/512'

Build:
- `app-radiant@develop` — submodule pinned at `6e4228a`, Makefile `radiant` variant added
- CI matrix builds both `bitcoin_cash` (regression) and `radiant` (new) green
- **Reproducibility verified**: local Docker build SHA256 matches CI artifact SHA256 exactly
  - `app.hex`: `0076b3c7da1659b5310350a8c5fea420f3f7a112ef2a11e40eb4072e7f0076b5`
  - `app.elf`: `6cc604c026479c0817c2da3583a11af263b55d25bf7119ee767f3ea6e71fab2f`

Device:
- Sideloaded to Nano S Plus (developer device, real seed).
- Derived address at `m/44'/512'/0'/0/0`: **`1LkYcHBgsNMvtYfySeZPh29fPrJaVFhMRc`**
- Independently re-derived from device pubkey via Python → byte-identical match
- Pubkey: `0445e713b307d0280d7d621292cfc218d5e649e127c72e8420824ecd246207ea8e7e308375c168ed642b8add3fc2353fca346555e47250973130c2cbf6cea8a9e6`

Runtime path-lock validated against four test cases:
| Path | Outcome | Expected |
|---|---|---|
| `m/44'/512'/0'/0/0` | derives `1LkYcHB...` | succeed ✅ |
| `m/44'/512'/0'/0/1` | derives `15jhhFT...` | succeed ✅ |
| `m/44'/0'/0'/0/0` (Bitcoin) | SW 6a80 | reject ✅ |
| `m/44'/145'/0'/0/0` (BCH) | SW 6a80 | reject ✅ |

Outstanding for Phase 1 finish line:
- Plugin work: modify Electron Radiant `electroncash_plugins/ledger/ledger.py` derivation path constant
- Send RXD to `1LkYcHB...` (user-funded)
- Sign + broadcast a 1-in/1-out send via the Radiant app on Ledger
- Verify mainnet acceptance via `getrawtransaction`

---

## Pins recorded for reproducibility

- `LedgerHQ/app-boilerplate` @ `ac10944e8bfed3d1e57af9a856dd6ab716a74a1b`
- `LedgerHQ/ledger-app-workflows` @ `2ddae7bf080353584b77bd1356c8909c5b8f8257` (still pinned for `guidelines_enforcer.yml` only)
- `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite` @ `sha256:b82bfff7862d890ea0c931f310ed1e9bce6efe2fac32986a2561aaa08bfc2834` (multi-arch index, resolved 2026-04-15)

## Phase 0 bootstrap — CI green

- Fork: [`Zyrtnin-org/app-radiant`](https://github.com/Zyrtnin-org/app-radiant) (from `LedgerHQ/app-bitcoin`)
- Fork: [`Zyrtnin-org/lib-app-bitcoin`](https://github.com/Zyrtnin-org/lib-app-bitcoin) (from `LedgerHQ/lib-app-bitcoin`)
- Submodule URL updated to point at our fork
- Tag: `v0.0.2-bootstrap` at commit `47125ea`
- First green CI: [run 24443131113](https://github.com/Zyrtnin-org/app-radiant/actions/runs/24443131113) (49s, COIN=bitcoin_cash)
- Artifact SHA256:
  - `bin/app.hex`: `cad2edf89307ca53de675ec14cc3bea8968f1357fa0cd3e8b7049c3ad40f117d`
  - `bin/app.elf`: `e9221f220eb710518ab310cba8b87d23187bfd60d711271e267856fbbf416f9d`
- `app.elf` verified as 32-bit ARM EABI5 ELF — correct target for the secure element

### CI deviation from the plan

The plan said "use `LedgerHQ/ledger-app-workflows` reusable workflow." We tried `@v1` and `@SHA` forms — both failed with `startup_failure` in a non-debuggable way on this fork. Replaced the build job with a direct workflow that pulls `ledger-app-builder-lite` by pinned digest. The guidelines_enforcer still uses the reusable workflow (pinned by SHA) because it's an app-quality gate, not the build step.

Unexpected upside: the direct workflow lets us pin the **builder image digest**, which the reusable workflow hardcodes to `:latest`. So reproducibility discipline is stronger than the original plan specified.
