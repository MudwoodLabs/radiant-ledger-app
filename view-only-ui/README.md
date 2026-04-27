# Radiant Glyph View-Only — Ledger Demo

Four-mode browser UI that classifies Radiant scriptPubKeys and queries
live address balances against the full node. Demonstrates that Glyph UTXOs
held by a Ledger address are normal, structurally identifiable, and already
fully owned — what's missing upstream is Electron-Wallet's script classifier,
not any on-chain capability.

## Layout

```
view-only-ui/
  index.html                    # single-page UI, ES modules
  classifier.mjs                # pure classifier (imported by UI + tests)
  server.js                     # zero-dep Node proxy → radiant-cli on VPS
  fixtures/
    classifier-vectors.json     # 13 golden vectors from mainnet + synthetic edge cases
    known-refs.json             # FT token refs observed in 500-block scan
    test_classifier.mjs         # node test runner — exit 0 when all pass
```

## Template reference

Derived from a 500-block mainnet scan (tip 420968 → 420469) via
[`../scripts/find_ft_utxo.py`](../scripts/find_ft_utxo.py): 2309 FT samples
across 6 distinct token refs, 100% template conformance.

| Shape | Bytes | Pattern |
|---|---|---|
| Plain P2PKH | 25 | `76a914 <pkh:20> 88ac` |
| NFT singleton | 63 | `d8 <ref:36> 75 76a914 <pkh:20> 88ac` |
| FT holder    | 75 | `76a914 <pkh:20> 88ac bd d0 <ref:36> dec0e9aa76e378e4a269e69d` |

The FT suffix is Radiant's canonical fungibility clause:

- `OP_STATESEPARATOR` (`0xbd`) splits standard P2PKH prologue from FT epilogue — [verified NOP at runtime in interpreter.cpp:1946](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L1946)
- Epilogue uses `OP_CODESCRIPTHASHVALUESUM_{UTXOS,OUTPUTS}` (`0xe3`/`0xe4`) to enforce Σ photon-value of inputs ≥ Σ photon-value of outputs per codeScript hash — [interpreter.cpp:2167-2204](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2167-L2204)

Since the prologue is untouched standard P2PKH, **the Ledger's existing signing
path produces a valid scriptSig without changes.** Proved on mainnet for NFT
singletons: [`22d4e0e0…`](https://explorer.radiantblockchain.org/tx/22d4e0e07200437791b48651125a636b994593b215152241aef7113b24b71da3).

## Run it

```bash
cd view-only-ui

# Terminal A — proxy to VPS radiant-cli (requires ssh access)
node server.js
# → listens on http://127.0.0.1:3999

# Terminal B — static host for the UI (or use any static server)
python3 -m http.server 8788 --bind 127.0.0.1
# → open http://127.0.0.1:8788/ in a browser
```

## The four UI modes

| Tab | What it does | Data source |
|---|---|---|
| **ScriptPubKey Hex** | Paste 1 script → classify & decode ref/pkh | pure client |
| **Tx JSON** | Paste `getrawtransaction <txid> 1` output → classify every vout | pure client |
| **Fetch by TxID** | Enter a txid → proxy calls `getrawtransaction` → UI classifies | `server.js` `/tx/<txid>` |
| **Address Balances** | Enter an address → multi-descriptor `scantxoutset` for P2PKH + all known FT refs | `server.js` `/scan/multi` |

## Why Radiant Core, not Glyph Explorer

Glyph Explorer (`glyph-explorer.rxd-radiant.com`) uses Next.js server components
and doesn't expose a stable public REST API — every obvious endpoint
(`/api/tx/…`, `/rawtx/…`, `/tx/…`) returns 404. `radiantexplorer.com/api/tx/`
does return JSON but **doesn't send CORS headers**, so browsers can't call it.

Radiant Core's RPC surface, on the other hand, is stable and complete for our
needs. The node does not advertise a "glyph explorer" RPC, but it has:

| RPC | Used for |
|---|---|
| `getrawtransaction <txid> 1` | Fetch tx JSON for classification |
| `scantxoutset start '[addr(X)]'` | Find plain P2PKH UTXOs for an address |
| `scantxoutset start '[raw(<spk>)]'` | Find FT/NFT UTXOs for a specific (pkh, ref) |
| `scantxoutset start '[...]'` multi | Batch the above — one UTXO-set scan, all descriptors |
| `getopenorders <token_ref>`, `getswaphistory <token_ref>` | Ref-indexed atomic-swap DEX (not used here, but confirms the node indexes by ref) |

One `/scan/multi` POST does a single UTXO-set pass (~28M entries, ~30s) across
an `addr()` descriptor plus one `raw()` descriptor per known FT token. Verified
against holder `15e1pB2h4Vj9psqaFHEuPMZMf8UPc9cCTr`: 11,295 FT UTXOs found in
one pass.

## server.js routes

| Route | Meaning |
|---|---|
| `GET  /height` | `getblockcount` |
| `GET  /tx/<txid>` | `getrawtransaction <txid> 1` |
| `GET  /scan/addr/<address>` | `scantxoutset start '[addr(…)]'` |
| `GET  /scan/raw/<spk_hex>` | `scantxoutset start '[raw(…)]'` |
| `POST /scan/multi` | `scantxoutset start '[<descriptors>…]'` (body: `{descriptors: [...]}`) |

CORS restricted to `localhost`/`127.0.0.1` origins. Descriptors are validated against `/^(addr|raw)\([0-9a-zA-Z]+\)$/`
to block shell-injection through user input.

Environment: `PORT=3999`, `VPS=user@your-vps-ip` (set to your Radiant node's
SSH target). `ssh` must be able to reach the VPS non-interactively.

## Golden vectors

Run:

```bash
node fixtures/test_classifier.mjs --verbose
```

Expected: `15 passed, 0 failed`. 12 scriptPubKey vectors + 2 round-trip builders
(`buildFtSpk`, `buildNftSpk`) + 1 `refToOutpoint` decode. Any drift in
`classifier.mjs` fails the runner.

## Limitations

- **Address mode only covers known refs.** An address may hold FTs for tokens
  absent from `fixtures/known-refs.json`. To discover new tokens for an address,
  a real wallet needs a ref registry (maintained from the chain's mint history).
  The demo is deliberately scoped to show the classifier + indexer work, not to
  enumerate every conceivable token.
- **`scantxoutset` is expensive.** Each scan walks the full UTXO set
  (~28M entries, ~30s on our VPS). Production wallets would maintain their own
  UTXO index instead.
- **No spending.** Spending uses `scripts/spend_glyph_2in_transfer.py` (transfer-preserving)
  or `scripts/spend_real_glyph_2in.py` (burn) and is documented in
  [`../docs/solutions/integration-issues/radiant-glyph-spend-end-to-end-mainnet.md`](../docs/solutions/integration-issues/radiant-glyph-spend-end-to-end-mainnet.md).

## What this is meant to unlock in Electron-Wallet

The classifier (regex version, fits in a PR comment):

```python
# Plain P2PKH
re.fullmatch(r"76a914[0-9a-f]{40}88ac", spk_hex)
# NFT singleton
re.fullmatch(r"d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac", spk_hex)
# FT holder
re.fullmatch(r"76a914[0-9a-f]{40}88acbdd0[0-9a-f]{72}dec0e9aa76e378e4a269e69d", spk_hex)
```

Downstream code that already handles `("p2pkh", pkh)` treats all three as
spendable by the same private key. Balance views group FT UTXOs by ref.
