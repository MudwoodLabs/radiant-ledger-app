**Two Radiant Glyph Releases: FT Support in the NFT Guide + View-Only Glyph Renderer**

We're shipping two complementary updates to the community Radiant Ledger + Glyph tooling.

**radiant-glyph-nft-guide -- now covers Fungible Tokens**

The implementation guide that AI agents and developers use to build on the Glyph protocol now documents both NFTs *and* FTs:

- **FT holder template (75 bytes)** fully decoded: `76a914 <pkh> 88ac bd d0 <ref> dec0e9aa76e378e4a269e69d` -- the P2PKH + conservation epilogue verified against 2,309 mainnet FT samples across 6 tokens with 100% template conformance
- **Wallet classifier regex** for all three spendable script shapes (P2PKH / NFT singleton / FT holder) -- drop these into Electron-Wallet and Glyph UTXOs become visible in the Coins tab
- **FT conservation mechanism** decoded from Radiant Core source: `OP_STATESEPARATOR` splits prologue from epilogue; `OP_CODESCRIPTHASHVALUESUM` opcodes enforce inputs >= outputs per token
- **CID validation** section added after discovering a 58-char truncated CID bug in production -- one character short makes the NFT invisible on every IPFS gateway
- V2 fee rates, infrastructure setup, proc_close exit-code fix, on-chain thumbnail generation, and more from a full day of real-world minting

https://github.com/Zyrtnin-org/radiant-glyph-nft-guide

**radiant-ledger-app -- Glyph View-Only Renderer**

A browser-based tool that classifies and renders Glyph NFT + FT assets for any Radiant address, powered by Radiant Core RPC:

- **Classify** any scriptPubKey as P2PKH, NFT singleton (63B), FT holder (75B), or unknown -- with 15/15 golden-vector tests from real mainnet
- **Render on-chain metadata**: token name, ticker, description, protocol type, and embedded images decoded from CBOR in reveal transactions
- **End-to-end verified**: Glyph Protocol FT renders with its 521x520 on-chain PNG; FlipperHub NFTs render with full metadata + IPFS images
- **Ledger compatible**: FT/NFT spend signatures are standard `<sig> <pubkey>` -- Ledger's existing P2PKH signing handles Glyph UTXOs without firmware changes. First mainnet Ledger Glyph spend confirmed: `22d4e0e072...`
- **Security reviewed**: 4-reviewer audit, all CBOR strings HTML-escaped, IPFS fetches proxied locally, no hardcoded credentials, no IP leaks

https://github.com/Zyrtnin-org/radiant-ledger-app (view-only-ui/ directory)

**Why this matters**: Electron-Wallet integration is the next step. These three classifier patterns are the one-line fix that makes Glyph assets visible in the desktop wallet. Community can test the view-only tool now and help validate before the wallet PR.

**Try it**: clone the repos, point the view-only renderer at your address, and see your Glyph assets rendered from chain data. Report issues on GitHub. If you're running a Ledger Nano S Plus with the Radiant app, we'd especially appreciate testing on different firmware versions.
