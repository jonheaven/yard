# YARD

Client-side validated notes on unmodified Dogecoin.

L1 stays a payment chain. YARD is optional software. If you delete
it, your DOGE is still DOGE.

See YARD.md for the spec. Review belongs in GitHub issues, not DMs.

## Phase 0

- issue a fixed-supply note
- transfer it
- verify a consignment against your own node

## Not this project

No new Dogecoin opcode. No wrapped DOGE. No YARD token. No EVM.

## Build

    cargo test --workspace
    cargo run -p yard-cli -- --help

Install from git (crates.io `yard` is an unrelated shunting-yard parser):

    cargo install --git https://github.com/jonheaven/yard --locked yard-cli

## Names

GitHub stays `jonheaven/yard`. The English word "yard" is not a mark.

crates.io `yard` is taken. The names to reserve before a public thread:

- crates: `yard-doge`, `yard-core`, `yard-cli`, `yard-index`
- domains: `yard-doge.org` and `yard-doge.dev` (RDAP 404 as of 2026-09-01 — unregistered)
- trademark: the distinctive form (YARD-DOGE / yard-doge), not "yard" alone

This README will point at `yard-doge.org` once that domain is owned.
Do not announce a URL you do not control. `cargo publish` still needs a
crates.io token on this machine.

## Backup

A `.yard` consignment is the history a receiver needs to spend a note.
If you lose it and have no backup, the note cannot be spent even if you
still hold the Dogecoin seal UTXO. That UTXO is still ordinary DOGE.

Tickers are not unique. Wallets must show `ContractId` (e.g. `TEST-a1b2c3d4`).

This is not legal advice. Notes can go to zero.

## Regtest

See `testdata/README.md`. Default RPC: `http://yard:yard@127.0.0.1:18332`.

```
dogecoind -regtest -server -txindex -rpcuser=yard -rpcpassword=yard -rpcport=18332
cargo run -p yard-cli -- new-key --network regtest
dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard generatetoaddress 110 <address>
cargo run -p yard-cli -- genesis --network regtest \
  --rpc http://yard:yard@127.0.0.1:18332 --wif <wif> \
  --tick TEST --name "Test Note" --dec 8 --max 21000000000000000 --seal-doge 0.05
dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard generatetoaddress 6 <address>
cargo run -p yard-cli -- verify --consignment testdata/last_genesis.yard \
  --rpc http://yard:yard@127.0.0.1:18332
```

`yard transfer --to` needs the recipient's compressed pubkey (an address is
only HASH160). Pass `--pubkey <33-byte-hex>` or put the hex in `--to`.

## License

MIT. Spec, test vectors, library, CLI, and reference indexer are public
so a receiver can verify a consignment against Dogecoin without asking
this repo's operator. That is the security model.

There is no YARD token and no contributor coin. Hosted products, the
name, and domains can be a business later. The rules cannot.

Private keys, RPC credentials, and `.yard` files are gitignored.
See SECURITY.md. There is no bounty token.

## Phase 1 (not built)

Open issues after Phase 0 is green:

- [ ] Launch notes: fixed-supply sale paid in L1 DOGE
- [ ] Linear or constant-product curve in genesis meta
- [ ] Replace Anoncoin-style meme launch without a foreign L1
- [ ] Optional larger OP_RETURN envelope behind raised `-datacarriersize`
- [ ] Ticker-collision UX in a wallet, not consensus
- [ ] Reorg test harness on regtest
- [ ] Independent review of encode + sig + seal binding
