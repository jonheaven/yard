# YARD

Client-side validated notes on unmodified Dogecoin.

L1 stays a payment chain. YARD is optional software. If you delete
it, your DOGE is still DOGE.

**Not a Doginal.** On-chain you only get a fingerprint; the note lives in a
`.yard` file sealed to a UTXO. See [docs/VS_DOGINALS.md](docs/VS_DOGINALS.md).

**Launch plan:** [GAMEPLAN.md](GAMEPLAN.md) — Burn a Wow on
[dogecoin.dog/yard](https://dogecoin.dog/yard) (Dojak web wallet).

See YARD.md for the spec. Review belongs in GitHub issues, not DMs.

## Phase 0

- issue a fixed-supply note
- transfer it
- burn it
- verify a consignment against your own node
- `show` / `export` / `backup` so a lost `.yard` file is survivable
- wallets print `TICK-a1b2c3d4`, never the ticker alone

## Phase 1

Launch is a coordinated sale plus client-validated inventory. It is
not an AMM and not miner-enforced.

- genesis `--curve lin|cpmm --treasury <addr>`
- `launch-buy` / `launch-sell` paid in L1 DOGE (no wrap, no VM)
- raise goes to a treasury P2PKH in the same L1 transaction
- the published price is checked by YARD software, not by miners
- a published pool key can be grief-spent as plain DOGE; the dust
  seal dies; already-sold notes survive
- sells need someone to fund the L1 DOGE refund; nothing in Core
  forces the treasury to pay

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
`yard show` and `yard verify` print that form; they never treat the ticker as an id.

Mutating commands write a second copy under `.yard/` (override with `--backup-dir`, skip with `--no-backup`).

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

## Status

Built:

- [x] Launch notes: coordinated sale paid in L1 DOGE (not an AMM)
- [x] Linear or `cpmm` price in genesis meta, checked by software
- [x] Anoncoin-style meme launch without a foreign L1
- [x] Ticker-collision UX: CLI prints `TICK-a1b2c3d4`, never ticker-only
- [x] Consignment backup/export so lost-file is survivable

Product path (see [GAMEPLAN.md](GAMEPLAN.md)):

- [x] Gameplan + vs-Doginals docs
- [x] dogecoin.dog `/yard` + `/yard/burn` lab surface (`dogenals/web-com`)
- [x] Dojak commitment encode/decode stub (`dojak/docs/YARD.md`)
- [ ] Dojak: protect seal UTXOs · verify `.yard` · tip/burn
- [ ] One public WOW drop + live burn wall
- [ ] Reorg test harness on regtest
- [ ] Independent review of encode + sig + seal binding

Still open / parked:

- [ ] Optional larger OP_RETURN envelope behind raised `-datacarriersize`
- [ ] Phase 2 channels (needs CSV)
- [ ] Phase 3 batch execution — parked. Do not start.
