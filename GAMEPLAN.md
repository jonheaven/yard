# YARD launch gameplan

Make something Shibes remember: sticky-note collectibles on real DOGE,
not another bridge and not another Doginal.

Status: protocol Phase 0 + Phase 1 CLI exist. Product surface starts here.

## One-line pitch

YARD seals an off-chain note to one Dogecoin UTXO and puts only a hash in
OP_RETURN. Spend the coin without a handoff and the note dies; the DOGE
stays ordinary money.

## YARD vs Doginals (read this first)

| | **Doginal** | **YARD note / stamp** |
|---|---|---|
| What it is | Content inscribed **on** Dogecoin (commit→reveal) | Off-chain note **sealed to** a UTXO |
| On-chain data | Full payload (image/JSON/…) in the reveal | ~40-byte `YARD` fingerprint only |
| How you prove it | Indexer + inscription id; anyone can rescan the chain | `.yard` consignment file + fingerprint + unspent seal |
| If software dies | Inscription remains on-chain | Seal UTXO remains spendable DOGE; note history needs the file |
| Custody | Your keys; content is on L1 | Your keys; **no wrap, no bridge** |
| Same product? | **No.** Different object, different trust, different UX |

Doginals people should hear: **YARD is not a Doginal.** It is closer to an
RGB-style client-validated claim stapled to cash. Tickers are not unique —
wallets show `TICK-a1b2c3d4`.

Full table: [docs/VS_DOGINALS.md](docs/VS_DOGINALS.md).

## Stack (studio)

| Layer | Where | Job |
|---|---|---|
| Protocol + CLI | [jonheaven/yard](https://github.com/jonheaven/yard) (`Desktop/yard`, junction `dogestack/yard`) | Spec, consignments, genesis/transfer/burn/launch |
| Wallet (lab) | `dogestack/dojak` | Protect stamped UTXOs, verify `.yard`, tip one stamp |
| **Shibe frontend** | **`dogestack/dogenals/web-com` → [dogecoin.dog](https://dogecoin.dog)** | All public UX; embeds `@dojak/web` |
| Indexer (optional) | `dogestack/dogex` | Catalog fingerprints later — never source of truth |
| Not this | `wow-signal` / Ð:WOW | Doginal guestbook postage — different product |

**Rule:** anything Shibe-facing ships on **dogecoin.dog** (`web-com`), with Dojak
web as the wallet. Do not invent a parallel storefront.

Routes (Labs):

- `/yard` — what YARD is + vs Doginals
- `/yard/burn` — **Burn a Wow** (first viral loop)

## Product: Burn a Wow

One fixed-supply stamp (`WOW`), tip with a transfer, burn to put a dog pic
on the daily wall. Verdict card is the share object.

Not WOW SIGNAL (`wow.dogecoin.dog`). That is Doginal postage. This is a
YARD stamp burn.

## Sequence

1. **Harden protocol** — reorg harness, independent review of encode/sig/seal, freeze v0.1 consignment shape.
2. ~~**dogecoin.dog `/yard` + `/yard/burn`**~~ — shipped (lab UI).
3. ~~**Dojak YARD lab**~~ — protect + verify + tip/burn (full-note) shipped in `@dojak/web` `YardLabPanel`.
4. **One public drop** — issue WOW via `yard-cli`, tip friends, run the wall a week. Measure tip/burn/share.
5. **Then** Phase 1 launch-buy as creator tool on the same site.

Parked: Phase 2 channels, Phase 3 batches, YARD token, bridges, EVM.

## Success

People tip or burn a WOW and share the daily card **without** reading
`YARD.md`. Strangers can still verify with `dogecoind` + `yard-cli` + `.yard`.

## Names / surface

- GitHub: `jonheaven/yard`
- Public face: `dogecoin.dog/yard`
- Reserve when ready: `yard-doge.org` / `.dev` (do not announce until owned)
- crates.io `yard` is taken — publish as `yard-doge` / `yard-cli` later
