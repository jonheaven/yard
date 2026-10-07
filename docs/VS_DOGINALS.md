# YARD collectibles vs Doginals

Short answer: **different.** If you know Doginals, do not treat a YARD note
as “another inscription format.”

## Doginal

A Doginal puts **content on Dogecoin** via a commit → reveal inscription
pattern. Indexers assign an inscription id. Explorers and marketplaces
rediscover it by scanning the chain. The art/JSON/file is the on-chain
artifact. Losing a local file does not erase the inscription.

## YARD note (stamp / collectible)

A YARD note is **extra meaning sealed to one UTXO**. Dogecoin only sees:

1. a normal payment that spends that UTXO, and
2. a ~40-byte OP_RETURN: magic `YARD` + version + 32-byte hash + flags

The name, supply, amounts, and history live in a **`.yard` consignment**
the sender gives the receiver. The receiver’s software checks the file
against the fingerprint and against their own Dogecoin node (or a node
service they trust).

Spending the seal UTXO as plain DOGE **kills the note**. The DOGE still
arrives. Nothing wraps or locks coins on another chain.

## Why both can exist

| Need | Prefer |
|---|---|
| Permanent on-chain media, marketplace inscription ids, Doginals culture | Doginal |
| Fungible or limited **labels** that must not trap DOGE, meme stamps, client-checked sales | YARD |
| Instant app-chain execution via a bridge | Neither (out of scope for YARD) |

## UX rules for wallets (Dojak / dogecoin.dog)

- Never show ticker alone — always `ContractId` form (`WOW-a1b2c3d4`).
- Mark sealed UTXOs **do-not-spend** in ordinary sends.
- Auto-backup `.yard` files; losing the file can strand the **note**, not the DOGE.
- Do not list YARD notes as inscriptions or Doginal collection items.

## Related studio products (do not conflate)

| Product | Protocol | Face |
|---|---|---|
| Marketplace NFTs / relics | Doginals + ÐMP | dogecoin.dog collectibles |
| WOW SIGNAL guestbook | Ð:WOW Doginal postage | wow.dogecoin.dog |
| **Burn a Wow** | **YARD stamps** | **dogecoin.dog/yard/burn** |
