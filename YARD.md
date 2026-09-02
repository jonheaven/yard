# YARD
## Client-side validated utility for Dogecoin
### Agent briefing, protocol spec, threat model, and build plan
### Version: 0.1.0-draft
### Date: 2026-09-01
### Status: implementable draft — no L1 fork, no token, no wrap-by-default

This is the only document an agent needs to start the repo.
If a later file disagrees with this file, this file wins until a human amends it.

-------------------------------------------------------------------------------
0. WHAT YOU ARE BUILDING
-------------------------------------------------------------------------------

YARD is not an EVM chain, not a wrapped-DOGE bridge, and not a Core soft fork.

YARD is a client-side validation protocol that uses unmodified Dogecoin as:

1. the only money
2. the only double-spend oracle
3. the only public clock / ordering layer

App state lives off-chain. Dogecoin sees ordinary payments plus a tiny
prunable commitment. Wallets validate the history that matters to them.

This is the design that survives contact with:

- Satoshi's brief: electronic cash without trusted third parties, simple
  nodes, scarce blockspace used for money first
- Casey Rodarmor's brief: a lens over existing UTXOs, content and meaning
  off to the side, ignore it if you do not care, no new consensus rules
- Changpeng Zhao's brief: users can deposit real DOGE, withdraw real DOGE,
  tickers are listable, ops are boring, no mystery gas token

If a feature requires miners to verify Groth16, run a VM, or hold wrapped
DOGE in a hot federation, it is out of scope for v1.

-------------------------------------------------------------------------------
1. NON-GOALS  (read twice)
-------------------------------------------------------------------------------

DO NOT:

- propose or depend on OP_CHECKZKP, OP_CHECKGROTH16VERIFY, or any new opcode
- require SegWit, Taproot, CSV, or bech32 (none of these are live Dogecoin
  mainnet consensus as of 2026; CLTV is live; CSV and SegWit are not)
- issue a YARD token, points token, sequencer token, or "ecosystem coin"
- build an EVM, zkEVM, or Solidity toolchain in Phase 0–1
- lock user DOGE in a custodial bridge as the default UX
- store JSON, images, or video in scriptSig or fake pubkeys
- invent a new address format
- claim "trustless rollup secured by Dogecoin miners"
- airdrop anything
- copy DogeOS, Dogechain, Anoncoin, or Fractal Engine architecture

DO:

- use P2PKH / P2SH and nLockTime / CLTV only
- commit 32-byte roots in standard OP_RETURN payloads that fit the
  historical 80-byte data push
- treat indexers as conveniences, never as sources of truth
- make L1 DOGE the always-available exit
- write tests before RPC polish

-------------------------------------------------------------------------------
2. WHY THIS BEATS THE EXISTING OPTIONS
-------------------------------------------------------------------------------

DogeOS
  App layer that wants Dogecoin Core to verify ZK proofs via OP_CHECKZKP.
  Draft / stub. Turns every full node into a proof verifier. Mixed DA story.
  Rejected as a dependency.

Dogechain
  Separate EVM + wrapped DOGE + DC token. Officially sunsetting in 2026.
  When the operator chain dies, bridged assets die. That is the lesson.

Anoncoin
  Launchpad product. Currently lives on Solana while waiting for DogeOS.
  An app, not settlement. YARD notes replace the need for that venue.

Fractal Engine
  Foundation RWA sidechain beside L1. Correct isolation instinct. Different
  product (RWA rules). YARD does not compete with it and does not merge into
  Core later.

YARD wins by being the thing that can fail without taking DOGE with it.

-------------------------------------------------------------------------------
3. DOGECOIN CONSTRAINTS  (do not "fix" these in software)
-------------------------------------------------------------------------------

Network
  Mainnet magic: 0xc0c0c0c0
  Default P2P: 22556
  RPC default: 22555
  Testnet magic: 0xfcc1b7dc
  Testnet P2P: 44556
  Block target: 60 seconds
  Coin: 100,000,000 koinu = 1 DOGE

Addresses
  P2PKH version byte: 0x1e  (addresses start with D)
  P2SH version byte:  0x16  (addresses start with 9 or A)
  WIF version:        0x9e
  No bech32 on mainnet. Do not generate doge1...

Script / consensus you MAY use
  P2PKH, P2SH, bare/P2SH multisig
  OP_CHECKSIG, OP_CHECKMULTISIG
  OP_CLTV / BIP65  (activated)
  nLockTime absolute lock
  OP_RETURN nulldata

Script / consensus you may NOT assume
  SegWit / P2WPKH / P2WSH / bech32
  CSV / BIP68 / BIP112 / BIP113   (code exists, not activated)
  Taproot / Tapscript
  OP_CAT and other disabled splice ops

Policy (relay, not consensus) — design for the conservative floor
  Recommended fee:     0.01 DOGE per kilobyte
  Min relay fee:       0.001 DOGE per kilobyte
  Hard dust:           0.001 DOGE
  Soft dust:           0.01 DOGE  (below this, extra fee required)
  Historical OP_RETURN standardness: 83-byte script ≈ 80-byte payload
  Max standard tx:     100,000 bytes
  scriptSig standard:  1,650 bytes

YARD commitments MUST be valid and standard under the 80-byte payload floor.
If a node operator has raised -datacarriersize, larger optional envelopes
are allowed as an upgrade, never as a v1 requirement.

Dust rule for seal UTXOs
  Every seal UTXO value >= 0.01 DOGE (soft dust) so it relays cleanly.
  Prefer 0.05 DOGE seals so they remain economical if fees rise.

-------------------------------------------------------------------------------
4. MENTAL MODEL
-------------------------------------------------------------------------------

Dogecoin L1 = clock + unique UTXOs + DOGE balances
YARD        = names for extra meaning attached to those UTXOs

A YARD "note" is extra state sealed to exactly one Dogecoin UTXO
(txid:vout). Spending that UTXO closes the seal. The closer may open
new seals on the outputs of the same transaction.

Double-spend protection is free: Dogecoin already forbids spending a
UTXO twice. YARD does not reimplement a ledger.

This is Peter Todd single-use seals + Rodarmor "optional lens" +
RGB-style client validation, parametrized for Dogecoin as it exists.

Users who do not run YARD software see a normal cheap DOGE payment
and maybe an OP_RETURN. That is the point.

-------------------------------------------------------------------------------
5. OBJECTS
-------------------------------------------------------------------------------

5.1 Outpoint
  txid: 32 bytes, internal byte order as in Bitcoin/Dogecoin RPC hex
        (display hex is reversed; be explicit in code and tests)
  vout: u32 LE

5.2 Seal
  An outpoint that currently holds YARD state.
  Closed when that outpoint is spent on L1.

5.3 ContractId
  sha256d of the genesis operation bytes.
  32 bytes. Display as hex, lowercase.

5.4 Note
  Fungible or non-fungible state assigned to a seal under a contract.
  For v1 fungible:
    amount: u128
    no decimals in consensus — display decimals are metadata only

5.5 Operation
  A signed state transition:
    - closes 1..n input seals
    - opens 0..n output seals
    - carries a typed payload (genesis, transfer, burn, launch)
  The operation is NOT broadcast to Dogecoin nodes.
  Only a commitment to it is.

5.6 Consignment
  The package a sender gives a receiver:
    - genesis
    - every operation from genesis to this transfer
    - proofs that each closed seal was spent by the claimed L1 tx
    - the L1 tx hex or txid+merkle proof
  Receiver validates locally. Indexer may fetch missing pieces but
  cannot be trusted to skip validation.

5.7 Commitment
  80-byte-or-smaller OP_RETURN payload in the L1 transaction that
  closes the seals.

-------------------------------------------------------------------------------
6. WIRE FORMAT
-------------------------------------------------------------------------------

All multi-byte integers little-endian unless noted.
Hashes: SHA256d = SHA256(SHA256(x)), same as Dogecoin.

6.1 OP_RETURN envelope (v1, MUST fit 80-byte push)

  scriptPubKey:
    OP_RETURN
    OP_PUSHBYTES_N
    <payload>

  payload:
    magic[4]     = 0x59 0x41 0x52 0x44      // "YARD"
    version[1]   = 0x01
    kind[1]      = see below
    root[32]     = SHA256d(tagged operation batch)
    flags[1]     = bitfield
    reserved[1]  = 0x00
    // total 40 bytes. Remaining 40 bytes MUST be unused in v1
    // so the push stays small and standard everywhere.

  kind
    0x01  single operation commitment
    0x02  merkle root of 2..n operations in one L1 tx
    0xFF  reserved

  flags
    bit0  = 1 if payload covers multiple contracts
    bits 1-7 reserved, MUST be 0 in v1

  Commitment message for kind 0x01:
    tag = "yard/op/v1"
    msg = SHA256d( tag || operation_canonical_bytes )
    root = msg

  Commitment message for kind 0x02:
    binary merkle tree of SHA256d("yard/op/v1" || op_i), sorted by
    op hash, bitcoin-style duplicate last on odd count.
    root = tree root

The L1 transaction that contains this OP_RETURN MUST also spend every
input seal referenced by the committed operation(s) and MUST create
every output seal UTXO referenced by those operations.

If the L1 graph and the YARD graph disagree, the operation is invalid.

6.2 Canonical operation bytes

  op_version: u8 = 1
  contract_id: 32 bytes          // 0x00..00 only for genesis
  op_type: u8
      0x00 genesis
      0x01 transfer
      0x02 burn
      0x03 launch_buy   // Phase 1
      0x04 launch_sell  // Phase 1
  input_count: u16
  inputs[input_count]:
      prev_op_hash: 32 bytes     // SHA256d of prev operation bytes
      prev_seal: outpoint
      amount: u128               // 0 for NFT
  output_count: u16
  outputs[output_count]:
      seal: outpoint             // MUST be an output of THIS L1 tx
      amount: u128
      pubkey: 33 bytes compressed secp256k1
  meta_len: u16                  // <= 512 in v1
  meta: bytes                    // utf-8 JSON or empty
  sig_count: u8                  // must equal input_count except genesis=1
  sigs[sig_count]:
      64-byte compact BIP66-valid DER is NOT used
      use 64-byte compact bip340-style? NO — Dogecoin keys are ECDSA
      use 64-byte compact r||s plus 1-byte recid? Keep it simple:
      sig: bitcoin-style compact 64-byte r||s from secp256k1
           low-S required
      sighash: implicit ALL over the operation bytes with sig fields
               zeroed (like Bitcoin tx signing spirit)

Signature message:
  SHA256d( "yard/sighash/v1" || operation_bytes_with_sigs_empty )

Genesis exception:
  contract_id field is 32 zero bytes in the signed body.
  After signing, ContractId := SHA256d(operation_bytes_including_sig)
  Receivers recompute this.

Output-seal txid (construction):
  An operation is hashed into the OP_RETURN that lives in the same L1
  transaction that creates the output seals. Putting that transaction's
  txid into the operation bytes would be circular (txid depends on the
  OP_RETURN, OP_RETURN depends on the operation). Constructors MUST
  write 32 zero bytes as the output seal txid, meaning "this committing
  L1 transaction". Validation accepts a zero txid or an exact match with
  the committing L1 txid, and ALWAYS checks the vout on that transaction.
  Input seals always use the real previous L1 txid (already known).

6.3 Genesis meta (JSON, utf-8, max 512 bytes)

  {
    "p": "yard",
    "v": 1,
    "ty": "ft",
    "tick": "TEST",
    "name": "Test Note",
    "dec": 8,
    "max": "21000000000000000",
    "lim": "0"
  }

  ty: "ft" | "nft"
  tick: 1..8 uppercase A-Z / 0-9
  max: decimal string of u128 base units
  lim: per-op mint cap, 0 means no open mint after genesis
  For v1 genesis, all `max` units MUST be assigned in genesis outputs.
  No post-genesis mint in Phase 0. Launch curves are Phase 1.

Ticker uniqueness is NOT consensus. Two contracts may use TEST.
Wallets display ContractId prefix. Exchanges list by ContractId.

6.4 Consignment file  (application/yard-consignment)

  magic "YARDCONS" (8)
  version u8 = 1
  n_ops u32
  ops: length-prefixed operation bytes
  n_txs u32
  txs: raw L1 transaction bytes, length-prefixed
  n_proofs u32
  proofs: for each close, { txid, blockhash, merkle path }
           proofs optional in Phase 0 if full txs + user-trusted height
           provided by local node

File extension: .yard
Human transfer: send .yard file or multipart over any channel.
Phase 0 may pass consignments as JSON for ease. Canonical is binary.

-------------------------------------------------------------------------------
7. VALIDATION RULES  (consensus of YARD, not of Dogecoin)
-------------------------------------------------------------------------------

A receiver MUST accept an incoming note only if all of the following hold.

G1  Genesis parses, signature valid under the genesis pubkey.
G2  ContractId = SHA256d(genesis bytes).
G3  Sum of genesis output amounts == meta.max.
G4  Each genesis output seal is an output of the genesis L1 tx.
G5  Genesis L1 tx contains a valid YARD OP_RETURN whose root commits
    to this genesis operation.
G6  Genesis L1 tx is in the best chain with N confirmations.
    Default N = 6. Config may raise. Never N = 0 for value > dust.

T1  Each transfer input refers to a previous accepted operation.
T2  Input amounts sum == output amounts sum + burned.
T3  Each input seal was unspent before this L1 tx and is spent by it.
T4  Each output seal is created by this L1 tx and value >= 0.01 DOGE.
T5  Signatures verify against the pubkeys assigned by the previous
    operation to those seals.
T6  OP_RETURN root commits to this operation (or merkle inclusion).
T7  No seal is closed twice. (Follow L1. If L1 reorgs, rewind YARD.)
T8  op_type allowed by contract. Phase 0: only genesis and transfer
    and burn.

Reorg
  Watch the local Dogecoin node. If a committing tx leaves the best
  chain, mark operations unconfirmed / invalid and wait for a new
  commitment. Never finalize across a reorg without re-validation.

Ignore unknown
  Unknown op_type, unknown flags, extra trailing payload bytes after
  the 40-byte v1 commitment: reject for safety in v1.
  (Rodarmor later blessed "cursed" inscriptions. We do not. Strict
  first. A later version can add an explicit blessing rule.)

-------------------------------------------------------------------------------
8. PHASES
-------------------------------------------------------------------------------

Phase 0  — this repo, this month
  Library + CLI + indexer that talks to dogecoin-core
  genesis + transfer + burn on testnet / regtest
  consignment export/import
  unit tests and test vectors
  NO launchpad, NO channels, NO HTTP app, NO token

Phase 1  — after Phase 0 is green
  Launch notes: fixed-supply sale paid in L1 DOGE
  Simple linear or constant-product curve encoded in genesis meta
  This replaces Anoncoin for Doge-native memes

Phase 2  — only if CSV activates on Dogecoin, or with weaker nLockTime
  Payment channels for DOGE itself
  Until CSV is live, do not advertise Lightning-on-Doge

Phase 3  — optional sovereign execution
  Batch roots in OP_RETURN
  Execution verified by YARD software, never by miners
  Still no L1 opcode

Agent: implement Phase 0 only unless the human says otherwise.

-------------------------------------------------------------------------------
9. REPOSITORY LAYOUT
-------------------------------------------------------------------------------

See the workspace. Rust 1.80+ edition 2021.

-------------------------------------------------------------------------------
10. CRATE RESPONSIBILITIES
-------------------------------------------------------------------------------

yard-core
  Pub types: Magic, Outpoint, Seal, Amount(u128), ContractId, OpType,
             Operation, GenesisMeta, Commitment, Consignment
  Encode/decode canonical bytes
  SHA256d helpers
  secp256k1 sign / verify compact 64-byte r||s low-S
  validate_operation(op, prev_ops, l1_tx) -> Result
  ticker syntax check
  No network. No RPC. No sqlite.

yard-doge
  Dogecoin address encode/decode (Base58Check version 0x1e / 0x16)
  Build a raw unsigned tx skeleton
  Fee: 0.01 DOGE per started kilobyte of serialized size
  JSON-RPC client against dogecoin-core
  Network enum: Mainnet | Testnet | Regtest

yard-index
  SQLite scan for magic YARD. Convenience only. Never a source of truth.

yard-cli
  new-key, genesis, transfer, verify, scan

-------------------------------------------------------------------------------
11. CRYPTOGRAPHY DETAILS  (do not get creative)
-------------------------------------------------------------------------------

Curve: secp256k1
Pubkeys: compressed 33 bytes
Signatures: compact 64-byte r||s, low-S mandatory
Verification: recover or store pubkey on the note (we store pubkey)
Hash: SHA256d
Merkle: Bitcoin-style

Do not use Schnorr. Dogecoin users have ECDSA keys.

Amount encoding: u128 LE. No floats anywhere in consensus.

Ticker: regex ^[A-Z0-9]{1,8}$

Contract display: first 8 hex of ContractId plus tick, e.g. TEST-a1b2c3d4

-------------------------------------------------------------------------------
12. THREAT MODEL
-------------------------------------------------------------------------------

Assets
  User DOGE in ordinary UTXOs
  YARD notes sealed to those UTXOs
  Private keys

Adversaries
  Malicious sender of a consignment
  Malicious indexer
  Malicious RPC provider
  Chain reorg up to ~20 blocks (Doge is fast and merge-mined; be sober)
  Fee-market griefing
  Ticker collision / fake TEST contracts
  Compromised CLI machine

Accepted risks in Phase 0
  Receiver must obtain the consignment. If they lose it and have no
  backup, the note cannot be spent even if they still hold the seal
  UTXO. Document this like RGB does. Backup the .yard file.
  Indexer can hide commitments; it cannot steal notes if the owner
  has the consignment and key.
  Anyone can issue a contract named DOGE or BTC. Wallets must show
  ContractId.

Rejected designs
  "Just trust our API for balances"
  Mint authority after genesis in Phase 0
  Admin keys
  Upgradeable contracts

Bridge
  There is no bridge in Phase 0. Do not add one "temporarily."

-------------------------------------------------------------------------------
13–20. TESTS, STYLE, CHECKLIST
-------------------------------------------------------------------------------

See README.md for build and the Phase 1 issue list.
Regtest is the default target. Phase 0 mainnet waits on the human checklist.
