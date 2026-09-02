# testdata

Local-only artifacts. `*.yard` consignments are gitignored.

If you lose a `.yard` file and have no backup, you cannot spend the YARD note
even if you still hold the Dogecoin seal UTXO. The UTXO remains ordinary DOGE.

## dogecoin.conf (regtest)

```
regtest=1
server=1
txindex=1
rpcuser=yard
rpcpassword=yard
rpcport=18332
datacarrier=1
# leave datacarriersize default; YARD v1 payload is 40 bytes
```

## Phase 0 flow

```
dogecoind -regtest -server -txindex -rpcuser=yard -rpcpassword=yard -rpcport=18332

dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard getnewaddress
# or: cargo run -p yard-cli -- new-key --network regtest

dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard generatetoaddress 110 <D-or-n-address>

cargo run -p yard-cli -- genesis --network regtest --rpc http://yard:yard@127.0.0.1:18332 \
  --wif <wif> --tick TEST --name "Test Note" --dec 8 --max 21000000000000000 --seal-doge 0.05

dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard generatetoaddress 6 <address>

cargo run -p yard-cli -- verify --consignment testdata/last_genesis.yard \
  --rpc http://yard:yard@127.0.0.1:18332

cargo run -p yard-cli -- transfer --consignment testdata/last_genesis.yard \
  --to <compressed-pubkey-hex-or-address> --pubkey <recipient-compressed-pubkey> \
  --amount 1000 --wif <wif> --rpc http://yard:yard@127.0.0.1:18332 --out testdata/last_transfer.yard
```
