# Electrum-XBT

Lightweight wallet for the Bitcoin BLAKE2b chain (XBT), a fork of
[Electrum](https://github.com/spesmilo/electrum).

The BLAKE2b chain is the Bitcoin Knots hardfork that moved proof of work to
BLAKE2b at mainnet height 961,640 (testnet4 150,308). A wallet for it needs two
things Electrum does not have, and this fork adds exactly those:

- **Headers.** Blocks after the fork carry a 164-byte header v2 hashed with
  BLAKE2b. `electrum/blake.py` decodes and hashes them and is checked against
  Knots' own `block_header_v2.json`. The header chain requires v2 at or above
  the fork height and refuses it below, so the client cannot follow the SHA256d
  chain by accident.
- **Signatures.** Every signature opts in to `SIGHASH_UNIFIED` (hash type
  `0x21`), the chain's replay-protected signature hash. `electrum/unified.py`
  implements it for all four script types and passes Knots' 166 vectors.
  A transaction signed here is invalid on the SHA256d chain and vice versa.

Everything else is Electrum: seeds, wallets, servers, the GUI.

## Status

Testnet4 first. Mainnet constants are in place but its server list is empty
until a public server exists, so `electrum-xbt` on mainnet will not connect.

- Data directory is `~/.electrum-xbt`, separate from any Electrum install.
- Hardware wallets cannot sign the unified sighash; use software wallets.
- Lightning is untested on this chain and its signatures are not replay-protected.
- Coinbase maturity on the BLAKE2b chain is 6,480 blocks under Knots' policy
  (PR 419); the wallet does not model that yet.

## Run from source (testnet4)

A public server for the BLAKE2b testnet4 is in the default list
(`melvin.me`, TLS on 51002, plain on 51001), so a fresh install connects on
its own. To run your own, [bitcoin-blake/electrs](https://github.com/bitcoin-blake/electrs)
(branch `blake2b`, a fork of jasonsopko/electrs) works against a Knots or
Plumb node; then start with `-1 -s 127.0.0.1:50001:t`.

```
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install cryptography pyqt6
.venv/bin/python run_electrum --testnet4
```

That opens the GUI. For the command line instead:

```
.venv/bin/python run_electrum --testnet4 daemon -d
.venv/bin/python run_electrum --testnet4 create
.venv/bin/python run_electrum --testnet4 load_wallet
.venv/bin/python run_electrum --testnet4 getunusedaddress
```

`electrum_ecc` needs libsecp256k1. If the wheel does not build, set
`ELECTRUM_ECC_DONT_COMPILE=1` and copy a `libsecp256k1.so` into the
`electrum_ecc` package directory.

## Tests

```
.venv/bin/python -m unittest tests.test_blake tests.test_unified tests.test_blockchain tests.test_transaction
```

## Upstream

This fork tracks spesmilo/electrum. The chain-specific code is `electrum/blake.py`,
`electrum/unified.py`, the fork heights in `electrum/constants.py`, the header
slot handling in `electrum/blockchain.py` and `electrum/interface.py`, and the
sighash hooks in `electrum/transaction.py`.

Electrum is licensed under the MIT licence; see `LICENCE`.
