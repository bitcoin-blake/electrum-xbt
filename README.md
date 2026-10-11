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

**Testnet4 is live.** A public server is in the default list and the wallet
has been used for real spends on the BLAKE2b testnet4.

**Mainnet is wired but switched off.** The code is complete for mainnet: fork
height, the target shift at the fork block, retargets from the shifted bits,
checkpoints up to just below the fork, coinbase maturity. It is verified
against the chain's own headers (`tests/test_mainnet_pow.py` replays mainnet
chunk 477 across the fork and the two retargets after it). What is missing is
a public mainnet server, so the mainnet server list is empty and
`electrum-xbt` on mainnet will not connect. Nobody should put real coins
through it until a server exists and a first small spend has been made and
written up here.

- Data directory is `~/.electrum-xbt`, separate from any Electrum install.
- Hardware wallets cannot sign the unified sighash; use software wallets.
- Lightning is present, untested on this chain and has no peers on it; its
  channel signatures are not replay-protected.
- Coinbase maturity follows Knots PR 419: 6,480 blocks on mainnet and 6,705
  on testnet4 by node policy, which is what the wallet uses for its immature
  balance and coin selection.
- Fiat rates are off: the sources quote BTC, not XBT.

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
