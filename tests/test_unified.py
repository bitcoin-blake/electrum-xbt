import json
import os

from electrum import unified
import electrum_ecc as ecc
from electrum.bitcoin import pubkey_to_address
from electrum.descriptor import parse_descriptor
from electrum.transaction import (Transaction, PartialTransaction, PartialTxInput, PartialTxOutput,
                                  TxOutpoint, Sighash, DEFAULT_SIGHASH)
from electrum.util import bfh

from . import ElectrumTestCase


VECTORS = os.path.join(os.path.dirname(__file__), 'unified_sighash.json')


class TestUnifiedSighash(ElectrumTestCase):

    def test_knots_vectors(self):
        with open(VECTORS) as f:
            raw = json.load(f)
        header, rows = raw[0], [dict(zip(raw[0], r)) for r in raw[1:]]
        self.assertEqual(len(rows), 166)
        seen = set()
        for t in rows:
            tx = Transaction(t['rawTx'])
            tx.deserialize()
            inputs, outputs = tx.inputs(), tx.outputs()
            spent = [(v, bfh(spk)) for v, spk in t['spentOutputs']]
            script_code = bfh(t['scriptCode'])
            leaf_hash = unified.tapleaf_hash(script_code) if t['scriptType'] == unified.SCRIPT_TYPE_TAPSCRIPT else None
            digest = unified.unified_sighash(
                version=tx.version, locktime=tx.locktime,
                prevouts=[txin.prevout.serialize_to_network() for txin in inputs],
                sequences=[txin.nsequence for txin in inputs],
                spent_outputs=spent,
                outputs=[o.serialize_to_network() for o in outputs],
                in_idx=t['inIdx'], hash_type=t['hashType'], script_type=t['scriptType'],
                script_code=script_code, leaf_hash=leaf_hash,
            )
            self.assertEqual(digest.hex(), t['sighash'], f"{t['scriptType']=} {t['hashType']=} {t['inIdx']=}")
            seen.add((t['scriptType'], t['hashType']))
        for st in range(4):
            self.assertTrue(any(s == st for s, _ in seen), f"no vector for script type {st}")

    def test_rejects_without_optin(self):
        with self.assertRaises(ValueError):
            unified.unified_sighash(version=2, locktime=0, prevouts=[], sequences=[], spent_outputs=[],
                                    outputs=[], in_idx=0, hash_type=0x01, script_type=0)


class TestUnifiedSigning(ElectrumTestCase):
    """sign_txin opts in by default and the signature verifies against the unified digest."""

    def _funding_tx(self, address: str, value: int) -> Transaction:
        dummy = PartialTxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=0))
        dummy.script_sig = b''
        dummy.witness = b'\x00'
        tx = PartialTransaction.from_io([dummy], [PartialTxOutput.from_address_and_value(address, value)])
        return Transaction(tx.serialize_to_network(include_sigs=True))

    def test_p2wpkh_sign_and_verify(self):
        privkey = bytes(range(1, 33))
        pubkey = ecc.ECPrivkey(privkey).get_public_key_bytes(compressed=True)
        addr = pubkey_to_address('p2wpkh', pubkey.hex())
        funding = self._funding_tx(addr, 100_000)
        txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(funding.txid()), out_idx=0))
        txin.utxo = funding
        txin.script_descriptor = parse_descriptor(f"wpkh({pubkey.hex()})")
        tx = PartialTransaction.from_io([txin], [PartialTxOutput.from_address_and_value(addr, 90_000)])
        self.assertEqual(DEFAULT_SIGHASH, 0x21)
        sig = tx.sign_txin(0, privkey)
        self.assertEqual(sig[-1], 0x21)
        self.assertTrue(tx.verify_sig_for_txin(txin_index=0, pubkey_bytes=pubkey, sig=sig))
        # the digest is the library's, with script type 1 and the P2PKH script code of BIP143
        digest = unified.unified_sighash(
            version=tx.version, locktime=tx.locktime,
            prevouts=[txin.prevout.serialize_to_network()], sequences=[txin.nsequence],
            spent_outputs=[(100_000, funding.outputs()[0].scriptpubkey)],
            outputs=[o.serialize_to_network() for o in tx.outputs()],
            in_idx=0, hash_type=0x21, script_type=1, script_code=txin.get_scriptcode_for_sighash())
        self.assertEqual(digest, tx.sighash_digest(0))
        # a legacy signature over the same input is a different message and fails against the unified digest
        txin.sighash = Sighash.ALL
        legacy_sig = tx.sign_txin(0, privkey)
        self.assertEqual(legacy_sig[-1], 0x01)
        self.assertTrue(tx.verify_sig_for_txin(txin_index=0, pubkey_bytes=pubkey, sig=legacy_sig))
        self.assertFalse(tx.verify_sig_for_txin(txin_index=0, pubkey_bytes=pubkey, sig=legacy_sig[:-1] + b'\x21'))
