# -*- coding: utf-8 -*-
#
# Electrum-XBT - lightweight client for the Bitcoin BLAKE2b chain
#
# SIGHASH_UNIFIED (0x20): the one opt-in signature hash the Bitcoin Knots
# BLAKE2b hardfork added for every input type. Setting the bit changes which
# message is signed and nothing else; signatures are made and verified as they
# are today for the script type in question. The message is BIP341-shaped and
# the digest is TaggedHash("UnifiedSighash", message). Because the message is
# distinct from every existing one, an opted-in signature cannot be replayed on
# a chain that does not implement it.
#
# Spec: Knots doc/unified-sighash.md; vectors src/test/data/unified_sighash.json
# (tests/test_unified.py).

from typing import Sequence, Tuple, Optional

from electrum_ecc.util import bip340_tagged_hash

from .bitcoin import var_int
from .crypto import sha256

SIGHASH_UNIFIED = 0x20
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

SCRIPT_TYPE_LEGACY = 0    # bare or P2SH
SCRIPT_TYPE_WITNESS_V0 = 1
SCRIPT_TYPE_TAPROOT = 2   # key path
SCRIPT_TYPE_TAPSCRIPT = 3

NO_CODESEPARATOR = 0xffffffff
TAPROOT_LEAF_TAPSCRIPT = 0xc0


def tapleaf_hash(script: bytes, leaf_version: int = TAPROOT_LEAF_TAPSCRIPT) -> bytes:
    return bip340_tagged_hash(b"TapLeaf", bytes([leaf_version]) + var_int(len(script)) + script)


class UnifiedTxDigestFields:
    """The five single-SHA256 aggregates, shared by every input of a transaction.
    They are exactly BIP341's."""

    def __init__(self, *, sha_prevouts: bytes, sha_amounts: bytes, sha_scripts: bytes,
                 sha_sequences: bytes, sha_outputs: bytes):
        self.sha_prevouts = sha_prevouts
        self.sha_amounts = sha_amounts
        self.sha_scripts = sha_scripts
        self.sha_sequences = sha_sequences
        self.sha_outputs = sha_outputs

    @classmethod
    def compute(cls, *, prevouts: Sequence[bytes], sequences: Sequence[int],
                spent_outputs: Sequence[Tuple[int, bytes]], outputs: Sequence[bytes]) -> 'UnifiedTxDigestFields':
        return cls(
            sha_prevouts=sha256(b''.join(prevouts)),
            sha_amounts=sha256(b''.join(int.to_bytes(v, 8, 'little', signed=True) for v, _ in spent_outputs)),
            sha_scripts=sha256(b''.join(var_int(len(spk)) + spk for _, spk in spent_outputs)),
            sha_sequences=sha256(b''.join(int.to_bytes(s, 4, 'little') for s in sequences)),
            sha_outputs=sha256(b''.join(outputs)),
        )


def unified_sighash_message(
    *,
    version: int,
    locktime: int,
    prevouts: Sequence[bytes],          # 36-byte serialized outpoints, one per input
    sequences: Sequence[int],
    spent_outputs: Sequence[Tuple[int, bytes]],  # (value, scriptPubKey) per input
    outputs: Sequence[bytes],           # serialized outputs (value, compact-size script)
    in_idx: int,
    hash_type: int,
    script_type: int,
    script_code: bytes = b'',           # script types 0 and 1
    annex: Optional[bytes] = None,      # script types 2 and 3, without its compact-size prefix
    leaf_hash: Optional[bytes] = None,  # script type 3
    codesep_pos: int = NO_CODESEPARATOR,
    shared: Optional[UnifiedTxDigestFields] = None,
) -> bytes:
    if not (hash_type & SIGHASH_UNIFIED):
        raise ValueError("hash type does not opt in to SIGHASH_UNIFIED")
    if script_type in (SCRIPT_TYPE_TAPROOT, SCRIPT_TYPE_TAPSCRIPT):
        if (hash_type & ~SIGHASH_UNIFIED) not in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            raise ValueError(f"hash type {hash_type:#x} is not defined for taproot")
    if shared is None:
        shared = UnifiedTxDigestFields.compute(
            prevouts=prevouts, sequences=sequences, spent_outputs=spent_outputs, outputs=outputs)
    acp = bool(hash_type & SIGHASH_ANYONECANPAY)
    base = hash_type & 0x1f

    msg = bytearray()
    msg += b'\x00'                                           # epoch
    msg += bytes([hash_type])
    msg += int.to_bytes(version, 4, 'little', signed=True)
    msg += int.to_bytes(locktime, 5, 'little')
    if not acp:
        msg += shared.sha_prevouts + shared.sha_amounts + shared.sha_scripts + shared.sha_sequences
    if base not in (SIGHASH_NONE, SIGHASH_SINGLE):
        msg += shared.sha_outputs
    msg += bytes([script_type])
    if acp:
        value, spk = spent_outputs[in_idx]
        msg += prevouts[in_idx]
        msg += int.to_bytes(value, 8, 'little', signed=True) + var_int(len(spk)) + spk
        msg += int.to_bytes(sequences[in_idx], 4, 'little')
    else:
        msg += int.to_bytes(in_idx, 4, 'little')
    if script_type in (SCRIPT_TYPE_LEGACY, SCRIPT_TYPE_WITNESS_V0):
        msg += var_int(len(script_code)) + script_code
    else:
        if annex is not None:
            msg += b'\x01' + sha256(var_int(len(annex)) + annex)
        else:
            msg += b'\x00'
    if base == SIGHASH_SINGLE:
        if in_idx >= len(outputs):
            raise ValueError("SIGHASH_SINGLE without a corresponding output")
        msg += sha256(outputs[in_idx])
    if script_type == SCRIPT_TYPE_TAPSCRIPT:
        if leaf_hash is None:
            raise ValueError("tapscript spend needs its leaf hash")
        msg += leaf_hash + b'\x00' + int.to_bytes(codesep_pos, 4, 'little')
    return bytes(msg)


def unified_sighash(**kwargs) -> bytes:
    """The 32-byte digest a signature over an opted-in input commits to."""
    return bip340_tagged_hash(b"UnifiedSighash", unified_sighash_message(**kwargs))
