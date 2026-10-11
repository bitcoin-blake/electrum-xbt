# -*- coding: utf-8 -*-
#
# Electrum-XBT - lightweight client for the Bitcoin BLAKE2b chain
#
# Block header v2 (Bitcoin Knots BLAKE2b hardfork, knots#359 / #385).
#
# Wire layout (164 bytes). The first 80 bytes are the classic header with the
# top bit of `version` set; the remaining 84 bytes are new:
#   u32  version | 0x80000000
#   32   prev block hash          (internal order)
#   32   merkle root
#   u32  time on wire             (= time - time_offset when flags & 4)
#   u32  bits
#   u32  nonce
#   u32  nonce2
#   u32  nonce3
#   16   extranonce               (uint128, internal order)
#   u32  time_offset
#   u16  tx_count
#   u8   flags                    (bits 0-1: ASIC profile, bit 2: use time offset)
#   u8   xor_key_mask_clear_bits
#   16   xor_key                  (uint128, internal order)
#   i32  height
#   32   mm_rhs                   (merge-mining hook, reserved)
#
# Hash pipeline (Knots primitives/block.cpp, CBlockHeader::GetHash); every
# tagged hash is Core's TaggedHash(tag) = SHA256(SHA256(tag)||SHA256(tag)||msg):
#   xor_key_hash = T("Bitcoin block hash PoW XOR key") << xor_key
#   mask         = T("Bitcoin block hash PoW XOR mask") << xor_key, low clear_bits bits zeroed (0 if key null)
#   prev_hidden  = T("Bitcoin prevblock header, hashed") << prev_hash (display order)
#   h1 = T("Bitcoin block header 1") << ver, prev(display), height, merkle, time_on_wire, 0u8, bits, u32 tx_count, flags, clear_bits, xor_key_hash
#   h2 = T("Merge-mining hook") << h1, 16 zero, 16 zero, mm_rhs
#   b1 = blake2b_256( u32 0 || h2 || extranonce )
#   b2 = blake2b_256( profile-dependent layout of prev_hidden/h2/nonces/time_offset/b1 )
#   block hash (display hex) = b2 XOR mask
#
# Checked against Knots' src/test/data/block_header_v2.json in tests/test_blake.py.

import hashlib
import struct
from typing import Dict, Any

LEGACY_HEADER_SIZE = 80
HEADER_V2_SIZE = 164
VERSION_HEADER_V2_FLAG = 0x80000000
FLAG_USE_TIME_OFFSET = 4


def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode('ascii')).digest()
    return hashlib.sha256(th + th + msg).digest()


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def is_header_v2(raw: bytes) -> bool:
    """True if the raw header bytes carry the v2 marker (top bit of version)."""
    return len(raw) >= 4 and (raw[3] & 0x80) != 0


def header_size(raw: bytes) -> int:
    return HEADER_V2_SIZE if is_header_v2(raw) else LEGACY_HEADER_SIZE


def _u32(n: int) -> bytes:
    return struct.pack('<I', n & 0xffffffff)


def deserialize_header_v2(s: bytes, height: int) -> Dict[str, Any]:
    if len(s) != HEADER_V2_SIZE:
        raise ValueError(f'header v2 must be {HEADER_V2_SIZE} bytes, got {len(s)}')
    if not is_header_v2(s):
        raise ValueError('not a v2 header (version top bit clear)')
    (version, ) = struct.unpack_from('<I', s, 0)
    time_on_wire, bits, nonce, nonce2, nonce3 = struct.unpack_from('<IIIII', s, 68)
    (time_offset, tx_count, flags, clear_bits) = struct.unpack_from('<IHBB', s, 104)
    (in_header_height, ) = struct.unpack_from('<i', s, 128)
    h = {
        'version': version,
        'prev_block_hash': s[4:36][::-1].hex(),
        'merkle_root': s[36:68][::-1].hex(),
        'timestamp': (time_on_wire + time_offset) & 0xffffffff if flags & FLAG_USE_TIME_OFFSET else time_on_wire,
        'bits': bits,
        'nonce': nonce,
        'nonce2': nonce2,
        'nonce3': nonce3,
        'extranonce': s[88:104][::-1].hex(),
        'time_offset': time_offset,
        'tx_count': tx_count,
        'flags': flags,
        'xor_key_mask_clear_bits': clear_bits,
        'xor_key': s[112:128][::-1].hex(),
        'height': in_header_height,
        'mm_rhs': s[132:164][::-1].hex(),
        'block_height': height,
    }
    return h


def _time_on_wire(h: dict) -> int:
    t = int(h['timestamp'])
    if h['flags'] & FLAG_USE_TIME_OFFSET:
        t = (t - int(h['time_offset'])) & 0xffffffff
    return t


def serialize_header_v2(h: dict) -> bytes:
    return (
        _u32(VERSION_HEADER_V2_FLAG | (int(h['version']) & ~VERSION_HEADER_V2_FLAG))
        + bytes.fromhex(h['prev_block_hash'])[::-1]
        + bytes.fromhex(h['merkle_root'])[::-1]
        + _u32(_time_on_wire(h)) + _u32(h['bits']) + _u32(h['nonce'])
        + _u32(h['nonce2']) + _u32(h['nonce3'])
        + bytes.fromhex(h['extranonce'])[::-1]
        + _u32(h['time_offset'])
        + struct.pack('<HBB', int(h['tx_count']), int(h['flags']), int(h['xor_key_mask_clear_bits']))
        + bytes.fromhex(h['xor_key'])[::-1]
        + struct.pack('<i', int(h['height']))
        + bytes.fromhex(h['mm_rhs'])[::-1]
    )


def hash_header_v2_detailed(h: dict) -> Dict[str, Any]:
    """Full pipeline with every intermediate, for the Knots vectors."""
    xor_key_wire = bytes.fromhex(h['xor_key'])[::-1]
    prev_display = bytes.fromhex(h['prev_block_hash'])
    xor_key_hash = tagged_hash('Bitcoin block hash PoW XOR key', xor_key_wire)

    mask = bytearray(32)
    if any(xor_key_wire):
        mask[:] = tagged_hash('Bitcoin block hash PoW XOR mask', xor_key_wire)
        clear_bits = int(h['xor_key_mask_clear_bits'])
        clear_bytes = clear_bits >> 3
        for i in range(min(clear_bytes, 32)):
            mask[i] = 0
        if clear_bytes < 32:
            mask[clear_bytes] &= 0xff >> (clear_bits & 7)
    mask = bytes(mask)

    prev_hidden = tagged_hash('Bitcoin prevblock header, hashed', prev_display)

    h1 = tagged_hash('Bitcoin block header 1', (
        _u32(VERSION_HEADER_V2_FLAG | (int(h['version']) & ~VERSION_HEADER_V2_FLAG))
        + prev_display + _u32(h['height']) + bytes.fromhex(h['merkle_root'])[::-1]
        + _u32(_time_on_wire(h)) + b'\x00' + _u32(h['bits']) + _u32(h['tx_count'])
        + bytes([int(h['flags']) & 0xff, int(h['xor_key_mask_clear_bits']) & 0xff]) + xor_key_hash
    ))
    h2 = tagged_hash('Merge-mining hook', h1 + bytes(16) + bytes(16) + bytes.fromhex(h['mm_rhs'])[::-1])
    b1 = blake2b_256(_u32(0) + h2 + bytes.fromhex(h['extranonce'])[::-1])

    nonce, nonce2, nonce3, toff = _u32(h['nonce']), _u32(h['nonce2']), _u32(h['nonce3']), _u32(h['time_offset'])
    nonces = nonce + nonce2 + toff + nonce3
    profile = int(h['flags']) & 3
    if profile == 0:
        asic_input = bytes(6) + prev_hidden[6:] + nonces + b1
    elif profile == 1:
        asic_input = nonce + nonce2 + nonce3 + toff + b1 + h2
    elif profile == 2:
        asic_input = bytes(48) + h2 + nonces + b1
    else:
        asic_input = bytes(80) + h2 + nonces + b1
    b2 = blake2b_256(asic_input)
    block_hash = bytes(x ^ m for x, m in zip(b2, mask))
    return {
        'xor_key_hash': xor_key_hash.hex(), 'h1': h1.hex(), 'h2': h2.hex(),
        'blake2b_1': b1.hex(), 'blake2b_2': b2.hex(), 'mask': mask.hex(),
        'asic_profile': profile, 'asic_input': asic_input.hex(),
        'block_hash': block_hash.hex(),  # display order, as bitcoind prints it
    }


def hash_header_v2(h: dict) -> str:
    return hash_header_v2_detailed(h)['block_hash']


def hash_raw_header_v2(raw: bytes) -> str:
    return hash_header_v2(deserialize_header_v2(raw, 0))
