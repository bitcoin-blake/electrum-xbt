import json
import os

from electrum import blake

from . import ElectrumTestCase


VECTORS = os.path.join(os.path.dirname(__file__), 'block_header_v2.json')


def _header_from_fields(f: dict) -> dict:
    return {
        'version': f['nVersion'], 'prev_block_hash': f['hashPrevBlock'], 'merkle_root': f['hashMerkleRoot'],
        'timestamp': f['nTime'], 'bits': f['nBits'], 'nonce': f['nNonce'], 'nonce2': f['m_nonce2'],
        'nonce3': f['m_nonce3'], 'extranonce': f['m_extranonce'], 'time_offset': f['m_time_offset'],
        'tx_count': f['m_txcount'], 'flags': f['m_flags'], 'xor_key_mask_clear_bits': f['m_xor_key_mask_clear_bits'],
        'xor_key': f['m_xor_key'], 'height': f['m_height'], 'mm_rhs': f['m_mm_rhs'],
    }


class TestHeaderV2(ElectrumTestCase):

    def test_primitives(self):
        self.assertEqual(blake.blake2b_256(b'').hex(),
                         '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8')

    def test_knots_vectors(self):
        with open(VECTORS) as f:
            vectors = json.load(f)['headers']
        self.assertEqual(len(vectors), 5)
        for t in vectors:
            h = _header_from_fields(t['fields'])
            raw = blake.serialize_header_v2(h)
            self.assertEqual(len(raw), blake.HEADER_V2_SIZE, t['name'])
            self.assertEqual(raw.hex(), t['serialized'], t['name'])
            self.assertTrue(blake.is_header_v2(raw))
            dec = blake.deserialize_header_v2(bytes.fromhex(t['serialized']), 840000)
            self.assertEqual(dec['timestamp'], t['fields']['nTime'], t['name'])
            self.assertEqual(blake.serialize_header_v2(dec).hex(), t['serialized'], t['name'])
            d = blake.hash_header_v2_detailed(h)
            for k in ('xor_key_hash', 'h1', 'h2', 'blake2b_1', 'asic_profile', 'asic_input', 'blake2b_2', 'mask', 'block_hash'):
                self.assertEqual(d[k], t[k], f"{t['name']}: {k}")
            self.assertEqual(blake.hash_raw_header_v2(raw), t['block_hash'], t['name'])
