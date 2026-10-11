import json
import os
from pathlib import Path

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum.blockchain import Blockchain, BlockchainManager, deserialize_header, hash_header, CHUNK_SIZE, HEADER_SIZE
from electrum.util import bfh

from . import ElectrumTestCase


FIXTURES = os.path.dirname(__file__)
FORK = 961640
FORK_CHUNK = FORK // CHUNK_SIZE  # 477: heights 961632..963647, the fork inside it


class TestMainnetBlake2bPoW(ElectrumTestCase):
    """Real mainnet headers across the BLAKE2b fork and the two retargets after it.
    Chunk 477 is verified against checkpoint 476 exactly as a syncing client does."""

    def setUp(self):
        super().setUp()
        self.data_dir = Path(self.electrum_path)
        self.config = SimpleConfig({'electrum_path': self.data_dir})
        self.bc_mgr = BlockchainManager.from_config(self.config)
        self.chain = self.bc_mgr.get_best_chain()
        with open(os.path.join(FIXTURES, 'mainnet_headers_chunk477.bin'), 'rb') as f:
            self.chunk = f.read()
        with open(os.path.join(FIXTURES, 'mainnet_headers_extra.json')) as f:
            self.extra = {int(k): bfh(v) for k, v in json.load(f).items()}

    def test_checkpoints_stop_below_fork(self):
        self.assertEqual(len(constants.net.CHECKPOINTS), FORK_CHUNK)
        self.assertLess(constants.net.max_checkpoint(), FORK)

    def test_target_shift(self):
        # bits of block 961639 (SHA256d) shifted by 22 give the bits of 961640 (first BLAKE2b block)
        t = Blockchain.bits_to_target(0x1702353d)
        self.assertEqual(Blockchain.target_to_bits(Blockchain.apply_blake2b_target_shift(t)), 0x1a008d4f)
        # a target already near the limit is capped at the limit
        near = Blockchain.bits_to_target(0x1d00ffff)
        self.assertEqual(Blockchain.target_to_bits(Blockchain.apply_blake2b_target_shift(near)), 0x1d00ffff)

    def test_fork_chunk_connects_and_retargets(self):
        self.assertTrue(self.chain.connect_chunk(FORK_CHUNK, self.chunk))
        self.assertEqual(self.chain.height(), FORK_CHUNK * CHUNK_SIZE + CHUNK_SIZE - 1)
        self.assertEqual(hash_header(self.chain.read_header(FORK)),
                         "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb")
        self.assertEqual(self.chain.read_header(FORK - 1)['bits'], 0x1702353d)
        self.assertEqual(self.chain.read_header(FORK)['bits'], 0x1a008d4f)
        # first retarget after the fork, computed from the shifted bits
        h963648 = deserialize_header(self.extra[963648], 963648)
        self.assertEqual(h963648['bits'], 0x1a00f0b5)
        self.assertEqual(Blockchain.target_to_bits(self.chain.target_for_height(963648)), 0x1a00f0b5)
        self.assertTrue(self.chain.can_connect(h963648))
        self.chain.save_header(h963648)
        # second retarget: needs the first and last header of chunk 478 only
        h965663 = deserialize_header(self.extra[965663], 965663)
        delta = 965663 - self.chain.forkpoint
        self.chain.write(self.chunk[:0] + self._slot(self.extra[965663]), delta * HEADER_SIZE, truncate=False)
        self.assertEqual(h965663['bits'], 0x1a00f0b5)
        self.assertEqual(Blockchain.target_to_bits(self.chain.target_for_height(965664)), 0x193c2d40)
        self.assertEqual(deserialize_header(self.extra[965664], 965664)['bits'], 0x193c2d40)

    def test_fork_chunk_rejected_without_the_shift(self):
        # the pre-fork formula alone (no shift) must not accept the chain
        orig = constants.net.BLAKE2B_TARGET_SHIFT
        constants.net.BLAKE2B_TARGET_SHIFT = 0
        try:
            self.assertFalse(self.chain.connect_chunk(FORK_CHUNK, self.chunk))
        finally:
            constants.net.BLAKE2B_TARGET_SHIFT = orig

    def test_legacy_header_after_fork_rejected(self):
        # a SHA256d-chain header at the fork height (80 bytes) is refused regardless of its PoW
        before = self.chunk[:(FORK - FORK_CHUNK * CHUNK_SIZE) * 80]
        legacy_at_fork = self.chunk[:80]  # any 80-byte header
        self.assertFalse(self.chain.connect_chunk(FORK_CHUNK, before + legacy_at_fork))

    @staticmethod
    def _slot(raw: bytes) -> bytes:
        return raw + bytes(HEADER_SIZE - len(raw))
