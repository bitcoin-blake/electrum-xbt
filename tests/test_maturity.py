from electrum import constants
from electrum.bitcoin import coinbase_maturity_heights, coinbase_spendable_height

from . import ElectrumTestCase


class TestLongCoinbaseMaturity(ElectrumTestCase):
    """The same cases as the blake web wallet's test.mjs, mainnet parameters."""

    def test_mainnet_heights(self):
        self.assertEqual(constants.net.LONG_COINBASE_MATURITY, (973440, 979920, 6480))
        # pre-window coinbase: 100 by consensus, 6480 by policy
        self.assertEqual(coinbase_maturity_heights(970198), (970298, 976678))
        # last pre-window height still 100 by consensus
        self.assertEqual(coinbase_maturity_heights(973439), (973539, 979919))
        # in-window coinbase: released when the window closes, 6480 by policy
        self.assertEqual(coinbase_maturity_heights(974010), (979920, 980490))
        # first in-window height: both at release
        self.assertEqual(coinbase_maturity_heights(973440), (979920, 979920))
        # near release: 100 by consensus once the window closes
        self.assertEqual(coinbase_maturity_heights(979900), (980000, 986380))

    def test_spendable_is_policy(self):
        tip = 976661
        self.assertGreater(coinbase_spendable_height(970198), tip + 1)   # maturing at this tip
        self.assertLessEqual(coinbase_spendable_height(970198), 976677 + 1)  # spendable once 6480 deep
        self.assertGreater(coinbase_spendable_height(974010), 979919 + 1)  # consensus-mature at release, policy-locked


class TestLongCoinbaseMaturityTestnet4(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        constants.BitcoinTestnet4.set_as_network()

    def tearDown(self):
        constants.BitcoinTestnet.set_as_network()
        super().tearDown()

    def test_testnet4_heights(self):
        self.assertEqual(constants.net.LONG_COINBASE_MATURITY, (151406, 158111, 6705))
        self.assertEqual(coinbase_maturity_heights(150371), (150471, 157076))  # knots-miner's first coinbases
        self.assertEqual(coinbase_maturity_heights(151406), (158111, 158111))
        self.assertEqual(coinbase_maturity_heights(152000), (158111, 158705))


class TestPlainMaturity(ElectrumTestCase):
    TESTNET = True  # plain testnet3 has no fork and no long maturity

    def test_100(self):
        self.assertIsNone(constants.net.LONG_COINBASE_MATURITY)
        self.assertEqual(coinbase_maturity_heights(5000), (5100, 5100))
