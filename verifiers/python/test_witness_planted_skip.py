# A planted skip for a witness run of the Conformance workflow. It is not for merge.
import unittest


class WitnessPlantedSkip(unittest.TestCase):
    @unittest.skip("planted skip, witness run, not for merge")
    def test_planted_skip(self):
        pass
