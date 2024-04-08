import os
import unittest

from rasim import Engine


class TestRasim(unittest.TestCase):

    def test_gen_sig(self):
        self_path = os.path.dirname(os.path.realpath(__file__))
        target = Engine(os.path.join(self_path, "r_anal.dll"), platform="win", debug=True)
        print(target.bin_path)
        target.gen_sig()
        print(len(target.sig_list))
        return

    def test_store_sig(self):
        self_path = os.path.dirname(os.path.realpath(__file__))
        target = Engine(os.path.join(self_path, "r_anal.dll"), platform="win", es_pass="ByteBSCA", debug=True)
        print(target.bin_path)
        target.store_sig()
        return
