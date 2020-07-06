#!/usr/bin/python
from unittest import TestCase
from Reconnoitre.lib.find_dns import FindDns
import os


class TestFindDns(TestCase):
    HOST = "35.227.24.107"
    OUTPUT_DIR = "results"
    OUTPUT_FILE = f"{OUTPUT_DIR}/targets.txt"
    OUTPUT_DETAILS = f"{OUTPUT_DIR}/DNS-Detailed.txt"
    OUTPUT_TARGETS = f"{OUTPUT_DIR}/DNS-targets.txt"
    F = FindDns(target_hosts=HOST, output_directory=OUTPUT_DIR, quiet=False)

    def test_find_dns(self):
        res = self.F.find_dns()
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(self.OUTPUT_FILE))
        self.assertTrue(os.path.exists(self.OUTPUT_DETAILS))
        self.assertTrue(os.path.exists(self.OUTPUT_TARGETS))
        os.remove(self.OUTPUT_FILE)
        os.remove(self.OUTPUT_DETAILS)
        os.remove(self.OUTPUT_TARGETS)
