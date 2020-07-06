#!/usr/bin/python
from unittest import TestCase
from Reconnoitre.lib.hostname_scan import HostnameScan
import os

class TestHostnameScan(TestCase):
    HOST = "192.168.1.0/24"
    OUTPUT_DIR = "results"
    OUTPUT_FILE = f"{OUTPUT_DIR}/hostnames.txt"
    H = HostnameScan(target_hosts=HOST, output_directory=OUTPUT_DIR, quiet=False)

    def test_hostname_scan(self):
        self.H.hostname_scan()
        self.assertTrue(os.path.exists(self.OUTPUT_FILE))
        self.assertTrue(os.path.isfile(self.OUTPUT_FILE))
        os.remove(self.OUTPUT_FILE)

