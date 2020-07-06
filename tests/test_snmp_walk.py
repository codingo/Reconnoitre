#!/usr/bin/python
from Reconnoitre.lib.snmp_walk import SnmpWalk
from unittest import TestCase
import os


class TestSnmpWalk(TestCase):
    HOST = "34.94.3.143"
    OUTPUT_DIR = "results"
    SNMP_DIR = f"{OUTPUT_DIR}/{HOST}/scans/snmp/"
    sw = SnmpWalk(HOST, OUTPUT_DIR, False)

    def test_valid_ip(self):
        self.assertTrue(self.sw.valid_ip(self.HOST))
