#!/usr/bin/python
from unittest import TestCase
from Reconnoitre.lib.service_scan import ServiceScan
import os


class TestServiceScan(TestCase):

    IP_ADDR = '34.94.3.143'
    OUTPUT_DIR = 'results'
    DNS_SERVER = ''
    QUIET = False
    QUICK = False
    no_udp_service_scan = True
    sscan = ServiceScan(IP_ADDR, OUTPUT_DIR, DNS_SERVER, QUIET, QUICK, no_udp_service_scan)

    def test_valid_ip(self):
        self.assertTrue(self.sscan.valid_ip(self.IP_ADDR))
