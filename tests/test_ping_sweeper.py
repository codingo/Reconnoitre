#!/usr/bin/python
from unittest import TestCase
from Reconnoitre.lib.ping_sweeper import PingSweeper
import os


class TestPingSweep(TestCase):
    """TODO: Add more tests covering unhappy paths"""

    HOST = "34.94.3.143"
    OUTPUT_DIR = "results"
    OUTPUT_FILE = f"{OUTPUT_DIR}/test-live-hosts.txt"
    PS = PingSweeper(target_hosts=HOST, output_directory=OUTPUT_DIR, quiet=False)

    TEST_LINES = """
    # Nmap 7.80 scan initiated Sat Jun 27 15:54:26 2020 as: nmap -sC -sV -Pn --disable-arp-ping -oA /home/ben/Desktop/34.94.3.143/scans/34.94.3.143.quick 34.94.3.143
    Nmap scan report for 143.3.94.34.bc.googleusercontent.com (34.94.3.143)
    Host is up (0.060s latency).
    Not shown: 997 filtered ports
    PORT     STATE  SERVICE       VERSION
    22/tcp   open   ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 fc:4c:60:8c:ed:13:eb:21:90:72:e1:2b:96:60:fb:6e (RSA)
    |   256 d9:cb:07:30:e2:eb:2d:67:d5:c6:7c:55:f1:f4:7e:34 (ECDSA)
    |_  256 73:e8:91:5d:f8:8e:f7:57:f6:99:b2:3c:77:aa:0b:f9 (ED25519)
    80/tcp   open   http          nginx 1.14.0 (Ubuntu)
    |_http-server-header: nginx/1.14.0 (Ubuntu)
    |_http-title: Welcome to nginx!
    5001/tcp closed commplex-link
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Sat Jun 27 15:54:41 2020 -- 1 IP address (1 host up) scanned in 14.83 seconds
    """

    def test_ping_sweeper(self):
        self.PS.ping_sweeper()
        self.assertTrue(os.path.exists(f"{self.OUTPUT_DIR}/targets.txt"))

    def test_call_nmap_sweep(self):
        self.PS.call_nmap_sweep()
        self.assertTrue(self.HOST in "\n".join(self.PS.nmap_lines))

    def test_parse_nmap_output_for_live_hosts(self):
        self.PS.parse_nmap_output_for_live_hosts()
        self.assertIsInstance(self.PS.live_hosts, list)

    def test_write_live_hosts_list_to_file(self):
        self.PS.ping_sweeper()
        self.PS.write_live_hosts_list_to_file()
        self.assertTrue(os.path.exists(self.PS.output_file))
        os.remove(self.PS.output_file)
