#!/usr/bin/python
from Reconnoitre.lib.subprocess_helper import run_scan
from Reconnoitre.lib.file_helper import FileHelper
import multiprocessing
import socket
import subprocess


class SnmpWalk(object):

    def __init__(
            self,
            target_hosts,
            output_directory,
            quiet):

        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.quiet = quiet
        self.snmp_directory = f"{self.output_directory}/{self.target_hosts}/scans/snmp/"

    @staticmethod
    def valid_ip(address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def target_file(self):
        targets = FileHelper.load_targets(self.target_hosts, self.output_directory, self.quiet)
        FileHelper.check_file(targets)

        try:
            target_file = open(targets, 'r')
            print(f"[*] Loaded targets from: {targets}")
        except FileNotFoundError as err:
            print(f"[!] Unable to load: {targets}")
            raise err

        for ip_address in target_file:
            ip_address = ip_address.strip()
            snmp_directory = f"{self.output_directory}/{ip_address}/scans/snmp/"
            FileHelper.check_directory(output_directory=snmp_directory)

            jobs = []
            p = multiprocessing.Process(target=SnmpWalk.snmp_scans)
            jobs.append(p)
            p.start()
        target_file.close()

    def target_ip(self):
        print(f"[*] Loaded single target: {self.target_hosts}")
        FileHelper.check_directory(output_directory=self.snmp_directory)
        jobs = []
        p = multiprocessing.Process(target=SnmpWalk.snmp_scans)
        jobs.append(p)
        p.start()

    def snmp_walk(self):
        FileHelper.check_directory(output_directory=self.output_directory)

        if (self.valid_ip(self.target_hosts)):
            self.target_ip()
        else:
            self.target_file()

    def snmp_scans(self):
        print(f"[+] Performing SNMP scans for {self.target_hosts} to {self.output_directory}")
        print(f"\t[>] Performing snmpwalk on public tree for: {self.target_hosts} - Checking for System Processes")
        SCAN = (f"snmpwalk -c public -v1 {self.target_hosts} 1.3.6.1.2.1.25.1.6.0 > '{self.output_directory}/{self.target_hosts}/systemprocesses.txt'")
        run_scan(SCAN, stderr=subprocess.STDOUT)
        print("[+] Completed SNMP scans for %s" % (self.target_hosts))
