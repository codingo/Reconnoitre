#!/usr/bin/python
from Reconnoitre.lib.file_helper import FileHelper
from Reconnoitre.lib.subprocess_helper import run_scan


class PingSweeper(object):

    def __init__(
            self,
            target_hosts,
            output_directory,
            quiet):

        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.output_file = f"{self.output_directory}/targets.txt"
        self.quiet = quiet
        self.live_hosts = None
        self.nmap_lines = None

    def ping_sweeper(self):
        FileHelper.check_directory(output_directory=self.output_directory)
        print("[+] Performing ping sweep over %s" % self.target_hosts)

        self.call_nmap_sweep()
        self.parse_nmap_output_for_live_hosts()
        self.write_live_hosts_list_to_file()

        for ip_address in self.live_hosts:
            print("   [>] Discovered host: %s" % (ip_address))

        print("[*] Found %s live hosts" % (len(self.live_hosts)))
        print("[*] Created target list %s" % (self.output_file))

    def call_nmap_sweep(self):
        SWEEP = "nmap -n -sP %s" % (self.target_hosts)
        results = run_scan(SWEEP)
        self.nmap_lines = str(results).split("\n")

    def parse_nmap_output_for_live_hosts(self):
        def get_ip_from_nmap_line(line):
            return line.split()[4]

        self.live_hosts = [get_ip_from_nmap_line(line)
                      for line in self.nmap_lines
                      if "Nmap scan report for" in line]

    def write_live_hosts_list_to_file(self):
        print(f"[+] Writing discovered targets to: {self.output_file}")
        with open(self.output_file, "w") as f:
            f.write("\n".join(self.live_hosts))
