#!/usr/bin/python
from Reconnoitre.lib.file_helper import FileHelper
from Reconnoitre.lib.subprocess_helper import run_scan
import os


class HostnameScan(object):

    def __init__(
            self,
            target_hosts,
            output_directory,
            quiet):

        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.output_file = f"{self.output_directory}/hostnames.txt"
        self.quiet = quiet
        self.hostnames = 0

    def hostname_scan(self):
        FileHelper.check_directory(self.output_directory)
        FileHelper.check_file(self.output_file)
        f = open(self.output_file, 'w')
        print("[+] Writing hostnames to: %s" % self.output_file)

        SWEEP = ''

        if (os.path.isfile(self.target_hosts)):
            SWEEP = "nbtscan -q -f %s" % (self.target_hosts)
        else:
            SWEEP = "nbtscan -q %s" % (self.target_hosts)

        results = run_scan(SWEEP)
        lines = results.split("\n")

        for line in lines:
            line = line.strip()
            line = line.rstrip()

            # Final line is blank which causes list index issues if we don't
            # continue past it.
            if " " not in line:
                continue

            while "  " in line:
                line = line.replace("  ", " ")

            ip_address = line.split(" ")[0]
            host = line.split(" ")[1]

            if (self.hostnames > 0):
                f.write('\n')

            print("   [>] Discovered hostname: %s (%s)" % (host, ip_address))
            f.write("%s - %s" % (host, ip_address))
            self.hostnames += 1

        print("[*] Found %s hostnames." % (self.hostnames))
        print("[*] Created hostname list %s" % (self.output_file))
        f.close()
