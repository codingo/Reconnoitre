import os
from lib.utility import Utility

class HostNameScan():
    def __init__(self, target_hosts, output_directory, quiet):
        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.quiet = quiet
        self.hostnames = 0
        self.output_file = "{}/hostnames.txt".format(self.output_directory)

    def hostname_scan(self, target_hosts, output_directory, quiet):
        Utility.check_directory(output_directory)
        f = open(self.output_file, 'w')
        print("[+] Writing hostnames to: %s" % self.output_file)

        SWEEP = ''

        if (os.path.isfile(target_hosts)):
            SWEEP = "nbtscan -q -f %s" % (target_hosts)
        else:
            SWEEP = "nbtscan -q %s" % (target_hosts)

        results = Utility.run_scan(SWEEP)
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
