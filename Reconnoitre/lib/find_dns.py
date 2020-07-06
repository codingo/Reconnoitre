#!/usr/bin/python
from Reconnoitre.lib.file_helper import FileHelper
from Reconnoitre.lib.subprocess_helper import run_scan


class FindDns(object):

    def __init__(
            self,
            target_hosts,
            output_directory,
            quiet):

        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.output_file = f"{self.output_directory}/DNS-Detailed.txt"
        self.output_targets = f"{self.output_directory}/DNS-targets.txt"
        self.quiet = quiet
        self.dns_server_list = []
        self.results = 0
        self.hostcount = 0
        self.dnscount = 0

    def find_dns(self):
        FileHelper.check_directory(output_directory=self.output_directory)
        output_file = open(self.output_file, 'w')
        output_targets = open(self.output_targets, 'w')
        targets = FileHelper.load_targets(self.target_hosts, self.output_directory, self.quiet)
        FileHelper.check_file(targets)
        try:
            target_file = open(targets, 'r')
            print("[*] Loaded targets from: %s" % targets)
        except FileExistsError as err:
            print("[!] Unable to load: %s" % targets)
            raise err

        print("[*] Loaded targets from: %s" % targets)
        print("[+] Enumerating TCP port 53 over targets to find dns servers")

        for ip_address in target_file:
            self.hostcount += 1
            ip_address = ip_address.strip()
            ip_address = ip_address.rstrip()

            print("   [>] Testing %s for DNS" % ip_address)
            DNSSCAN = "nmap -n -sV -Pn -vv -p53 %s" % (ip_address)
            results = run_scan(DNSSCAN)
            lines = results.split("\n")

            for line in lines:
                line = line.strip()
                line = line.rstrip()
                if (("53/tcp" in line) and ("open" in line) and ("Discovered" not in line)):
                    print("      [=] Found DNS service running on: %s" % (ip_address))
                    output_file.write("[*] Found DNS service running on: %s\n" % (ip_address))
                    output_file.write("   [>] %s\n" % (line))
                    output_targets.write("%s\n" % (ip_address))
                    self.dns_server_list.append(ip_address)
                    self.dnscount += 1

        print("[*] Found %s DNS servers within %s hosts" % (str(self.dnscount), str(self.hostcount)))
        output_file.close()
        output_targets.close()
        target_file.close()
        return '' if len(self.dns_server_list) == 0 else ','.join(self.dns_server_list)
