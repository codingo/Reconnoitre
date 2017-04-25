import subprocess
import sys
import os
from directory_helper import check_directory
from directory_helper import load_targets

def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    results = 0
    output_file = open(output_directory + "/DNS-Servers.txt", 'w')
    output_targets = open(output_directory + "/DNS-targets.txt", 'w')
    targets = load_targets(target_hosts, output_directory, quiet)
    print("[*] Loaded targets from: %s" % targets)

    print("[+] Enumerating TCP port 53 to find dns servers")
    for ip_address in targets:
        ip_address = ip_address.strip()
        DNSSCAN = "nmap -n -sV -Pn -vv -p53 %s" % (ip_address)
        results = subprocess.check_output(DNSSCAN, shell=True)
        lines = results.split("\n")
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            if ("53/tcp" in line) and ("open" in line) and ("open" in line) and not ("Discovered" in line):
                print("[*] Found DNS service running on: %s/TCP" % (ip_address))
                output_file.write("[*] Found DNS service running on: %s/TCP\n" % (ip_address))
                output_targets.write("%s" % (ip_address))
                print("   [>] %s" % (line))
                output_file.write("   [>] %s\n" % (line))
                results += 1
    print("[*] Found %s DNS servers" % (results))
    output_file.close()
    output_targets.close()