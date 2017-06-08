import subprocess
import sys
import os
from file_helper import check_directory


def ping_sweeper(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/targets.txt"

    print("[+] Writing discovered targets to: %s" % output_file)
    live_hosts = 0
    f = open(output_file, 'w')

    print("[+] Performing ping sweep over %s" % target_hosts)

    SWEEP = "nmap -n -sP %s" % (target_hosts)
    results = subprocess.check_output(SWEEP, shell=True)
    lines = results.split("\n")
    
    for line in lines:
        line = line.strip()
        line = line.rstrip()
        if ("Nmap scan report for" in line):
            ip_address = line.split(" ")[4]
            if (live_hosts > 0):
                f.write('\n')
            f.write("%s" % (ip_address))
            print("   [>] Discovered host: %s" % (ip_address))
            live_hosts += 1
    print("[*] Found %s live hosts" % (live_hosts))
    print("[*] Created target list %s" % (output_file))
    f.close()
