import subprocess
import sys
import os
from file_helper import check_directory


def ping_sweeper(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/targets.txt"

    print("[+] Writing discovered targets to: %s" % output_file)
    f = open(output_file, 'w')

    print("[+] Performing ping sweep over %s" % target_hosts)

    SWEEP = "nmap -n -sP %s" % (target_hosts)
    results = subprocess.check_output(SWEEP, shell=True)
    lines = str(results, "utf-8").split("\n")
    
    live_hosts = parse_nmap_output_for_live_hosts(lines)
    f.write("\n".join(live_hosts))
    for ip_address in live_hosts:
        print("   [>] Discovered host: %s" % (ip_address))
    print("[*] Found %s live hosts" % (len(live_hosts)))
    print("[*] Created target list %s" % (output_file))
    f.close()


def parse_nmap_output_for_live_hosts(lines):
    def get_ip_from_nmap_line(line):
        return line.split()[4]

    live_hosts = [get_ip_from_nmap_line(line)
                  for line in lines
                  if "Nmap scan report for" in line]

    return live_hosts

