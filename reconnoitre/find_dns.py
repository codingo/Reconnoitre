import subprocess
import sys
import os
from directory_helper import check_directory

def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/DNS-Servers.txt"

    if(os.path.isdir(target_hosts)):
        targets = open(target_hosts, 'r')
    else:
        targets = open(output_directory + "/targets.txt")
    print("[*] Loaded targets from: %s" % targets)