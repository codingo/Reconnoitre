import subprocess
import sys
import os
from directory_helper import check_directory
from directory_helper import load_targets

def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/DNS-Servers.txt"


    
    targets = load_targets(target_hosts, output_directory, quiet)

    print("[*] Loaded targets from: %s" % targets)