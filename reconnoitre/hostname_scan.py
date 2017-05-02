import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory
from file_helper import load_targets
from file_helper import create_dir_structure
from file_helper import write_recommendations



def hostname_scan(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/hostnames.txt"
    print("[+] Writing hostsnames to: %s" % output_file)
    hostnames = 0

    SWEEP = ''
    if(os.path.isfile(target_hosts)):
        SWEEP = "nbtscan -q -f " % (target_hosts)
    else:
        SWEEP = "nbtscan -q " % (target_hosts)

    results = subprocess.check_output(SWEEP, shell=True)
    lines = results.split("\n")
    
    for line in lines:
        line = line.strip()
        line = line.rstrip()
        if ("Nmap scan report for" in line):
            ip_address = line.split(" ")[1]
            host = line.split(" ")[2]
            if (hostnames > 0):
                f.write('\n')
            f.write("%s - %s" % (host, ip_address))
            print("   [>] Discovered hostname: %s (%s)" % (host, ip_address))
            hostnames += 1
    print("[*] Found %s hostnames." % (hostnames))
    print("[*] Created hostname list %s" % (output_file))
    f.close()