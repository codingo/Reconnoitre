import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory
from file_helper import create_dir_structure

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def target_file(target_hosts, output_directory, quiet):    
    targets = load_targets(target_hosts, output_directory, quiet)
    target_file = open(targets, 'r')
    try:
        target_file = open(targets, 'r')
        print("[*] Loaded targets from: %s" % targets)
    except:
        print("[!] Unable to load: %s" % targets)

    for ip_address in target_file:
       ip_address = ip_address.strip()
       create_dir_structure(ip_address, output_directory)

       host_directory = output_directory + "/" + ip_address
       snamp_directory = host_directory + "/scans/snmp/"
       
       jobs = []
       p = multiprocessing.Process(target=snmp_scans, args=(ip_address, snamp_directory))
       jobs.append(p)
       p.start()
    target_file.close() 


def target_ip(target_hosts, output_directory, quiet):
    print("[*] Loaded single target: %s" % target_hosts)
    target_hosts = target_hosts.strip()    
    create_dir_structure(target_hosts, output_directory)

    host_directory = output_directory + "/" + ip_address
    snamp_directory = host_directory + "/scans/snmp/"
    
    jobs = []
    p = multiprocessing.Process(target=snmp_scans, args=(ip_address, snamp_directory))
    jobs.append(p)
    p.start()


def snmp_walk(target_hosts, output_directory, quiet):
    check_directory(output_directory)

    if(valid_ip(target_hosts)):
        target_ip(target_hosts, output_directory, quiet)
    else:
        target_file(target_hosts, output_directory, quiet)

def snmp_scans(ip, output_directory):
    print("[+] Performing SNMP scans for %s to %s" % (ip_address, output_directory))	
    print("   [>] Performing snmpwalk on public tree for: %s - Checking for System Processes" % (ip_address))
    SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.1.6.0 > %s/%s/%s-systemprocesses.txt"  % (ip_address, output_directory, ip_address, ip_address)
    subprocess.check_output(SCAN, shell=True)
    print("[+] Completed SNMP scans for %s" % (ip_address))