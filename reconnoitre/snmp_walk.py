import subprocess
import multiprocessing
import socket
import os
import time
from multiprocessing import Process, Queue
from file_helper import check_directory, load_targets


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

       snmp_directory = output_directory + '/' + ip_address+ '/scans/snmp/'
       check_directory(snmp_directory)

       jobs = []
       p = multiprocessing.Process(target=snmp_scans, args=(ip_address, snmp_directory))
       jobs.append(p)
       p.start()
    target_file.close()


def target_ip(target_hosts, output_directory, quiet):
    print("[*] Loaded single target: %s" % target_hosts)
    target_hosts = target_hosts.strip()

    snmp_directory = output_directory + '/' + target_hosts+ '/scans/snmp/'
    check_directory(snmp_directory)

    jobs = []
    p = multiprocessing.Process(target=snmp_scans, args=(target_hosts, snmp_directory))
    jobs.append(p)
    p.start()


def snmp_walk(target_hosts, output_directory, quiet):
    check_directory(output_directory)

    if(valid_ip(target_hosts)):
        target_ip(target_hosts, output_directory, quiet)
    else:
        target_file(target_hosts, output_directory, quiet)
        
def snmp_scans(ip_address, output_directory):
    print("[+] Performing SNMP scans for %s to %s" % (ip_address, output_directory))
    # Public Community Strings
    PUBLIC_SYSTEM_PROCESS_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.1.6.0 > '%s%s-systemprocesses.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_RUNNING_PROGRAMS_SCAN  = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.2 > '%s%s-runningprograms.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_PROCESS_PATH_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.4 > '%s%s-processespath.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_STORAGE_UNITS_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.2.3.1.4 > '%s%s-storageunits.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_SOFTWARE_NAMES_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.6.3.1.2 > '%s%s-softwarename.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_USER_ACCOUNTS_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.4.1.77.1.2.25 > '%s%s-useraccounts.txt'"  % (ip_address, output_directory, ip_address)
    PUBLIC_TCP_LOCAL_PORTS_SCAN = "snmpwalk -c public -v1 %s 1.3.6.1.2.1.6.13.1.3 > '%s%s-tcplocalports.txt'"  % (ip_address, output_directory, ip_address)
    # Private Community Strings
    PRIVATE_SYSTEM_PROCESS_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.25.1.6.0 > '%s%s-systemprocesses.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_RUNNING_PROGRAMS_SCAN  = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.25.4.2.1.2 > '%s%s-runningprograms.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_PROCESS_PATH_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.25.4.2.1.4 > '%s%s-processespath.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_STORAGE_UNITS_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.25.2.3.1.4 > '%s%s-storageunits.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_SOFTWARE_NAMES_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.25.6.3.1.2 > '%s%s-softwarename.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_USER_ACCOUNTS_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.4.1.77.1.2.25 > '%s%s-useraccounts.txt'"  % (ip_address, output_directory, ip_address)
    PRIVATE_TCP_LOCAL_PORTS_SCAN = "snmpwalk -c PRIVATE -v1 %s 1.3.6.1.2.1.6.13.1.3 > '%s%s-tcplocalports.txt'"  % (ip_address, output_directory, ip_address)
    # Manager Community Strings
    MANAGER_SYSTEM_PROCESS_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.25.1.6.0 > '%s%s-systemprocesses.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_RUNNING_PROGRAMS_SCAN  = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.25.4.2.1.2 > '%s%s-runningprograms.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_PROCESS_PATH_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.25.4.2.1.4 > '%s%s-processespath.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_STORAGE_UNITS_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.25.2.3.1.4 > '%s%s-storageunits.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_SOFTWARE_NAMES_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.25.6.3.1.2 > '%s%s-softwarename.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_USER_ACCOUNTS_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.4.1.77.1.2.25 > '%s%s-useraccounts.txt'"  % (ip_address, output_directory, ip_address)
    MANAGER_TCP_LOCAL_PORTS_SCAN = "snmpwalk -c MANAGER -v1 %s 1.3.6.1.2.1.6.13.1.3 > '%s%s-tcplocalports.txt'"  % (ip_address, output_directory, ip_address)
    try:
        print("   [>] Performing snmpwalk on public tree for: %s - Checking for System Processes" % (ip_address))
        results = subprocess.check_output(PUBLIC_SYSTEM_PROCESS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_RUNNING_PROGRAMS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_PROCESS_PATH_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_STORAGE_UNITS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_SOFTWARE_NAMES_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_USER_ACCOUNTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PUBLIC_TCP_LOCAL_PORTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        print("   [>] Performing snmpwalk on private tree for: %s - Checking for System Processes" % (ip_address))
        results = subprocess.check_output(PRIVATE_SYSTEM_PROCESS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_RUNNING_PROGRAMS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_PROCESS_PATH_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_STORAGE_UNITS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_SOFTWARE_NAMES_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_USER_ACCOUNTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(PRIVATE_TCP_LOCAL_PORTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        print("   [>] Performing snmpwalk on manager tree for: %s - Checking for System Processes" % (ip_address)) 
        results = subprocess.check_output(MANAGER_SYSTEM_PROCESS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_RUNNING_PROGRAMS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_PROCESS_PATH_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_STORAGE_UNITS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_SOFTWARE_NAMES_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_USER_ACCOUNTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        results = subprocess.check_output(MANAGER_TCP_LOCAL_PORTS_SCAN, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
    except Exception as e:
        print("[+] No Response from %s" % ip_address)
    except subprocess.CalledProcessError as cpe:
        print("[+] Subprocess failure during scan of %s" % ip_address)

    print("[+] Completed SNMP scans for %s" % (ip_address))
