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


def nmap_scan(ip_address, output_directory, dns_server, quick):
   ip_address = ip_address.strip()

   print("[+] Starting quick nmap scan for %s" % (ip_address))
   QUICKSCAN = "nmap -sC -sV %s -oA '%s/%s.quick'"  % (ip_address, output_directory, ip_address)
   quickresults = subprocess.check_output(QUICKSCAN, shell=True)

   write_recommendations(quickresults, ip_address, output_directory)
   print("[*] TCP quick scans completed for %s" % ip_address)

   if(quick):
       return

   if dns_server:
       print("[+] Starting detailed TCP/UDP nmap scans for %s using DNS Server %s" % (ip_address, dns_server))
       print("[+] Using DNS server %s" % (dns_server))
       TCPSCAN = "nmap -vv -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 --dns-servers %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
       UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 --max-retries 0 --dns-servers %s -oN '%s/%sU.nmap' -oX '%s/%sU_nmap_scan_import.xml' %s" % (dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
   else:
       print("[+] Starting detailed TCP/UDP nmap scans for %s" % (ip_address))
       TCPSCAN = "nmap -vv -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 -n %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
       UDPSCAN = "nmap -sC -sV -sU %s -oA '%s/%s-udp'" % (ip_address, output_directory, ip_address)

   udpresults = subprocess.check_output(UDPSCAN, shell=True)
   tcpresults = subprocess.check_output(TCPSCAN, shell=True)

   write_recommendations(tcpresults + udpresults, ip_address, output_directory)
   print("[*] TCP/UDP scans completed for %s" % ip_address)


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def target_file(target_hosts, output_directory, dns_server, quiet, quick):
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
       nmap_directory = host_directory + "/scans"

       jobs = []
       p = multiprocessing.Process(target=nmap_scan, args=(ip_address, nmap_directory, dns_server, quick))
       jobs.append(p)
       p.start()
    target_file.close()


def target_ip(target_hosts, output_directory, dns_server, quiet, quick):
    print("[*] Loaded single target: %s" % target_hosts)
    target_hosts = target_hosts.strip()
    create_dir_structure(target_hosts, output_directory)

    host_directory = output_directory + "/" + target_hosts
    nmap_directory = host_directory + "/scans"

    jobs = []
    p = multiprocessing.Process(target=nmap_scan, args=(target_hosts, nmap_directory, dns_server, quick))
    jobs.append(p)
    p.start()


def service_scan(target_hosts, output_directory, dns_server, quiet, quick):
    check_directory(output_directory)

    if(valid_ip(target_hosts)):
        target_ip(target_hosts, output_directory, dns_server, quiet, quick)
    else:
        target_file(target_hosts, output_directory, dns_server, quiet, quick)
