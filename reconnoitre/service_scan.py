import subprocess
import multiprocessing
import socket
from multiprocessing import Process, Queue
import os
import time 
from directory_helper import check_directory
from directory_helper import load_targets
from directory_helper import create_dir_structure
from write_recommendations import write_recommendations


def nmapScan(ip_address, outputdir, dns_server):
   ip_address = ip_address.strip()
   outfile = outputdir + "/" + ip_address + "_findings.txt"

   print("[+] Starting quick nmap scan for %s" % (ip_address))
   QUICKSCAN = "nmap -n -oN '%s/%s.quick.nmap' %s"  % (outputdir, ip_address, ip_address)
   quickresults = subprocess.check_output(QUICKSCAN, shell=True)
   
   write_recommendations(quickresults)

   print("[+] Starting detailed TCP/UDP nmap scans for %s" % (ip_address))
   serv_dict = {}


   if dns_server:
       print("[+] Using DNS server %s" % (dns_server))
       TCPSCAN = "nmap -vv -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 --dns-servers %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (dns_server, outputdir, ip_address, outputdir, ip_address, ip_address)
       UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 --dns-servers %s -oN '%s/%sU.nmap' -oX '%s/%sU_nmap_scan_import.xml' %s" % (dns_server, outputdir, ip_address, outputdir, ip_address, ip_address)
   else:
       print("[+] No DNS server was specified. Continuing with a regular scan.")
       TCPSCAN = "nmap -vv -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 -n %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (dns_server, outputdir, ip_address, outputdir, ip_address, ip_address)
       UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -n %s -oN '%s/%sU.nmap' -oX '%s/%sU_nmap_scan_import.xml' %s" % (dns_server, outputdir, ip_address, outputdir, ip_address, ip_address)

   results = subprocess.check_output(TCPSCAN, shell=True)
   udpresults = subprocess.check_output(UDPSCAN, shell=True)

   write_recommendations(results)

   return

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def target_file(target_hosts, output_directory, dns_server, quiet):    
    targets = load_targets(target_hosts, output_directory, quiet)
    target_file = open(targets, 'r')
    print("[*] Loaded targets from: %s" % targets)

    try:
        target_file = open(targets, 'r')
        print("[*] Loaded targets from: %s" % targets)
    except:
        print("[!] Unable to load: %s" % targets)

    for ip_address in target_file:
       ip_address = ip_address.strip()
       create_dir_structure(ip_address, output_directory)

       host_directory = output_directory + "/" + ip_address
       nmap_directory = host_directory + "/nmap"
       
       jobs = []
       p = multiprocessing.Process(target=nmapScan, args=(ip_address, nmap_directory, dns_server))
       jobs.append(p)
       p.start()
    target_file.close() 


def target_ip(target_hosts, output_directory, dns_server, quiet):
    print("[*] Loaded single target: %s" % target_hosts)
    target_hosts = target_hosts.strip()    
    create_dir_structure(target_hosts, output_directory)
    
    host_directory = output_directory + "/" + target_hosts
    nmap_directory = host_directory + "/nmap"
    
    jobs = []
    p = multiprocessing.Process(target=nmapScan, args=(target_hosts, nmap_directory, dns_server))
    jobs.append(p)
    p.start()


def service_scan(target_hosts, output_directory, dns_server, quiet):
    check_directory(output_directory)

    if(valid_ip(target_hosts)):
        target_ip(target_hosts, output_directory, dns_server, quiet)
    else:
        target_file(target_hosts, output_directory, dns_server, quiet)
