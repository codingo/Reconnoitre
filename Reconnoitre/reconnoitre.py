#!/usr/bin/python

import os
import signal
import sys

from Reconnoitre.lib.core.input import CliArgumentParser
from Reconnoitre.lib.find_dns import FindDns
from Reconnoitre.lib.hostname_scan import HostnameScan
from Reconnoitre.lib.ping_sweeper import PingSweeper
from Reconnoitre.lib.service_scan import ServiceScan
from Reconnoitre.lib.snmp_walk import SnmpWalk
from Reconnoitre.lib.virtual_host_scanner import VirtualHostScanner


def print_banner():
    print("  __")
    print(r"|\"\"\"\-=  RECONNOITRE")
    print("(____)      An OSCP scanner by @codingo_\n")


def util_checks(util=None):
    if util is None:
        print("[!] Error hit in chktool: None encountered for util.")
        sys.exit(1)

    pyvers = sys.version_info

    if (pyvers[0] >= 3) and (pyvers[1] >= 3):  # python3.3+
        import shutil
        if shutil.which(util) is None:
            if util == "nmap":
                print(
                    "   [!] nmap was not found on your system."
                    " Exiting since we wont be able to scan anything. "
                    "Please install nmap and try again.")
                sys.exit(1)
            else:
                print(
                    "   [-] %s was not found in your system."
                    " Scan types using this will fail." %
                    util)
                return "Not Found"
        else:
            return "Found"
    else:  # less-than python 3.3
        from distutils import spawn
        if spawn.find_executable(util) is None:
            if util == "nmap":
                print(
                    "   [!] nmap was not found on your system."
                    " Exiting since we wont be able to scan anything. "
                    "Please install nmap and try again.")
                sys.exit(1)
            else:
                print(
                    "   [-] %s was not found in your system."
                    " Scan types using this will fail." %
                    util)
                return "Not Found"
        else:
            return "Found"


def main(arguments):
    dns_servers = ''

    if arguments.output_directory.endswith('/' or '\\'):
        arguments.output_directory = arguments.output_directory[:-1]
    if arguments.target_hosts.endswith('/' or '\\'):
        arguments.target_hosts = arguments.target_hosts[:-1]

    if arguments.quiet is not True:
        print_banner()
        print("[+] Testing for required utilities on your system.")

    # list of utils to check on local system.
    utils = ['nmap', 'snmpwalk', 'nbtscan']
    for util in utils:
        util_checks(util)

    if arguments.ping_sweep is True:
        print("[#] Performing ping sweep")
        scanner = PingSweeper(
            arguments.target_hosts,
            arguments.output_directory,
            arguments.quiet)
        scanner.ping_sweeper()

    if arguments.hostname_scan is True:
        print("[#] Identifying hostnames")
        scanner = HostnameScan(
            arguments.target_hosts,
            arguments.output_directory,
            arguments.quiet)
        scanner.hostname_scan()

    if arguments.find_dns_servers is True:
        print("[#] Identifying DNS Servers")
        scanner = FindDns(
            arguments.target_hosts,
            arguments.output_directory,
            arguments.quiet)
        dns_servers = scanner.find_dns()

    if arguments.perform_service_scan is True:
        print("[#] Performing service scans")
        scanner = ServiceScan(
            arguments.target_hosts,
            arguments.output_directory,
            dns_servers,
            arguments.quiet,
            arguments.quick,
            arguments.no_udp_service_scan)
        scanner.service_scan()

    if arguments.perform_snmp_walk is True:
        print("[#] Performing SNMP walks")
        scanner = SnmpWalk(
            arguments.target_hosts,
            arguments.output_directory,
            arguments.quiet)
        scanner.snmp_walk()

    if arguments.virtualhosts is True:
        print("[#] Performing Virtual host scans")
        if arguments.wordlist is False:
            print("[!] No wordlist was provided,"
                  " skipping virtual host scanning.")
        else:
            scanner = VirtualHostScanner(
                arguments.target_hosts,
                arguments.output_directory,
                arguments.port,
                arguments.ignore_http_codes,
                arguments.ignore_content_length,
                arguments.wordlist)
            scanner.scan()


# Declare signal handler to immediately exit on KeyboardInterrupt
def signal_handler(signal, frame):
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    parser = CliArgumentParser()
    args = parser.parse(sys.argv[1:])
    main(args)
