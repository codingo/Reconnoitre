#!/usr/bin/python


import sys
from argparse import ArgumentParser
from ping_sweeper import ping_sweeper
from find_dns import find_dns
from service_scan import service_scan
from hostname_scan import hostname_scan
from snmp_walk import snmp_walk
from virtual_host_scanner import virtual_host_scanner


def print_banner():
    print("  __")
    print("|\"\"\"\-=  RECONNOITRE")
    print("(____)      An OSCP scanner by @codingo_\n")

def util_checks(util = None):
    if util is None:
        print("[!] Error hit in chktool: None encountered for util.")
        sys.exit(1)

    pyvers = sys.version_info

    if (pyvers[0] >= 3) and (pyvers[1] >= 3): # python3.3+
        import shutil
        if shutil.which(util) is None:
            if util is "nmap":
                print("   [!] nmap was not found on your system. Exiting since we wont be able to scan anything. Please install nmap and try again.")
                sys.exit(1)
            else:
                print("   [-] %s was not found in your system. Scan types using this will fail." % util)
                return "Not Found"
        else:
            return "Found"
    else: # less-than python 3.3
        from distutils import spawn
        if spawn.find_executable(util) is None:
            if util is "nmap":
                print("   [!] nmap was not found on your system. Exiting since we wont be able to scan anything. Please install nmap and try again.")
                sys.exit(1)
            else:
                print("   [-] %s was not found in your system. Scan types using this will fail." % util)
                return "Not Found"
        else:
            return "Found"

def main():
    parser = ArgumentParser()
    parser.add_argument("-t",               dest="target_hosts", required=True, help="Set a target range of addresses to target. Ex 10.11.1.1-255" )
    parser.add_argument("-o",               dest="output_directory", required=True, help="Set the output directory. Ex /root/Documents/labs/")
    parser.add_argument("-w",               dest="wordlist", required=False, help="Set the wordlist to use for generated commands. Ex /usr/share/wordlist.txt", default=False)
    parser.add_argument("-p",               dest="port", required=False, help="Set the port to use. Leave blank to use discovered ports. Useful to force virtual host scanning on non-standard webserver ports.", default=80)
    parser.add_argument("--pingsweep",      dest="ping_sweep", action="store_true", help="Write a new target.txt by performing a ping sweep and discovering live hosts.", default=False)
    parser.add_argument("--dns",            dest="find_dns_servers", action="store_true", help="Find DNS servers from a list of targets.", default=False)
    parser.add_argument("--services",       dest="perform_service_scan", action="store_true", help="Perform service scan over targets.", default=False)
    parser.add_argument("--hostnames",      dest="hostname_scan", action="store_true", help="Attempt to discover target hostnames and write to 0-name.txt and hostnames.txt.", default=False)
    parser.add_argument("--snmp",           dest="perform_snmp_walk", action="store_true", help="Perform service scan over targets.", default=False)
    parser.add_argument("--quick",          dest="quick",   action="store_true", required=False, help="Move to the next target after performing a quick scan and writing first-round recommendations.", default=False)    

    parser.add_argument("--virtualhosts",   dest="virtualhosts",   action="store_true", required=False, help="Attempt to discover virtual hosts  using the specified wordlist.", default=False)  
    parser.add_argument('--ignore-http-codes', dest='ignore_http_codes', type=str, help='Comma separated list of http codes to ignore with virtual host scans.', default='404')
    parser.add_argument('--ignore-content-length', dest='ignore_content_length', type=int, help='Ignore content lengths of specificed amount. This may become useful when a server returns a static page on every virtual host guess.', default=0)

    parser.add_argument("--quiet",          dest="quiet",   action="store_true", help="Supress banner and headers to limit to comma dilimeted results only.", default=False)
    parser.add_argument("--exec",           dest="follow",  action="store_true", help="Execute shell comamnds from recommendations as they are discovered. Likely to lead to very long execute times depending on the wordlist being used.", default=False)
    parser.add_argument("--simple_exec",    dest="quickfollow",  action="store_true", help="Execute non-brute forcing shell comamnds only as they are discovered.", default=False)
    parser.add_argument("--no-udp",    dest="no_udp_service_scan",  action="store_true", help="Disable UDP services scan over targets.", default=False)
    arguments = parser.parse_args()

    if len(sys.argv) == 1:
        print_banner()
        parser.error("No arguments given.")
        parser.print_usage
        sys.exit()

    if arguments.output_directory.endswith('/' or '\\'):
        arguments.output_directory = arguments.output_directory[:-1]
    if arguments.target_hosts.endswith('/' or '\\'):
        arguments.target_hosts = arguments.target_hosts[:-1]

    if arguments.quiet is not True:
        print_banner()
        print("[+] Testing for required utilities on your system.")

    utils = ['nmap', 'snmpwalk', 'nbtscan'] # list of utils to check on local system.
    for util in utils:
        util_checks(util)

    if arguments.ping_sweep is True:
        print("[#] Performing ping sweep")
        ping_sweeper(arguments.target_hosts, arguments.output_directory, arguments.quiet)
        
    if arguments.hostname_scan is True:
        print("[#] Identifying hostnames")
        hostname_scan(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.find_dns_servers is True:
        print("[#] Identifying DNS Servers")
        find_dns(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.perform_service_scan is True:
        print("[#] Performing service scans")
        if arguments.find_dns_servers is True:
            service_scan(arguments.target_hosts, arguments.output_directory, arguments.find_dns_servers, arguments.quiet, arguments.quick, arguments.no_udp_service_scan)
        else:
            service_scan(arguments.target_hosts, arguments.output_directory, '', arguments.quiet, arguments.quick, arguments.no_udp_service_scan)

    if arguments.perform_snmp_walk is True:
        print("[#] Performing SNMP walks")
        snmp_walk(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.virtualhosts is True:
        print("[#] Performing Virtual host scans")
        if arguments.wordlist is False:
            print("[!] No wordlist was provided, skipping virtual host scanning.")
        else:
            scanner = virtual_host_scanner(arguments.target_hosts, arguments.output_directory, arguments.port, arguments.ignore_http_codes, arguments.ignore_content_length, arguments.wordlist)
            scanner.scan()


if __name__ == "__main__":
    main()
