import subprocess

from Reconnoitre.lib.file_helper import check_directory
from Reconnoitre.lib.file_helper import load_targets


def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    dns_server_list = []
    results = 0
    hostcount = 0
    dnscount = 0

    output_file = open(output_directory + "/DNS-Detailed.txt", 'w')
    output_targets = open(output_directory + "/DNS-targets.txt", 'w')

    targets = load_targets(target_hosts, output_directory, quiet)
    target_file = open(targets, 'r')

    print("[*] Loaded targets from: %s" % targets)
    print("[+] Enumerating TCP port 53 over targets to find dns servers")

    for ip_address in target_file:
        hostcount += 1
        ip_address = ip_address.strip()
        ip_address = ip_address.rstrip()

        print("   [>] Testing %s for DNS" % ip_address)
        DNSSCAN = "nmap -n -sV -Pn -vv -p53 %s" % (ip_address)
        results = subprocess.check_output(DNSSCAN, shell=True).decode("utf-8")
        lines = results.split("\n")

        for line in lines:
            line = line.strip()
            line = line.rstrip()
            if (("53/tcp" in line) and ("open" in line)
                    and ("Discovered" not in line)):
                print(
                    "      [=] Found DNS service running on: %s" %
                    (ip_address))
                output_file.write(
                    "[*] Found DNS service running on: %s\n" %
                    (ip_address))
                output_file.write("   [>] %s\n" % (line))
                output_targets.write("%s\n" % (ip_address))
                dns_server_list.append(ip_address)
                dnscount += 1
    print("[*] Found %s DNS servers within %s hosts" %
          (str(dnscount), str(hostcount)))
    output_file.close()
    output_targets.close()
    return '' if len(dns_server_list) == 0 else ','.join(dns_server_list)
