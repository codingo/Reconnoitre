import subprocess

from Reconnoitre.lib.file_helper import check_directory


def ping_sweeper(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/targets.txt"

    print("[+] Performing ping sweep over %s" % target_hosts)

    lines = call_nmap_sweep(target_hosts)
    live_hosts = parse_nmap_output_for_live_hosts(lines)
    write_live_hosts_list_to_file(output_file, live_hosts)

    for ip_address in live_hosts:
        print("   [>] Discovered host: %s" % (ip_address))

    print("[*] Found %s live hosts" % (len(live_hosts)))
    print("[*] Created target list %s" % (output_file))


def call_nmap_sweep(target_hosts):
    SWEEP = "nmap -n -sP %s" % (target_hosts)

    results = subprocess.check_output(SWEEP, shell=True)
    lines = str(results).encode("utf-8").split("\n")
    return lines


def parse_nmap_output_for_live_hosts(lines):
    def get_ip_from_nmap_line(line):
        return line.split()[4]

    live_hosts = [get_ip_from_nmap_line(line)
                  for line in lines
                  if "Nmap scan report for" in line]

    return live_hosts


def write_live_hosts_list_to_file(output_file, live_hosts):
    print("[+] Writing discovered targets to: %s" % output_file)
    with open(output_file, 'w') as f:
        f.write("\n".join(live_hosts))
