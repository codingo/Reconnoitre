from lib.utility import Utility

class PingSweeper:

    def __init__(self, target_hosts, output_directory, quiet) -> None:
        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.quiet = quiet
        self.output_file = "{}/targets.txt".format(self.output_directory)
        self.live_hosts = []
        self.nmap_output = None

    def ping_sweeper(self):
        Utility.check_directory(self.output_directory)

        print("[+] Performing ping sweep over %s" % self.target_hosts)

        self.call_nmap_sweep()
        self.parse_nmap_output_for_live_hosts()
        self.write_live_hosts_list_to_file()

        for ip_address in self.live_hosts:
            print("   [>] Discovered host: %s" % (ip_address))

        print("[*] Found %s live hosts" % (len(self.live_hosts)))
        print("[*] Created target list %s" % (self.output_file))


    def call_nmap_sweep(self):
        SWEEP = "nmap -n -sP %s" % (self.target_hosts)
        results = Utility.run_scan(SWEEP)
        self.nmap_output = str(results).split("\n")


    def parse_nmap_output_for_live_hosts(self):
        self.live_hosts = [line.split()[4]
                    for line in self.nmap_output
                    if "Nmap scan report for" in line]


    def write_live_hosts_list_to_file(self):
        print("[+] Writing discovered targets to: %s" % self.output_file)
        with open(self.output_file, 'w') as f:
            f.write("\n".join(self.live_hosts))
