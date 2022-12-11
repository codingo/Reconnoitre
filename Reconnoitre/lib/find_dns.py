from lib.utility import Utility

class FindDNS:
    def __init__(self, target_hosts, output_directory, quiet) -> None:
        # Function args
        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.quiet = quiet
        # Algorithm setup
        self.output_file = "{}/DNS-Detailed.txt".format(self.output_directory)
        self.output_targets = "{}/DNS-targets.txt".format(self.output_directory)
        self.dns_server_list = []
        self.results = 0
        self.hostcount = 0
        self.dnscount = 0
        
    def find_dns(self):
        Utility.check_directory(self.output_directory)

        output_file = open(self.output_directory + "/DNS-Detailed.txt", 'w')
        output_targets = open(self.output_directory + "/DNS-targets.txt", 'w')

        targets = Utility.load_targets(self.target_hosts, self.output_directory, self.quiet)
        target_file = open(targets, 'r')

        print("[*] Loaded targets from: %s" % targets)
        print("[+] Enumerating TCP port 53 over targets to find dns servers")

        for ip_address in target_file:
            self.hostcount += 1
            ip_address = ip_address.strip()
            ip_address = ip_address.rstrip()

            print("   [>] Testing %s for DNS" % ip_address)
            DNSSCAN = "nmap -n -sV -Pn -vv -p53 %s" % (ip_address)
            results = Utility.run_scan(DNSSCAN)
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
                    self.dns_server_list.append(ip_address)
                    self.dnscount += 1
        print("[*] Found %s DNS servers within %s hosts" %
            (str(self.dnscount), str(self.hostcount)))
        output_file.close()
        output_targets.close()
        return '' if len(self.dns_server_list) == 0 else ','.join(self.dns_server_list)
