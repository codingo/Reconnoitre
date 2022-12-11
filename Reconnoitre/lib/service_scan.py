import multiprocessing

from lib.utility import Utility

class ServiceScan:

    def __init__(self, target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan):
        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.dns_server = dns_server
        self.quiet = quiet
        self.quick = quick 
        self.no_udp_service_scan = no_udp_service_scan
        Utility.create_dir_structure(self.target_hosts, self.output_directory)

    def nmap_scan(self, ip_address):
        print("[+] Starting quick nmap scan for %s" % (self.target_hosts))
        flags = Utility.get_config_options('nmap', 'quickscan')
        hostDirectory = self.output_directory+"/"+ip_address
        scanDirectory = hostDirectory + "/scans"
        QUICKSCAN = f"nmap {flags} {ip_address} -oA '{scanDirectory}/{ip_address}.quick'"
        quickresults = Utility.run_scan(QUICKSCAN)
        Utility.write_recommendations(quickresults, ip_address, scanDirectory)
        print("[*] TCP quick scans completed for %s" % self.target_hosts)

        if (self.quick):
            return

        if self.dns_server:
            print(
                "[+] Starting detailed TCP%s nmap scans for "
                "%s using DNS Server %s" %
                (("" if self.no_udp_service_scan is True else "/UDP"),
                ip_address,
                self.dns_server))
            print("[+] Using DNS server %s" % (self.dns_server))
            flags = Utility.get_config_options("nmap", "tcpscan")
            TCPSCAN = f"nmap {flags} --dns-servers {self.dns_server} -oN\
            '{scanDirectory}/{ip_address}.nmap' -oX\
            '{scanDirectory}/{ip_address}_nmap_scan_import.xml' {ip_address}"

            flags = Utility.get_config_options("nmap", "dnsudpscan")
            UDPSCAN = f"nmap {flags} \
            --dns-servers {self.dns_server} -oN '{scanDirectory}/{ip_address}U.nmap' \
            -oX '{scanDirectory}/{ip_address}U_nmap_scan_import.xml' {ip_address}"

        else:
            print("[+] Starting detailed TCP%s nmap scans for %s" % (
                ("" if self.no_udp_service_scan is True else "/UDP"), ip_address))
            flags = Utility.get_config_options("nmap", "tcpscan")
            TCPSCAN = f"nmap {flags} -oN\
            '{scanDirectory}/{ip_address}.nmap' -oX\
            '{scanDirectory}/{ip_address}_nmap_scan_import.xml' {ip_address}"

            flags = Utility.get_config_options("nmap", "udpscan")
            UDPSCAN = f"nmap {flags} {ip_address} -oA '{scanDirectory}/{ip_address}-udp'"

        udpresult = "" if self.no_udp_service_scan is True else Utility.run_scan(UDPSCAN)
        tcpresults = Utility.run_scan(TCPSCAN)

        Utility.write_recommendations(tcpresults + udpresult, ip_address, scanDirectory)
        print("[*] TCP%s scans completed for %s" %
            (("" if self.no_udp_service_scan is True else "/UDP"), ip_address))

    def target_file(self):
        targets = Utility.load_targets(self.target_hosts, self.output_directory, self.quiet)
        target_file = open(targets, 'r')
        try:
            target_file = open(targets, 'r')
            print("[*] Loaded targets from: %s" % targets)
        except Exception:
            print("[!] Unable to load: %s" % targets)

        for ip_address in target_file:
            ip_address = ip_address.strip()
            Utility.create_dir_structure(ip_address, self.output_directory)
            jobs = []
            p = multiprocessing.Process(target=self.nmap_scan, args=[ip_address])
            jobs.append(p)
            p.start()
        target_file.close()


    def target_ip(self, ip_address):
        print("[*] Loaded single target: %s" % ip_address)
        target_hosts = ip_address.strip()
        Utility.create_dir_structure(target_hosts, self.output_directory)

        jobs = []
        p = multiprocessing.Process(target=self.nmap_scan, args=[ip_address])
        jobs.append(p)
        p.start()


    def service_scan(self):
        Utility.check_directory(self.output_directory)

        if (Utility.valid_ip(self.target_hosts)):
            self.target_ip(self.target_hosts)
        else:
            self.target_file()
