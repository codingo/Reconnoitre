#!/usr/bin/python
from Reconnoitre.lib.file_helper import FileHelper
from Reconnoitre.lib.subprocess_helper import run_scan
import multiprocessing
import socket


class ServiceScan(object):

    def __init__(
            self,
            target_hosts,
            output_directory,
            dns_server,
            quiet,
            quick,
            no_udp_service_scan):

        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.dns_server = dns_server
        self.quiet = quiet
        self.quick = quick
        self.no_udp_service_scan = no_udp_service_scan
        self.nmap_directory = f"{self.output_directory}/{self.target_hosts}/scans"
        FileHelper.create_dir_structure(target_hosts, self.output_directory)

    @staticmethod
    def valid_ip(address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def target_file(self):
        targets = FileHelper.load_targets(self.target_hosts, self.output_directory, self.quiet)
        FileHelper.check_file(targets)

        try:
            target_file = open(targets, 'r')
            print(f"[*] Loaded targets from: {targets}")
        except FileExistsError as err:
            print(f"[!] Unable to load: {targets}")
            raise err

        for ip_address in target_file:
            ip_address = ip_address.strip()
            FileHelper.create_dir_structure(ip_address, self.output_directory)
            nmap_directory = f"{self.output_directory}/{ip_address}/scans"
            FileHelper.check_directory(output_directory=nmap_directory)
            jobs = []
            p = multiprocessing.Process(target=self.nmap_scan)
            jobs.append(p)
            p.start()
        target_file.close()

    def target_ip(self):
        print(f"[*] Loaded single target: {self.target_hosts}")
        target_hosts = self.target_hosts.strip()
        FileHelper.create_dir_structure(target_hosts, self.output_directory)
        FileHelper.check_directory(output_directory=self.nmap_directory)
        jobs = []
        p = multiprocessing.Process(target=self.nmap_scan)
        jobs.append(p)
        p.start()

    def nmap_scan(self):
        print(f"[+] Starting quick nmap scan for {self.target_hosts}")
        flags = FileHelper.get_config_options('nmap', 'quickscan')
        QUICKSCAN = f"nmap {flags} {self.target_hosts} -oA '{self.nmap_directory}.quick'"
        quickresults = run_scan(QUICKSCAN)
        FileHelper.write_recommendations(quickresults, self.target_hosts, self.output_directory)
        print(f"[*] TCP quick scans completed for {self.target_hosts}")

        if (self.quick):
            return

        if self.dns_server:
            print(f"[+] Starting detailed TCP{('' if self.no_udp_service_scan is True else '/UDP')} nmap scans for {self.target_hosts} using DNS Server {self.dns_server}")
            print("[+] Using DNS server %s" % (self.dns_server))
            flags = FileHelper.get_config_options("nmap", "tcpscan")
            TCPSCAN = f"nmap {flags} --dns-servers {self.dns_server} -oN '{self.nmap_directory}.nmap' -oX '{self.nmap_directory}/scan_import.xml' {self.target_hosts}"

            flags = FileHelper.get_config_options("nmap", "dnsudpscan")
            UDPSCAN = f"nmap {flags} --dns-servers {self.dns_server} -oN '{self.nmap_directory}U.nmap' -oX '{self.nmap_directory}/UDP_scan_import.xml' {self.target_hosts}"

        else:
            print(f"[+] Starting detailed TCP{('' if self.no_udp_service_scan is True else '/UDP')} nmap scans for {self.target_hosts}")
            flags = FileHelper.get_config_options("nmap", "tcpscan")
            TCPSCAN = f"nmap {flags} -oN '{self.nmap_directory}.nmap' -oX '{self.nmap_directory}/scan_import.xml' {self.target_hosts}"

            flags = FileHelper.get_config_options("nmap", "udpscan")
            UDPSCAN = f"nmap {flags} {self.target_hosts} -oA '{self.nmap_directory}-udp'"

        if self.no_udp_service_scan:
            udpresult = ""
        else:
            udpresult = run_scan(UDPSCAN)

        tcpresults = run_scan(TCPSCAN)
        FileHelper.write_recommendations(tcpresults + udpresult, self.target_hosts, self.output_directory)
        print(f"[*] TCP{('' if self.no_udp_service_scan is True else '/UDP')} scans completed for {self.target_hosts}")

    def service_scan(self):
        FileHelper.check_directory(output_directory=self.output_directory)

        if (self.valid_ip(self.target_hosts)):
            self.target_ip()
        else:
            self.target_file()
