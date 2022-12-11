import multiprocessing
import subprocess
from lib.utility import Utility

class SnmpWalk:

    def __init__(self, target_hosts, output_directory, quiet):
        self.target_hosts = target_hosts
        self.output_directory = output_directory
        self.quiet = quiet

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
            jobs = []
            p = multiprocessing.Process(target=self.snmp_scans, args=(ip_address))
            jobs.append(p)
            p.start()
        target_file.close()


    def target_ip(self, ip_address):
        print("[*] Loaded single target: %s" % self.target_hosts)
        target_hosts = target_hosts.strip()

        snmp_directory = self.output_directory + '/' + target_hosts + '/scans/snmp/'
        Utility.check_directory(snmp_directory)

        jobs = []
        p = multiprocessing.Process(
            target=self.snmp_scans, args=(ip_address))
        jobs.append(p)
        p.start()


    def snmp_walk(self):
        Utility.check_directory(self.output_directory)

        if (Utility.valid_ip(self.target_hosts)):
            self.target_ip(self.target_hosts)
        else:
            self.target_file()


    def snmp_scans(self, ip_address):
        ipDir = self.output_directory+'/'+ip_address+'/scans/snmp'
        print("[+] Performing SNMP scans for %s to %s" %
            (ip_address, ipDir))
        print(
            "   [>] Performing snmpwalk on public tree for:"
            " %s - Checking for System Processes" %
            (ip_address))
        SCAN = ("snmpwalk -c public -v1 %s "
                "1.3.6.1.2.1.25.1.6.0 > '%s%s-systemprocesses.txt'" % (
                    ip_address, ipDir, ip_address))

        try:
            Utility.run_scan(SCAN, stderr=subprocess.STDOUT)
        except Exception:
            print("[+] No Response from %s" % ip_address)
        except subprocess.CalledProcessError:
            print("[+] Subprocess failure during scan of %s" % self.target_hosts)

        print("[+] Completed SNMP scans for %s" % (ip_address))
