#!/usr/bin/python
import os
import json


class FileHelper(object):

    @staticmethod
    def check_directory(output_directory):
        try:
            assert (os.path.exists(output_directory) and os.path.isdir(output_directory))
        except AssertionError:
            print(f"[!] Output directory {output_directory} does not exist. Creating it.")
            FileHelper.make_directory(output_directory)
        finally:
            return output_directory

    @staticmethod
    def make_directory(output_directory):
        try:
            os.mkdir(output_directory)
        except FileExistsError as err:
            print(f"[!] Directory {output_directory} already exists.")
            raise err

    @staticmethod
    def check_file(file):
        try:
            assert (os.path.exists(file) and os.path.isfile(file))
        except AssertionError:
            print(f"[!] File {file} does not exist. Creating it.")
            FileHelper.make_file(file)
        finally:
            return file

    @staticmethod
    def make_file(file):
        try:
            with open(file, "w") as f:
                print(f"[+] Created new file {f.name}")
        except FileExistsError as err:
            print(f"[!] File {file} already exists.")
            raise err

    @staticmethod
    def load_targets(target_hosts, output_directory, quiet):
        if (os.path.isdir(target_hosts) or os.path.isfile(target_hosts)):
            return target_hosts
        elif "-" in target_hosts:
            FileHelper.expand_targets(target_hosts, output_directory)
            return output_directory + "/targets.txt"
        else:
            return output_directory + "/targets.txt"

    @staticmethod
    def expand_targets(target_hosts, output_directory):
        iprange = None
        target_list = []
        if "-" not in target_hosts:
            return

        try:
            parts = target_hosts.split(".")
            for part in parts:
                if "-" in part:
                    iprange = part.split("-")
        except FileHelperException as err:
            raise err
        else:
            for i in range(int(iprange[0]), int(iprange[1])):
                target_list.append(
                    parts[0] +
                    "." +
                    parts[1] +
                    "." +
                    parts[2] +
                    "." +
                    str(i))
        target_list = []
        with open(output_directory + "/targets.txt", "w") as targets:
            for target in target_list:
                targets.write("%s\n" % target)

    @staticmethod
    def create_dir_structure(ip_address, output_directory):
        print("[+] Creating directory structure for " + ip_address)

        hostdir = output_directory + "/" + ip_address
        try:
            os.stat(hostdir)
        except OSError:
            os.mkdir(hostdir)

        nmapdir = hostdir + "/scans"
        print("   [>] Creating scans directory at: %s" % nmapdir)
        try:
            os.stat(nmapdir)
        except OSError:
            os.mkdir(nmapdir)

        exploitdir = hostdir + "/exploit"
        print("   [>] Creating exploit directory at: %s" % exploitdir)
        try:
            os.stat(exploitdir)
        except OSError:
            os.mkdir(exploitdir)

        lootdir = hostdir + "/loot"
        print("   [>] Creating loot directory at: %s" % lootdir)
        try:
            os.stat(lootdir)
        except OSError:
            os.mkdir(lootdir)

        prooffile = hostdir + "/proof.txt"
        print("   [>] Creating proof file at: %s" % prooffile)
        open(prooffile, "a").close()

    @staticmethod
    def write_recommendations(results, ip_address, outputdir):
        recommendations_file = outputdir + "/" + ip_address + "_findings.txt"
        serv_dict = {}
        lines = results.split("\n")
        for line in lines:
            ports = []
            line = line.strip()
            if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
                while "  " in line:
                    line = line.replace("  ", " ")
                service = line.split(" ")[2]
                port = line.split(" ")[0]

                if service in serv_dict:
                    ports = serv_dict[service]

                ports.append(port)
                serv_dict[service] = ports

        print("[+] Writing findings for %s" % (ip_address))

        __location__ = os.path.realpath(
            os.path.join(
                os.getcwd(),
                os.path.dirname(__file__)))
        with open(os.path.join(__location__, "config.json"), "r") as config:
            c = config.read()
            j = json.loads(
                c.replace(
                    "$ip",
                    "%(ip)s").replace(
                    "$port",
                    "%(port)s").replace(
                    "$outputdir",
                    "%(outputdir)s"))

        f = open(recommendations_file, "w")
        for serv in serv_dict:
            ports = serv_dict[serv]

            for service in j["services"]:
                if (serv in j["services"][service]
                        ["nmap-service-names"]) or (service in serv):
                    for port in ports:
                        port = port.split("/")[0]

                        description = ("[*] "
                                       + j["services"][service]["description"])
                        print(description % {"ip": ip_address, "port": port})
                        f.write((description + "\n") %
                                {"ip": ip_address, "port": port})

                        for entry in j["services"][service]["output"]:
                            f.write("   [*] " + entry["description"] + "\n")

                            for cmd in entry["commands"]:
                                f.write(("      [=] " + cmd + "\n") %
                                        {"ip": ip_address,
                                         "port": port,
                                         "outputdir": outputdir})

                        f.write("\n")

        f.write(
            "\n\n[*] Always remember to manually go over the"
            " portscan report and carefully read between the lines ;)")
        f.close()

    @staticmethod
    def get_config_options(key, *args):
        __location__ = os.path.realpath(
            os.path.join(
                os.getcwd(),
                os.path.dirname(__file__)))
        with open(os.path.join(__location__, "config.json"), "r") as config:
            c = config.read()
            j = json.loads(
                c.replace(
                    "$ip",
                    "%(ip)s").replace(
                    "$port",
                    "%(port)s").replace(
                    "$outputdir",
                    "%(outputdir)s"))

            res = j.get(key, None)
            for arg in args:
                res = res.get(arg, None)
                if res is None:
                    raise KeyError

            return res


class FileHelperException(Exception):
    pass
