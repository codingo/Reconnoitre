import os
import json


def check_directory(output_directory):
    try:
        os.stat(output_directory)
    except Exception:
        os.mkdir(output_directory)
        print("[!] %s didn't exist and has been created." % output_directory)


def load_targets(target_hosts, output_directory, quiet):
    if (os.path.isdir(target_hosts) or os.path.isfile(target_hosts)):
        return target_hosts
    elif "-" in target_hosts:
        expand_targets(target_hosts, output_directory)
        return output_directory + "/targets.txt"
    else:
        return output_directory + "/targets.txt"


def expand_targets(target_hosts, output_directory):
    parts = target_hosts.split(".")
    target_list = []
    for part in parts:
        if "-" in part:
            iprange = part.split("-")
    for i in range(int(iprange[0]), int(iprange[1])):
        target_list.append(
            parts[0] +
            "." +
            parts[1] +
            "." +
            parts[2] +
            "." +
            str(i))
    with open(output_directory + "/targets.txt", "w") as targets:
        for target in target_list:
            targets.write("%s\n" % target)


def create_dir_structure(ip_address, output_directory):
    print("[+] Creating directory structure for " + ip_address)

    hostdir = output_directory + "/" + ip_address
    try:
        os.stat(hostdir)
    except Exception:
        os.mkdir(hostdir)

    nmapdir = hostdir + "/scans"
    print("   [>] Creating scans directory at: %s" % nmapdir)
    try:
        os.stat(nmapdir)
    except Exception:
        os.mkdir(nmapdir)

    exploitdir = hostdir + "/exploit"
    print("   [>] Creating exploit directory at: %s" % exploitdir)
    try:
        os.stat(exploitdir)
    except Exception:
        os.mkdir(exploitdir)

    lootdir = hostdir + "/loot"
    print("   [>] Creating loot directory at: %s" % lootdir)
    try:
        os.stat(lootdir)
    except Exception:
        os.mkdir(lootdir)

    prooffile = hostdir + "/proof.txt"
    print("   [>] Creating proof file at: %s" % prooffile)
    open(prooffile, 'a').close()


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

    f = open(recommendations_file, 'w')
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
