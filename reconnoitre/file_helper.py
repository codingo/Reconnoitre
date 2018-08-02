import os
import json


def check_directory(output_directory):
    try:
        os.stat(output_directory)
    except:
        os.mkdir(output_directory)
        print("[!] %s didn't exist and has been created." % output_directory)


def load_targets(target_hosts, output_directory, quiet):
    if(os.path.isdir(target_hosts) or os.path.isfile(target_hosts)):
        return target_hosts
    else:
        return output_directory + "/targets.txt"


def create_dir_structure(ident, output_directory):
    print("[+] Creating directory structure for " + ident)

    hostdir = output_directory + "/" + ident 
    try:
        os.stat(hostdir)
    except:
        os.mkdir(hostdir)

    nmapdir = hostdir + "/scans"
    print("   [>] Creating scans directory at: %s" % hostdir)
    try:
        os.stat(nmapdir)
    except:
        os.mkdir(nmapdir)

    exploitdir = hostdir + "/exploit"
    print("   [>] Creating exploit directory at: %s" % exploitdir)
    try:
        os.stat(exploitdir)
    except:
        os.mkdir(exploitdir)

    lootdir = hostdir + "/loot"
    print("   [>] Creating loot directory at: %s" % lootdir)
    try:
        os.stat(lootdir)
    except:
        os.mkdir(lootdir)
    
    prooffile = hostdir + "/proof.txt"
    print("   [>] Creating proof file at: %s" % prooffile)
    open(prooffile, 'a').close()

def write_recommendations(results, ip_address, outputdir, **kwargs):
    if 'ident' in kwargs:
        ident = kwargs['ident']
    else:
        ident = ip_address
    recommendations_file = outputdir + "/" + ident + "_findings.txt"
    serv_dict = {}
    lines = results.split("\n")
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            service = line.split(" ")[2]
            port = line.split(" ")[0]
 
            if service in serv_dict:
                ports = serv_dict[service]
 
            ports.append(port)
            serv_dict[service] = ports
 
    print("[+] Writing findings for %s" % (ident))
 
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    with open(os.path.join(__location__, "config.json"), "r") as config:
        c = config.read()
        j = json.loads(c.replace("$ip", "%(ip)s").replace("$port", "%(port)s").replace("$outputdir", "%(outputdir)s"))
 
    f = open(recommendations_file, 'w')
    for serv in serv_dict:
        ports = serv_dict[serv]
 
        for service in j["services"]:
            if (serv in j["services"][service]["nmap-service-names"]) or (service in serv):
                for port in ports:
                    port = port.split("/")[0]
 
                    description = "[*] " + j["services"][service]["description"]
                    print(description % {"ip": ip_address, "port": port})
                    f.write((description + "\n") % {"ip": ip_address, "port": port})
 
                    for entry in j["services"][service]["output"]:
                        f.write("   [*] " + entry["description"] + "\n")
 
                        for cmd in entry["commands"]:
                           f.write(("      [=] " + cmd + "\n") % {"ip": ip_address, "port": port, "outputdir": outputdir})
 
                    f.write("\n")
 
    f.write("\n\n[*] Always remember to manually go over the portscan report and carefully read between the lines ;)")
    f.close()
