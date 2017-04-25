import os


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

def create_dir_structure(ip_address, output_directory):
    print("[+] Creating directory structure for " + ip_address)

    hostdir = output_directory + "/" + ip_address
    try:
        os.stat(hostdir)
    except:
        os.mkdir(hostdir)

    nmapdir = hostdir + "/nmap"
    print("[>] Creating nmap directory at: %s" % nmapdir)
    try:
        os.stat(nmapdir)
    except:
        os.mkdir(nmapdir)

    exploitdir = hostdir + "/exploit"
    print("[>] Creating exploit directory at: %s" % exploitdir)
    try:
        os.stat(exploitdir)
    except:
        os.mkdir(exploitdir)

    lootdir = hostdir + "/loot"
    print("[>] Creating loot directory at: %s" % lootdir)
    try:
        os.stat(lootdir)
    except:
        os.mkdir(lootdir)

    prooffile = hostdir + "/proof.txt"
    print("[>] Creating proof file at: %s" % prooffile)
    open(prooffile, 'a').close()

    namefile = hostdir + "/0-name"
    open(namefile, 'a').close()