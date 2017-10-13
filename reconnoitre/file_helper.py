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

    nmapdir = hostdir + "/scans"
    print("   [>] Creating scans directory at: %s" % nmapdir)
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


def write_recommendations(results, ip_address, outputdir):
   recommendations_file = outputdir + "/" + ip_address + "_findings.txt"
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

   print("[+] Writing findings for %s" % (ip_address))
   f = open(recommendations_file, 'w')
   for serv in serv_dict:
       ports = serv_dict[serv]
       if ("ftp" in serv):
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found FTP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found FTP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts for further enumeration or hydra for password attack, e.g\n")
               f.write("      [=] nmap -sV -Pn -vv -p%s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '%s/%s_ftp.nmap' -oX '%s/%s_ftp_nmap_scan_import.xml' %s\n" % (port, outputdir, ip_address, outputdir, ip_address, ip_address))
               f.write("      [=] hydra -L User List -P Pass List -f -o %s/%s_ftphydra.txt -u %s -s %s ftp\n" % (outputdir, ip_address, ip_address, port))
       elif (serv == "http") or (serv == "ssl/http") or ("https" in serv) or ("http" in serv):
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found HTTP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found HTTP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nikto & dirb / dirbuster for service enumeration, e.g\n")
               f.write("      [=] nikto -h %s -p %s > %s/%s_nikto.txt\n" % (ip_address, port, outputdir, ip_address))
               f.write("      [=] dirb http://%s:%s/ -o %s/%s_dirb.txt\n" % (ip_address, port, outputdir, ip_address))
               f.write("      [=] gobuster -w /usr/share/wordlists/SecLists/Discovery/Web_Content/common.txt -u http://%s:%s/ -s '200,204,301,302,307,403,500' -e > '%s/%s_gobuster_common.txt' -t 50 \n" % (ip_address, port, outputdir, ip_address))
               f.write("      [=] gobuster -w /usr/share/wordlists/SecLists/Discovery/Web_Content/cgis.txt -u http://%s:%s/ -s '200,204,301,307,403,500' -e > '%s/%s_gobuster_cgis.txt' -t 50 \n" % (ip_address, port, outputdir, ip_address))
               f.write("   [>] Use curl and W3M (apt install w3m) to retreive web headers and find host information, e.g\n")
               f.write("      [=] curl -i %s\n" % (ip_address))
               f.write("      [=] w3m -dump %s/robots.txt  > '%s/%s_robots.txt'\n" % (ip_address, outputdir, ip_address))
       elif "mysql" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found mysql service on %s:%s\n" % (ip_address, port))
               print("   [>] Found mysql service on %s:%s" % (ip_address, port))
               f.write("   [>] Check out the server for web applications with sqli vulnerabilities\n")
       elif "telnet" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found telnet service on %s:%s\n" % (ip_address, port))
               print("   [>] Found telnet service on %s:%s" % (ip_address, port))
               f.write("   [>] Check out the server headers to enumerate further\n")
               f.write("      [=] nc -nv %s %s\n" % (ip_address, port))
       elif "microsoft-ds" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found MS SMB service on %s:%s\n" % (ip_address, port))
               print("   [>] Found MS SMB service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts or enum4linux for further enumeration, e.g\n")
               f.write("      [=] nmap -sV -Pn -vv -p 139,%s --script=smb-vuln* --script-args=unsafe=1 -oN '%s/%s_smb.nmap' -oX '%s/%s_smb_nmap_scan_import.xml' %s\n" % (port, outputdir, ip_address, outputdir, ip_address, ip_address))
               f.write("      [=] enum4linux %s > '%s/%s_enum4linux.txt'\n" % (ip_address, outputdir, ip_address))
               f.write("      [=] nmap -sV -Pn -vv -p %s --script=smb-enum-users -oN '%s/%s_smb_smb-enum-users.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
       elif "ms-sql" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found MS SQL service on %s:%s\n" % (ip_address, port))
               print("   [>] Found MS SQL service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts for further enumeration, e.g\n")
               f.write("      [=] nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=%s,smsql.username-sa,mssql.password-sa -oX '%s/%s_mssql_nmap_scan_import.xml' %s" % (port, port, outputdir, ip_address, ip_address))
       elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found RDP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found RDP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use ncrackpassword cracking, e.g\n")
               f.write("      [=] ncrack -vv --user administrator -P rockyou.txt rdp://%s\n" % (ip_address))
       elif "smtp" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SMTP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SMTP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use smtp-user-enum to find users, e.g\n")
               f.write("      [=] smtp-user-enum -M VRFY -U SecLists/Usernames/Names/top_shortlist.txt -t %s -p %s\n" % (ip_address, port))
       elif "snmp" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SNMP service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SNMP service on %s:%s" % (ip_address, port))
               f.write("   [>] Use nmap scripts, onesixtyone or snmwalk for further enumeration, e.g\n")
               f.write("      [=] nmap -sV -Pn -vv -p%s --script=snmp-netstat,snmp-processes -oN '%s/%s_snmp.nmap' -oX '%s/%s_snmp_nmap_scan_import.xml' %s\n" % (port, outputdir, ip_address, outputdir, ip_address, ip_address))
               f.write("      [=] onesixtyone %s\n" % (ip_address))
               f.write("      [=] snmpwalk -c public -v1 %s > '%s/%s_snmpwalk.txt'\n" % (ip_address, outputdir, ip_address))
       elif "ssh" in serv:
           for port in ports:
               port = port.split("/")[0]
               f.write("[*] Found SSH service on %s:%s\n" % (ip_address, port))
               print("   [>] Found SSH service on %s:%s" % (ip_address, port))
               f.write("   [>] Use medusa or hydra (unreliable) for password cracking, e.g\n")
               f.write("      [=] medusa -u root -P rockyou.txt -e ns -h %s - %s -M ssh\n" % (ip_address, port))
               f.write("      [=] hydra -f -V -t 1 -l root -P rockyou.txt -s %s %s ssh\n" % (port, ip_address))
               f.write("   [>] Use nmap to automate banner grabbing and key fingerprints, e.g.\n")
               f.write("      [=] nmap %s -p %s -sV --script=ssh-hostkey -oN '%s/%s_ssh-hostkey.nmap' \n" % (ip_address, port, outputdir, ip_address))

   f.close()
