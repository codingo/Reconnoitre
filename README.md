![Reconnnoitre](https://github.com/codingo/Reconnoitre/blob/master/tank-152362_640.png)
A reconnaissance tool made for the OSCP labs to automate information gathering and service enumeration whilst creating a directory structure to store  results, findings and exploits used for each host, recommended commands to execute and directory structures for storing loot and flags.

Contributions are more than welcome!

[![Python 3.2|3.6](https://img.shields.io/badge/python-3.2|3.6-green.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPL3-_red.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html) [![Build Status](https://travis-ci.org/codingo/Reconnoitre.svg?branch=master)](https://travis-ci.org/codingo/Reconnoitre) [![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

# Credit

This tool is based heavily upon the work made public in Mike Czumak's (T_v3rn1x) OSCP review ([link](https://www.securitysift.com/offsec-pwb-oscp/)) along with considerable influence and code taken from Re4son's mix-recon ([link](https://whitedome.com.au/re4son/category/re4son/oscpnotes/)). Virtual host scanning is originally adapted from teknogeek's work which is heavily influenced by jobertabma's virtual host discovery script ([link](https://github.com/jobertabma/virtual-host-discovery)). Further Virtual Host scanning code has been adapted from a project by Tim Kent and I, available here ([link](https://github.com/codingo/VHostScan)).

# Usage

This tool can be used and copied for personal use freely however attribution and credit should be offered to Mike Czumak who originally started the process of automating this work.

| Argument        | Description |
| ------------- |:-------------|
| -h, --help | Display help message and exit |
| -t TARGET_HOSTS | Set either a target range of addresses or a single host to target. May also be a file containing hosts. |
| -o OUTPUT_DIRECTORY | Set the target directory where results should be written. |
| -n NAMED_HOST | Set a target address and name for directory structure output and reporting. Ex 10.11.1.15 -n examplebox creates /examplebox. Does not work with target file or IP address ranges. |
| -w WORDLIST | Optionally specify your own wordlist to use for pre-compiled commands, or executed attacks. |
| --dns DNS_SERVER | Optionally specify a DNS server to use with a service scan. |
| --pingsweep | Write a new target.txt file in the OUTPUT_DIRECTORY by performing a ping sweep and discovering live hosts. |
| --dnssweep | Find DNS servers from the list of target(s). |
| --snmp | Find hosts responding to SNMP requests from the list of target(s). |
| --services | Perform a service scan over the target(s) and write recommendations for further commands to execute. |
| --hostnames | Attempt to discover target hostnames and write to hostnames.txt. |
| --virtualhosts | Attempt to discover virtual hosts using the specified wordlist. This can be expended via discovered hostnames. |
| --ignore-http-codes | Comma separated list of http codes to ignore with virtual host scans. |
| --ignore-content-length | Ignore content lengths of specificed amount. This may become useful when a server returns a static page on every virtual host guess. |
| --quiet | Supress banner and headers and limit feedback to grepable results. |
| --exec | Execute shell commands from recommendations as they are discovered. Likely to lead to very long execution times depending on the wordlist being used and discovered vectors. |
| --simple_exec | Execute non-brute forcing shell comamnds only commands as they are discovered. Likely to lead to very long execution times depending on the wordlist being used and discovered vectors. |
| --quick | Move to the next target after performing a quick scan and writing first-round recommendations. |
| --no-udp | Disable UDP service scanning, which is ON by default. |

## Usage Examples
_Note that these are some examples to give you insight into potential use cases for this tool. Command lines can be added or removed based on what you wish to accomplish with your scan._

### Scan a single host, create a file structure and discover services
```
python ./reconnoitre.py -t 192.168.1.5 -o /root/Documents/labs/ --services
```

An example output would look like:

```
root@kali:~/Documents/tools/reconnoitre/reconnoitre# python ./reconnoitre.py -t 192.168.1.5 --services -o /root/Documents/labs/
  __
|"""\-=  RECONNOITRE
(____)      An OSCP scanner

[#] Performing service scans
[*] Loaded single target: 192.168.1.5
[+] Creating directory structure for 192.168.1.5
   [>] Creating scans directory at: /root/Documents/labs/192.168.1.5/scans
   [>] Creating exploit directory at: /root/Documents/labs/192.168.1.5/exploit
   [>] Creating loot directory at: /root/Documents/labs/192.168.1.5/loot
   [>] Creating proof file at: /root/Documents/labs/192.168.1.5/proof.txt
[+] Starting quick nmap scan for 192.168.1.5
[+] Writing findings for 192.168.1.5
   [>] Found HTTP service on 192.168.1.5:80
   [>] Found MS SMB service on 192.168.1.5:445
   [>] Found RDP service on 192.168.1.5:3389
[*] TCP quick scan completed for 192.168.1.5
[+] Starting detailed TCP/UDP nmap scans for 192.168.1.5
[+] Writing findings for 192.168.1.5
   [>] Found MS SMB service on 192.168.1.5:445
   [>] Found RDP service on 192.168.1.5:3389
   [>] Found HTTP service on 192.168.1.5:80
[*] TCP/UDP Nmap scans completed for 192.168.1.5
```
Which would also write the following recommendations file in the scans folder for each target:
```
[*] Found HTTP service on 192.168.1.50:80
   [>] Use nikto & dirb / dirbuster for service enumeration, e.g
      [=] nikto -h 192.168.1.50 -p 80 > /root/Documents/labs/192.168.1.50/scans/192.168.1.50_nikto.txt
      [=] dirb http://192.168.1.50:80/ -o /root/Documents/labs/192.168.1.50/scans/192.168.1.50_dirb.txt -r -S -x ./dirb-extensions/php.ext
      [=] java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar -H -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -r /root/Documents/labs/192.168.1.50/scans/192.168.1.50_dirbuster.txt -u http://192.168.1.50:80/
      [=] gobuster -w /usr/share/seclists/Discovery/Web_Content/common.txt -u http://192.168.1.50:80/ -s '200,204,301,302,307,403,500' -e > /root/Documents/labs/192.168.1.50/scans/192.168.1.50_gobuster_common.txt -t 50 
      [=] gobuster -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -u http://192.168.1.50:80/ -s '200,204,301,307,403,500' -e > /root/Documents/labs/192.168.1.50/scans/192.168.1.50_gobuster_cgis.txt -t 50 
   [>] Use curl to retreive web headers and find host information, e.g
      [=] curl -i 192.168.1.50
      [=] curl -i 192.168.1.50/robots.txt -s | html2text
[*] Found MS SMB service on 192.168.1.5:445
   [>] Use nmap scripts or enum4linux for further enumeration, e.g
      [=] nmap -sV -Pn -vv -p445 --script="smb-* -oN '/root/Documents/labs/192.168.1.5/nmap/192.168.1.5_smb.nmap' -oX '/root/Documents/labs/192.168.1.5/scans/192.168.1.5_smb_nmap_scan_import.xml' 192.168.1.5
      [=] enum4linux 192.168.1.5
[*] Found RDP service on 192.168.1.5:3389
   [>] Use ncrackpassword cracking, e.g
      [=] ncrack -vv --user administrator -P /root/rockyou.txt rdp://192.168.1.5
```
### Discover live hosts and hostnames within a range
```
python ./reconnoitre.py -t 192.168.1.1-252 -o /root/Documents/testing/ --pingsweep --hostnames
```

### Discover live hosts within a range and then do a quick probe for services
```
python ./reconnoitre.py -t 192.168.1.1-252 -o /root/Documents/testing/ --pingsweep --services --quick
```
This will scan all services within a target range to create a file structure of live hosts as well as write recommendations for other commands to be executed based on the services discovered on these machines. Removing --quick will do a further probe but will greatly lengthen execution times.

### Discover live hosts within a range and then do probe all ports (UDP and TCP) for services
```
python ./reconnoitre.py -t 192.168.1.1-252 -o /root/Documents/testing/ --pingsweep --services
```

# Requirements

This bare requirement for host and service scanning for this tool is to have both `nbtscan` and `nmap` installed. If you are not using host scanning and only wish to perform a ping sweep and service scan you can get away with only installing `nmap`. The outputted _findings.txt_ will often recommend additional tools which you may not have available in your distribution if not using Kali Linux. All requirements and recommendations are native to Kali Linux which is the recommended (although not required) distribution for using this tool.

In addition to these requirements outputs will often refer to Wordlists that you may need to find. If you are undertaking OSCP these can be found in the "List of Recommended Tools" thread by g0tmilk. If not then you can find the majority of these online or already within a Kali Linux installation.
