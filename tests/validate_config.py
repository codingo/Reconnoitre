#!/usr/bin/python
import sys
from argparse import ArgumentParser
import json

CONFIG = '../reconnoitre/config.json'
SOURCEFILE = './sample.nmap'
OUTPUTFILE = './recommendations.txt'

def main():
    parser = ArgumentParser()
    parser.add_argument("-t",           dest="target_hosts", required=True, help="Set a target range of addresses to target. Ex 10.11.1.1-255" )
    parser.add_argument("-o",           dest="output_directory", required=True, help="Set the output directory. Ex /root/Documents/labs/")
    parser.add_argument("-w",           dest="wordlist", required=False, help="Set the wordlist to use for generated commands. Ex /usr/share/wordlist.txt")
    parser.add_argument("--pingsweep",  dest="ping_sweep", action="store_true", help="Write a new target.txt by performing a ping sweep and discovering live hosts.", default=False)
    parser.add_argument("--dns",        dest="find_dns_servers", action="store_true", help="Find DNS servers from a list of targets.", default=False)
    parser.add_argument("--services",   dest="perform_service_scan", action="store_true", help="Perform service scan over targets.", default=False)
    parser.add_argument("--hostnames",  dest="hostname_scan", action="store_true", help="Attempt to discover target hostnames and write to 0-name.txt and hostnames.txt.", default=False)
    parser.add_argument("--snmp",       dest="perform_snmp_walk", action="store_true", help="Perform service scan over targets.", default=False)
    parser.add_argument("--quick",      dest="quick",   action="store_true", required=False, help="Move to the next target after performing a quick scan and writing first-round recommendations.", default=False)    
    parser.add_argument("--quiet",      dest="quiet",   action="store_true", help="Supress banner and headers to limit to comma dilimeted results only.", default=False)
    parser.add_argument("--exec",       dest="follow",  action="store_true", help="Execute shell comamnds from recommendations as they are discovered. Likely to lead to very long execute times depending on the wordlist being used.", default=False)
    parser.add_argument("--simple_exec",dest="quickfollow",  action="store_true", help="Execute non-brute forcing shell comamnds only as they are discovered.", default=False)
    arguments = parser.parse_args()

    if len(sys.argv) == 1:
        print_banner()
        parser.error("No arguments given.")
        parser.print_usage
        sys.exit()

    if arguments.output_directory.endswith('/' or '\\'):
        arguments.output_directory = arguments.output_directory[:-1]
    if arguments.target_hosts.endswith('/' or '\\'):
        arguments.target_hosts = arguments.target_hosts[:-1]

    print(is_json(CONFIG))
        

# return true is json is valid or false if unable to load
def is_json(json_file):
  try:
      with open(json_file, "r") as f: 
          json_object = json.load(f)
  except ValueError:
    return False
  return True        


if __name__ == "__main__":
    main()
