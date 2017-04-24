import subprocess
import sys
import os

def check_directory(output_directory):
    try:
        os.stat(output_directory)
    except:
        os.mkdir(output_directory)
        print("[!] %s didn't exist and has been created." % output_directory)

def ping_sweeper(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = output_directory + "/targets.txt"

    print("[+] Writing targets to: %s" % output_file)