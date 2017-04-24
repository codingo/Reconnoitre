#!/usr/bin/python
from argparse import ArgumentParser
import sys
from ping_sweeper import ping_sweeper

def print_banner():
    print("  __")
    print("|\"\"\"\-=  RECONNOITRE")
    print("(____)      An OSCP scanner\n")

def main():
    parser = ArgumentParser()
    parser.add_argument("-t", dest="target_hosts", required=True, help="Set a target range of addresses to target. Ex 10.11.0.1-255" )
    parser.add_argument("-o", dest="output_directory", help="Set the output directory.")
    parser.add_argument("--quiet", dest="quiet",  action="store_true", help="Supress banner and headers to limit to comma dilimeted results only.", default=False)
    arguments = parser.parse_args()

    if len(sys.argv) == 1:
        print_banner()
        parser.error("No arguments given.")
        parser.print_usage
        sys.exit()

    if arguments.quiet is not True:
        print_banner()

    ping_sweeper(arguments.target_hosts.strip(), arguments.output_directory.strip(), arguments.quiet)

if __name__ == "__main__":
    main()