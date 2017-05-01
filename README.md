![Reconnnoitre](https://github.com/codingo/Reconnoitre/blob/master/tank-152362_640.png)
A reconnaissance tool made for the OSCP labs to automate information gathering and service enumeration whilst also creating a directory structure of results for each host, recommended commands to execute and directory structures for storing loot and flags.

[![Python 3.2|3.6](https://img.shields.io/badge/python-3.2|3.6-green.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Public_domain-red.svg)](https://wiki.creativecommons.org/wiki/Public_domain) [![Build Status](https://travis-ci.org/codingo/reconnoitre.svg?branch=master)](https://travis-ci.org/codingo/reconnoitre)

# Credit

This tool is based heavily upon the work made public in Mike Czumak's (T_v3rn1x) OSCP review, found here: https://www.securitysift.com/offsec-pwb-oscp/

This also has considerable influence and code taken from Re4son's mix-recon (see: https://whitedome.com.au/re4son/category/re4son/oscpnotes/) which is also based upon Mike Czumak's original offering. The public repository for mix-recon can be found here: https://github.com/Re4son/mix-recon

# Usage

This tool can be used and copied for personal use freely however attribution and credit should be offered to Mike Czumak who originally started the process of automating this work.

| Argument        | Description |
| ------------- |:-------------|
| -h, --help | Display help message and exit |
| -t TARGET_HOSTS | Set either a target range of addresses or a single host to target. May also be a file containing hosts. |
| -o OUTPUT_DIRECTORY | Set the target directory where results should be written. |
| -w WORDLIST | Optionally specify your own wordlist to use for pre-compiled command, or executed attacks. |
| -pS | Write a new target.txt file in the OUTPUT_DIRECTORY by performing a ping sweep and discovering live hosts. |
| -fD | Find DNS servers from the list of target(s). |
| -sS | Perform a service scan over the target(s) and write recommendations for further commands to execute, or execute commands (such as password brute forcing). |
| --quiet | Supress banner and headers and limit feedback to grepable results. |
| --execute | Execute shell commands from recommendations as they are discovered. Likely to lead to very long execution tiomes depending on the wordlist being used and discovered vectors. |
