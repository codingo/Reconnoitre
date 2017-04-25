import subprocess
import sys
from directory_helper import check_directory

def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)