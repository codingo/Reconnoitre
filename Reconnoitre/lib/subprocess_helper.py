#!/usr/bin/python
from subprocess import CalledProcessError
import subprocess


def run_scan(scan, stderr=None):
    """Helper method to perform a scan using a subprocess and return results.
    We use the same configuration options for each call to check_output, this
    can be bunched into one helper function to keep config constant."""
    try:
        return subprocess.check_output(scan, shell=True, stderr=stderr, universal_newlines=True)
    except CalledProcessError as err:
        raise err
