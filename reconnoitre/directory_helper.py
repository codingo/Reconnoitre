import os


def check_directory(output_directory):
    try:
        os.stat(output_directory)
    except:
        os.mkdir(output_directory)
        print("[!] %s didn't exist and has been created." % output_directory)
