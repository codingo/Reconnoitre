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