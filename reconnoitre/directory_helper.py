import os


def check_directory(output_directory):
    try:
        os.stat(output_directory)
    except:
        os.mkdir(output_directory)
        print("[!] %s didn't exist and has been created." % output_directory)

def load_targets(target_hosts, output_directory, quiet):
    # check if targets was sent as a target file, or IP range.
    # todo: should be improved to force load targets if they don't already exist in targets.txt
    if(os.path.isdir(target_hosts) or os.path.isfile(target_hosts)):
        return open(target_hosts, 'r')
    else:
        return open(output_directory + "/targets.txt")