from argparse import ArgumentParser
import os.path


class CliHelper(object):
    @staticmethod
    def readable_file(parser, arg):
        if not os.path.exists(arg):
            parser.error("The file %s does not exist!" % arg)
        else:
            return open(arg, 'r')  # return an open file handle


class CliArgumentParser(object):
    def __init__(self):
        self._parser = self.setup_parser()

    def parse(self, argv):
        return self._parser.parse_args(argv)

    @staticmethod
    def setup_parser():
        parser = ArgumentParser()

        parser.add_argument(
            "-t",
            dest="target_hosts",
            required=True,
            help="Set a target range of addresses to target. Ex 10.11.1.1-255")

        parser.add_argument(
            "-o",
            dest="output_directory",
            required=True,
            help="Set the output directory. Ex /root/Documents/labs/")

        parser.add_argument(
            "-w",
            dest="wordlist",
            required=False,
            help="Set the wordlist to use for generated commands."
            " Ex /usr/share/wordlist.txt",
            default=False)

        parser.add_argument(
            "-p",
            dest="port",
            required=False,
            help="Set the port to use. Leave blank to use discovered ports. "
            "Useful to force virtual host "
            "scanning on non-standard webserver ports.",
            default=80)

        parser.add_argument(
            "--pingsweep",
            dest="ping_sweep",
            action="store_true",
            help="Write a new target.txt by performing "
            "a ping sweep and discovering live hosts.",
            default=False)

        parser.add_argument("--dns", "--dnssweep",
                            dest="find_dns_servers",
                            action="store_true",
                            help="Find DNS servers from a list of targets.",
                            default=False)

        parser.add_argument("--services",
                            dest="perform_service_scan",
                            action="store_true",
                            help="Perform service scan over targets.",
                            default=False)

        parser.add_argument(
            "--hostnames",
            dest="hostname_scan",
            action="store_true",
            help="Attempt to discover target hostnames and "
            "write to 0-name.txt and hostnames.txt.",
            default=False)

        parser.add_argument("--snmp",
                            dest="perform_snmp_walk",
                            action="store_true",
                            help="Perform service scan over targets.",
                            default=False)

        parser.add_argument(
            "--quick",
            dest="quick",
            action="store_true",
            required=False,
            help="Move to the next target after "
            "performing a quick scan and writing "
            "first-round recommendations.",
            default=False)

        parser.add_argument(
            "--virtualhosts",
            dest="virtualhosts",
            action="store_true",
            required=False,
            help="Attempt to discover virtual hosts "
            "using the specified wordlist.",
            default=False)

        parser.add_argument(
            '--ignore-http-codes',
            dest='ignore_http_codes',
            type=str,
            help='Comma separated list of http '
            'codes to ignore with virtual host scans.',
            default='404')

        parser.add_argument(
            '--ignore-content-length',
            dest='ignore_content_length',
            type=int,
            help='Ignore content lengths of specificed amount. '
            'This may become useful when a server returns a static page on '
            'every virtual host guess.',
            default=0)

        parser.add_argument(
            "--quiet",
            dest="quiet",
            action="store_true",
            help="Supress banner and headers to limit "
            "to comma dilimeted results only.",
            default=False)

        parser.add_argument("--no-udp",
                            dest="no_udp_service_scan",
                            action="store_true",
                            help="Disable UDP services scan over targets.",
                            default=False)
        return parser
