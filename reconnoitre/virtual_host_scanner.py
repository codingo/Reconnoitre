class virtual_host_scanner(object):
    """Virtual host scanning class for Reconnoitre
    
    Virtual host scanner has the following properties:
    
    Attributes:
        wordlist: location to a wordlist file to use with scans
        target: the target for scanning
        port: the port to scan. Defaults to 80
        ignore_http_codes: commad seperated list of http codes to ignore
        ignore_content_length: integer value of content length to ignore
        output: folder to write output file to

    """

    def __init__(self, target, output, port=80, ignore_http_codes='404', ignore_content_length=0, wordlist="./wordlist/virtual-host-scanning.txt"):
        self.target = target
        self.output = output + '/' + target + '_virtualhosts.txt'
        self.port = port
        self.ignore_http_codes = list(map(int, args.ignore_http_codes.replace(' ', '').split(',')))
        self.ignore_content_length = ignore_content_length
        self.wordlist = wordlist

    def scan(self):
        print("DEBUG: entered scan routine")