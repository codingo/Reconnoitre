#!/usr/bin/python

import os
import requests


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
        self.ignore_http_codes = list(map(int, ignore_http_codes.replace(' ', '').split(',')))
        self.ignore_content_length = ignore_content_length
        self.wordlist = wordlist

    def scan(self):
        print("[+] Starting virtual host scan for %s using port %s and wordlist %s" % (self.target, str(self.port), self.wordlist))
        print("[>] Ignoring HTTP codes: %s" % (self.ignore_http_codes))
        if(self.ignore_content_length > 0):
            print("[>] Ignoring Content length: %s" % (self.ignore_content_length))

        if not os.path.exists(self.wordlist):
            print("[!] Wordlist %s doesn't exist, exiting virtual host scanner." % self.wordlist)
            return
        
        virtual_host_list = open(self.wordlist).read().splitlines()
        results = ''

        for virtual_host in virtual_host_list:
            hostname = virtual_host.replace('%s', self.target)

            headers = {
                'Host': hostname if self.port == 80 else '{}:{}'.format(hostname, self.port),
                'Accept': '*/*'
            }
            
            dest_url = '{}://{}:{}/'.format('https' if int(self.port) == 443 else 'http', self.target, self.port)

            try:
                res = requests.get(dest_url, headers=headers, verify=False)
            except requests.exceptions.RequestException:
                continue

            if res.status_code in self.ignore_http_codes:
                continue

            if self.ignore_content_length > 0 and self.ignore_content_length == int(res.headers.get('content-length')):
                continue

            output = 'Found: {} (code: {}, length: {})'.format(hostname, res.status_code, res.headers.get('content-length'))
            results += output + '\n'
            
            print(output)
            for key, val in res.headers.items():
                output = '  {}: {}'.format(key, val)
                results += output + '\n'
                print(output)
