#!/usr/bin/env python3

import argparse
import nmap
import dns.resolver
import whois


def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024', arguments=' -0 -sV')
    print(f"Scan results for {target}:")
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        if 'osclass' in scanner[host]:
            print("OS Detection:")
            for osclass in scanner[host]['osclass']:
                print(f"  - {osclass['osfamily']} {osclass['osgen']}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                print(f"  Port: {port}, State: {scanner[host][proto][port]['state']}, Service: {scanner[host][proto][port]['name']}")
