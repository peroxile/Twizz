#!/usr/bin/env python3

import sys
import os
import json
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict, field


# Check and Import dependencies with helpful error

try:
    import nmap
except ImportError:
    print("ERROR: python-nmap not installed")
    print("Fix: pip install python-nmap")
    print("Then install nmap system package:")
    print("  Ubuntu/Debian: sudo apt-get install nmap")
    print(" macOS: brew install nmap")
    print(" RHEL/CentOS: sudo yum install nmap")
    sys.exit(1)

try:
    from prometheus_client import start_http_server, Counter, Gauge, Histogram
except ImportError:
    print("ERROR: prormetheus-client not installed")
    print("Fix: pip install prometheus-client")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except ImportError:
    print(" WARNING: colorama not installed (colored outout disabled)")
    print("Fix: pip install colorama")
    # Define dummy Fore and Style if colorama not available

    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ''

        class Style:
            RESET_ALL = BRIGHT = ''

try:
    from tabulate import tabulate
except ImportError: 
    print("WARNING: tabulate not installed (table formatting disabled)")
    tabulate = None

# Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('recon.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)


# Prometheus metrics
SCAN_TOTAL = Counter('network_recon_scans_total', 'Total number of scans performed')
HOSTS_DISCOVERED = Gauge('network_recon_hosts_discovered', 'Number of hosts discovered')
PORTS_FOUND = Counter('network_recon_ports_found', 'Total open ports found')
SCAN_DURATION = Histogram('network_recon_scan_durations_seconds', 'Scan duration')


@dataclass
class Port:
    """Represent an open port on a host"""
    number: int
    protocol: str = 'tcp'
    state: str = 'open'
    service: str = 'unknown'
    version: str = ''


@dataclass
class Host:
    """Represents a discovered network host"""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    status: str = 'up'
    ports: List[Port] = field(default_factory=list)
    os_guess: Optional[str] = None

    def add_port(self, port: Port):
        """Add a port to the host"""
        self.ports.append(port)
        PORTS_FOUND.inc()


@dataclass
class ScanResult:
    """Complete scan results"""
    scan_id: str
    target: str 
    start_time: str
    end_time: str
    duration: float
    hosts: List[Host] = field(default_factory=list)
    total_hosts: int = 0
    total_ports: int = 0

    def to_dict(self):
        """Convert to dictionary for JSON export"""
        return asdict(self)


class NetworkScanner: 
    """Main network scanning class"""

    def __init__(self, target: str, scan_type: str = 'basic'):
        self.target = target
        self.scan_type = scan_type
        self.scanner = nmap.PortScanner()
        self.hosts: List[Host] = []
        self.start_time = None
        self.end_time = None

        logger.info(f"Initialized scanner for target: {target}")