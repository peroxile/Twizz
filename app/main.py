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
    print("ERROR: prormtheus-client not installed")
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