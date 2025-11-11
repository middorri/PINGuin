# PINGuin

Automated reconnaissance tool for network scanning and enumeration.\
\
[![License](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/) [![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/) [![x](https://img.shields.io/badge/x-@middorri-blue.svg)](https://x.com/middorri)

## What it does

- Scans networks for open ports and services
- Runs service-specific enumeration scripts
- Supports both stealthy and aggressive scanning modes
- Handles single IPs or CIDR ranges (like 192.168.1.0/24)
- Saves results to organized folders

## Requirements

- Python 3
- Nmap
- sudo privileges (for some scan types)

## Installation

```bash
git clone https://github.com/yourusername/pinguin.git
cd pinguin

Usage

Run the main interface:
bash

python3 main.py

Basic Commands

In the PINGuin interface:

    scan <ip> - Run network scan on target IP

    enum <ip> - Run service enumeration on target IP

    status - Show current settings

    help - Show all commands

    exit - Quit the tool

Set configuration:

    set ip <address> - Set target IP

    set stype <stealthy/aggressive> - Set scan type

    set fname <folder> - Set results folder name

    set config <file> - Load settings from config file

Examples

Quick scan:
text

$ python3 main.py
$ set ip 192.168.1.100
$ set stype aggressive  
$ scan

Stealthy scan with custom folder:
text

$ set ip 10.0.0.0/24
$ set stype stealthy
$ set fname my_scan_results
$ scan

Configuration File

Create a config file with settings:
text

# config.txt
IP 192.168.1.100
STYPE stealthy
FNAME scan_results

Load it with: set config config.txt
File Structure
text

├── main.py                 # Main interface
├── config_loader.py        # Configuration loader
├── config.py              # Configuration module
└── modules/
    ├── aggressive/         # Fast, comprehensive scans
    │   ├── network_scan.py
    │   └── enumeration.py
    └── stealthy/          # Slow, stealthy scans  
        ├── network_scan.py
        └── enumeration.py

Scan Types

Aggressive:

    Fast scanning with timing template T4

    service detection

Stealthy:

    Slow scanning with timing template T2

    Random delays between scans

    Fragment packets and source port manipulation

Contains:

    Nmap XML and text outputs

    Service-specific scan results

    Merged results for analysis

Notes

    Some scans require sudo for raw socket access

    Stealthy scans take much longer to complete

    CIDR range scans create subfolders for each IP

    Check help in the interface for all available commands
