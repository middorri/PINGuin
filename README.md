# PINGuin v2.5.0

Automated reconnaissance tool for network scanning and enumeration.

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/) [![x](https://img.shields.io/badge/x-@k3pt_exe-blue.svg)](https://x.com/k3pt_exe)

## What it does

- Scans networks for open ports and services
- Runs service-specific enumeration scripts
- Supports both stealthy and aggressive scanning modes
- Handles single IPs or CIDR ranges (like 192.168.1.0/24)
- Saves results to organized folders
- **Auto‑update check** – notifies you when a new version is available

## Requirements

- Python 3
- Nmap
- sudo privileges (for some scan types)
- Git (for update functionality)

## Installation

``` bash
git clone https://github.com/middorri/PINGuin
cd PINGuin
```
## Usage


### Run the main interface:
``` bash

python3 main.py
```
# Basic Commands

### In the PINGuin interface:

    scan <ip> - Run network scan on target IP

    enum <ip> - Run service enumeration on target IP

    status - Show current settings

    clear - Clear the terminal screen

    help - Show all commands

    exit - Quit the tool

### Set configuration:

    set ip <address> - Set target IP

    set stype <stealthy/aggressive> - Set scan type

    set fname <folder> - Set results folder name

    set config <file> - Load settings from config file

    set zombie <config path>/<USR/PASS/IP> - set zombie credentials

    set service_scan - Enable/disable service version scanning

    set host_check - Enable/disable host up check

    set nmap_path - Set custom path to nmap binary

    set debug - Enable/disable debug mode

    set auto-update - Enable/disable automatic update check (true/false)

## Examples
``` bash
Quick scan:

$ python3 main.py
$ set ip 192.168.1.100
$ set stype aggressive  
$ scan

Stealthy scan with custom folder:

$ set ip 10.0.0.0/24
$ set stype stealthy
$ set fname my_scan_results
$ scan
```
## Configuration File

Create a config file with settings:

## config.txt
IP 192.168.1.100
STYPE stealthy
FNAME scan_results
SERVICE_SCAN = false
HOST_CHECK = true
ZOMBIE_USER <USERNAME>
ZOMBIE_PASS <PASSWORD>
ZOMBIE_IP <IP>

Load it with: set config config.txt
File Structure

├── main.py                 # Main interface
├── config_loader.py        # Configuration loader
├── config.py               # Configuration module
├── setup.py                # run after downloading the repository
├── requirements.txt        # what tools libs required for PINGuin to work properly        
└── modules/
    ├── aggressive/         # Fast, comprehensive scans
    │   ├── network_scan.py
    │   └── enumeration.py
    └── stealthy/           # Slow, stealthy scans  
        ├── network_scan.py
        └── enumeration.py
└── config
    └── config_loader       # loads configs from config file
Scan Types

Aggressive:

    Fast scanning with timing template T4

    service detection

Stealthy:

    Slow scanning with timing template T1

    Random delays between scans

Contains:

    Nmap XML and text outputs

    Service-specific scan results

    Merged results for analysis

Notes

    Some scans require sudo for raw socket access

    Stealthy scans take much longer to complete

    CIDR range scans create subfolders for each IP

    Check help in the interface for all available commands
