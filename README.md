# PINGuin v2.8.0

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

## Interactive Shell Commands

Inside the PINGuin prompt (`$`), you can use the following commands:

| Command | Description |
|---------|-------------|
| `help` | Show all available commands and configuration attributes |
| `scan <ip>` | Run network scan on target IP |
| `enum <ip>` | Run service enumeration on target IP |
| `full <ip>` | Run both scan and enumeration (full recon) |
| `status` | Show current configuration (including zombie settings) |
| `clear` | Clear the terminal screen and redisplay banner |
| `exit` | Quit the tool |
| `ip` | Show current target IP |
| `stype` | Show current scan type (stealthy/aggressive) |
| `fname` | Show results folder name |
| `service-scan` | Show whether service version scanning is enabled |
| `host-check` | Show whether host up check is enabled |
| `nmap-path` | Show custom nmap path (if set) |
| `debug` | Show debug mode status |
| `version` | Display PINGuin version |
| `auto-update` | Show auto‑update check status |
| `update` | Pull the latest code from git (auto‑stashes local changes) |
| `update check` | Check if an update exists without pulling |
| `zombie status` | Show zombie configuration (username, IP, password hidden) |
| `zombie check` | Test zombie connectivity and readiness |

## Configuration Attributes (set command)

Use `set <attribute> <value>` to modify settings:

| Attribute | Description | Example |
|-----------|-------------|---------|
| `ip` | Target IP address | `set ip 192.168.1.10` |
| `stype` | Scan type: `stealthy` or `aggressive` | `set stype aggressive` |
| `fname` | Folder name for scan results | `set fname scan_results` |
| `config` | Path to a configuration file | `set config my_config.ini` |
| `zombie` | Set zombie credentials (user, password, ip) or load config file | `set zombie bob pass123 10.0.0.5` or `set zombie config /path/to/zombie.conf` |
| `service-scan` | Enable/disable service version scanning (`true`/`false`) | `set service-scan true` |
| `host-check` | Enable/disable host up check (`true`/`false`, default true) | `set host-check false` |
| `nmap-path` | Custom path to nmap binary | `set nmap-path /usr/local/bin/nmap` |
| `debug` | Enable/disable debug output (`true`/`false`) | `set debug true` |
| `auto-update` | Enable/disable automatic update check at startup (`true`/`false`) | `set auto-update false` |

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

Load it with: `set config config.txt`

## File Structure

    ├── main.py
    ├── config_loader.py
    ├── config.py
    ├── setup.py
    ├── requirements.txt
    ├── modules/
    │   ├── aggressive/
    │   │   ├── network_scan.py
    │   │   └── enumeration.py
    │   └── stealthy/
    │       ├── network_scan.py
    │       └── enumeration.py
    └── config/
        └── config_loader
    
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
