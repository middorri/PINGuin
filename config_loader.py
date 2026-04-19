#!/usr/bin/env python3
"""
PINGuin - Configuration Loader
Loads settings from a config file and sets environment variables.
Supports key=value format, with boolean values (true/false) stored as strings.
"""

import os
import sys

def parse_bool(value):
    """Convert string boolean to 'true'/'false' for environment storage."""
    v = value.strip().lower()
    if v in ('true', 't', 'yes', 'y', '1'):
        return 'true'
    elif v in ('false', 'f', 'no', 'n', '0'):
        return 'false'
    return value  # return as-is if not a bool

def load_config(config_path):
    """Load key=value pairs from config file and set as environment variables."""
    if not os.path.exists(config_path):
        print(f" [!] Config file not found: {config_path}")
        return False
    
    print(f" [*] Loading configuration from: {config_path}")
    loaded = 0
    with open(config_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                print(f" [!] Line {line_num}: Ignoring malformed line (missing '='): {line}")
                continue
            
            key, value = line.split('=', 1)
            key = key.strip().upper()
            value = value.strip()
            
            # Handle known boolean settings
            if key in ('SERVICE_SCAN', 'HOST_CHECK'):
                value = parse_bool(value)
            
            os.environ[key] = value
            print(f" [+] {key} = {value}")
            loaded += 1
    
    print(f" [*] Loaded {loaded} configuration entries.")
    return True

def load_zombie_config(config_path):
    """Load zombie-specific config (username, password, zombie_ip)."""
    if not os.path.exists(config_path):
        print(f" [!] Zombie config file not found: {config_path}")
        return False
    
    print(f" [*] Loading zombie configuration from: {config_path}")
    loaded = 0
    with open(config_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                print(f" [!] Line {line_num}: Ignoring malformed line (missing '='): {line}")
                continue
            
            key, value = line.split('=', 1)
            key = key.strip().upper()
            value = value.strip()
            
            if key in ('USERNAME', 'PASSWORD', 'ZOMBIE_IP'):
                os.environ[key] = value
                print(f" [+] {key} = {value}")
                loaded += 1
            else:
                print(f" [!] Line {line_num}: Unknown key '{key}' for zombie config, ignoring.")
    
    if loaded > 0:
        os.environ['ZOMBIE'] = 'enabled'
        print(" [+] ZOMBIE = enabled")
    else:
        print(" [!] No valid zombie configuration entries found.")
        return False
    
    print(f" [*] Loaded {loaded} zombie configuration entries.")
    return True

# If run directly, test loading a config file
if __name__ == "__main__":
    if len(sys.argv) > 1:
        load_config(sys.argv[1])
        print("\nCurrent environment variables:")
        for k, v in sorted(os.environ.items()):
            if k in ('IP', 'SCAN_TYPE', 'FNAME', 'ZOMBIE', 'USERNAME', 'PASSWORD', 
                     'ZOMBIE_IP', 'SERVICE_SCAN', 'HOST_CHECK'):
                print(f"  {k} = {v}")
    else:
        print("Usage: config_loader.py <config_file>")