#!/usr/bin/env python3
"""
PINGuin - Configuration Loader
Loads settings from config files and sets environment variables
"""

import os
import sys

def load_config(config_path):
    """Load configuration from file and set environment variables"""
    try:
        if not os.path.exists(config_path):
            print(f" [!] Config file not found: {config_path}")
            return False
        
        print(f" [*] Loading configuration from: {config_path}")
        
        with open(config_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse key-value pairs
                if ' ' in line:
                    key, value = line.split(' ', 1)
                    key = key.strip().upper()
                    value = value.strip()
                    
                    # Set environment variables
                    if key == 'IP':
                        os.environ['IP'] = value
                        print(f" [+] Target IP set: {value}")
                    elif key == 'STYPE':
                        if value.lower() in ['stealthy', 'aggressive']:
                            os.environ['SCAN_TYPE'] = value.lower()
                            print(f" [+] Scan type set: {value}")
                        else:
                            print(f" [!] Invalid scan type: {value}")
                    elif key == 'FNAME':
                        os.environ['FNAME'] = value
                        print(f" [+] Results folder set: {value}")
                    elif key == 'ZOMBIE_IP':
                        os.environ['ZOMBIE_IP'] = value
                        os.environ['ZOMBIE'] = "enabled"
                        print(f" [+] Zombie IP set: {value}")
                    elif key == 'ZOMBIE_USER':
                        os.environ['USERNAME'] = value
                        print(f" [+] Zombie username set: {value}")
                    elif key == 'ZOMBIE_PASS':
                        os.environ['PASSWORD'] = value
                        print(f" [+] Zombie password set")
                    else:
                        print(f" [!] Unknown configuration key: {key}")
        
        print(" [+] Configuration loaded successfully")
        return True
        
    except Exception as e:
        print(f" [!] Error loading configuration: {e}")
        return False

def main():
    """Test function for config loader"""
    if len(sys.argv) != 2:
        print("Usage: python config_loader.py <config_file>")
        return
    
    config_file = sys.argv[1]
    load_config(config_file)

if __name__ == "__main__":
    main()