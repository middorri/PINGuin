#!/usr/bin/python3
"""
PINGuin - Automated Reconnaissance Tool
Main entry point that coordinates all reconnaissance modules
Features a pinned banner that stays visible during menu navigation
"""

import os
import sys
import subprocess
import config_loader

def banner():
    """Display the PINGuin banner"""
    os.system('clear')
    print("")
    print("")
    print("    ██▓███   ██▓ ███▄    █   ▄████  █    ██  ██▓ ███▄    █ ")
    print("   ▓██░  ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒ ██  ▓██▒▓██▒ ██ ▀█   █ ")
    print("   ▓██░ ██▓▒▒██▒▓██  ▀█ ██▒▒██░▄▄▄░▓██  ▒██░▒██▒▓██  ▀█ ██▒")
    print("   ▒██▄█▓▒ ▒░██░▓██▒  ▐▌██▒░▓█  ██▓▓▓█  ░██░░██░▓██▒  ▐▌██▒")
    print("   ▒██▒ ░  ░░██░▒██░   ▓██░░▒▓███▀▒▒▒█████▓ ░██░▒██░   ▓██░")
    print("   ▒▓▒░ ░  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒ ░▒▓▒ ▒ ▒ ░▓  ░ ▒░   ▒ ▒ ")
    print("   ░▒ ░      ▒ ░░ ░░   ░ ▒░  ░   ░ ░░▒░ ░ ░  ▒ ░░ ░░   ░ ▒░")
    print("   ░░        ▒ ░   ░   ░ ░ ░ ░   ░  ░░░ ░ ░  ▒ ░   ░   ░ ░ ")
    print("             ░           ░       ░    ░      ░           ░ ")
    print("   PINGuin - Automated Recon Tool")
    print("")

def check_zombie_ready(zombie_ip, user, password):
    cmd = f"""
    sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -tt {user}@{zombie_ip} '
    set -e

    [ -d /home/{user} ] || exit 10
    [ -w /home/{user} ] || sudo chown -R {user}:{user} /home/{user}
    [ -w /home/{user} ] || sudo chmod 700 /home/{user}

    cd /home/{user} || exit 11
    sudo -n true || exit 12
    command -v nmap >/dev/null 2>&1 || exit 13
    '
    """
    return subprocess.call(cmd, shell=True)


def use_case():
    """Return the module path for the given use case, prompting if needed"""
    case = os.environ.get('SCAN_TYPE')
    if case == "stealthy":
        return "modules/stealthy"
    elif case == "aggressive":
        return "modules/aggressive"
    else:
        choice = input(" [?] Enter scan type (stealthy/aggressive): ")
        if choice not in ["stealthy", "aggressive"]:
            print(" [!] Invalid scan type.")
            exit(1)
        os.environ['SCAN_TYPE'] = choice
        return "modules/" + choice

def main():
    """Main function - provides menu interface with pinned banner"""
    banner()
    cmd = ""
    while cmd != "exit":
        
        cmd = input(" $ ")

        if cmd == "help":
            print(" Available commands:")
            print("   help       - Show this help message")
            print("   scan <ip>  - Run network scan module")
            print("   enum <ip>  - Run enumeration module")
            print("   full <ip>  - Run full reconnaissance module")
            print("   status     - Show current configuration status")
            print("   clear      - Clear the terminal screen")
            print("   exit       - Exit the tool")

            print("\n Configuration attributes:")
            print("   ip         - Set target IP address")
            print("   stype      - Set type of scan (stealthy/aggressive)")
            print("   fname      - Set folder name for results")
            print("   config     - Set configuration file path")
            print("   zombie     - Set zombie configuration file path/ USR/PASS/IP")
            print("\n Usage: set <attribute> <value>")
        
        elif cmd.startswith("scan"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run(["python3", f"{module}/network_scan.py"])
        
        elif cmd.startswith("enum"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run(["python3", f"{module}/enumeration.py"])
        
        elif cmd.startswith("full"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run(["python3", f"{module}/network_scan.py"])
            subprocess.run(["python3", f"{module}/enumeration.py"])
        
        elif cmd.startswith("set"):
            parts = cmd.split()
            if len(parts) < 2:
                print(" [!] Usage: set <attribute> [value]")
            else:
                attr = parts[1].lower()
                if attr == "ip":
                    if len(parts) >= 3:
                        os.environ['IP'] = parts[2]
                    else:
                        os.environ['IP'] = input(" [?] Enter IP: ")
                    print(f" [+] IP set to {os.environ['IP']}")
                
                elif attr in ("stype", "use_case"):
                    if len(parts) >= 3:
                        choice = parts[2]
                    else:
                        choice = input(" [?] Enter scan type (stealthy/aggressive): ")
                    if choice not in ["stealthy", "aggressive"]:
                        print(" [!] Invalid scan type.")
                    else:
                        os.environ['SCAN_TYPE'] = choice
                        print(f" [+] Scan type set to {choice}")
                
                elif attr == "fname":
                    if len(parts) >= 3:
                        os.environ['FNAME'] = parts[2]
                    else:
                        os.environ['FNAME'] = input(" [?] Enter folder name: ")
                    print(f" [+] Results folder set to {os.environ['FNAME']}")
                
                elif attr == "config":
                    if len(parts) >= 3:
                        config_file = parts[2]
                        config_loader.load_config(config_file)
                
                elif attr == "zombie":
                    os.environ['ZOMBIE'] = "enabled"
                    # zombie
                    if len(parts) == 1:
                        print("[-] Usage: zombie <config|user> [pass] [ip]")
                        return
                    # zombie config [path]
                    if parts[1] == "config":
                        if len(parts) >= 3:
                            config_path = parts[2]
                        else:
                            config_path = input(" [?] Enter zombie config file path: ")
                        config_loader.load_zombie_config(config_path)
                        return
                    # zombie user
                    if len(parts) == 2:
                        os.environ['USERNAME'] = parts[1]
                        os.environ['PASSWORD'] = input(" [?] Enter zombie password: ")
                        os.environ['ZOMBIE_IP'] = input(" [?] Enter zombie IP address: ")
                        return
                    # zombie user pass
                    if len(parts) == 3:
                        os.environ['USERNAME'] = parts[1]
                        os.environ['PASSWORD'] = parts[2]
                        os.environ['ZOMBIE_IP'] = input(" [?] Enter zombie IP address: ")
                        return
                    # zombie user pass ip
                    if len(parts) == 4:
                        os.environ['USERNAME'] = parts[1]
                        os.environ['PASSWORD'] = parts[2]
                        os.environ['ZOMBIE_IP'] = parts[3]
                        return
                    else:
                        print("[-] Invalid zombie syntax")

        
        elif cmd.startswith("zombie"):
            parts = cmd.split()
            if len(parts) < 2:
                print(" [!] Usage: zombie stauts/check")
            else:
                attr = parts[1].lower()
            if attr == "status":
                if os.environ.get('ZOMBIE') == 'enabled':
                    print(" [*] Zombie configuration is enabled.")
                    print(f"     USERNAME: {os.environ.get('USERNAME', 'Not set')}")
                    print(f"     PASSWORD: {os.environ.get('PASSWORD', 'Not set')}")
                    print(f"     ZOMBIE_IP: {os.environ.get('ZOMBIE_IP', 'Not set')}")
                else:
                    print(" [*] Zombie configuration is disabled.")
            if attr == "check":
                if os.environ.get('ZOMBIE') == 'enabled':
                    zombie_ip = os.environ.get('ZOMBIE_IP')
                    user = os.environ.get('USERNAME')
                    password = os.environ.get('PASSWORD')
                    print(" [*] Checking zombie readiness...")
                    ret = check_zombie_ready(zombie_ip, user, password)
                    if ret == 0:
                        print(" [+] Zombie is ready for use.")
                    else:
                        print(f" [!] Zombie check failed with code {ret}.")
                else:
                    print(" [!] Zombie configuration is not set.")



        elif cmd == "ip":
            print(f" [*] Current IP: {os.environ.get('IP', 'Not set')}")
        
        elif cmd == "stype":
            scantype = os.environ.get('SCAN_TYPE')
            print(f" [*] Current scan type: {scantype}")
        
        elif cmd == "fname":
            fname = os.environ.get('FNAME')
            if fname and not os.path.exists(f"{fname}"):
                os.mkdir(f"{fname}")
            print(f" [*] Current results folder: {fname}")
        
        elif cmd == "status":
            print(f" [*] Current configuration:")
            print(f"     IP: {os.environ.get('IP', 'Not set')}")
            print(f"     Scan Type: {os.environ.get('SCAN_TYPE', 'Not set')}")
            print(f"     Results Folder: {os.environ.get('FNAME', 'Not set')}")
        
        elif cmd == "clear":
            os.system('clear')
            banner()

if __name__ == "__main__":
    main()