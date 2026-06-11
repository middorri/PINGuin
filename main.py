#!/usr/bin/python3
"""
PINGuin - Automated Reconnaissance Tool
Main entry point that coordinates all reconnaissance modules
"""

import argparse
import os
import sys
import subprocess
import config_loader

os.environ['VERSION'] = "2.9.0"

def banner():
    """Display the PINGuin banner"""
    os.system('cls' if sys.platform == 'win32' else 'clear')
    print(f"""
    ██▓███   ██▓ ███▄    █   ▄████  █    ██  ██▓ ███▄    █ 
   ▓██░  ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒ ██  ▓██▒▓██▒ ██ ▀█   █ 
   ▓██░ ██▓▒▒██▒▓██  ▀█ ██▒▒██░▄▄▄░▓██  ▒██░▒██▒▓██  ▀█ ██▒
   ▒██▄█▓▒ ▒░██░▓██▒  ▐▌██▒░▓█  ██▓▓▓█  ░██░░██░▓██▒  ▐▌██▒
   ▒██▒ ░  ░░██░▒██░   ▓██░░▒▓███▀▒▒▒█████▓ ░██░▒██░   ▓██░
   ▒▓▒░ ░  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒ ░▒▓▒ ▒ ▒ ░▓  ░ ▒░   ▒ ▒ 
   ░▒ ░      ▒ ░░ ░░   ░ ▒░  ░   ░ ░░▒░ ░ ░  ▒ ░░ ░░   ░ ▒░
   ░░        ▒ ░   ░   ░ ░ ░ ░   ░  ░░░ ░ ░  ▒ ░   ░   ░ ░ 
             ░           ░       ░    ░      ░           ░ 
   PINGuin - Automated Recon Tool           Version: {os.environ.get('VERSION')}
    """)

def check_zombie_ready(zombie_ip, user, password):
    ssh_cmd = (
        "sshpass -p {pw} ssh "
        "-o StrictHostKeyChecking=no "
        "-o BatchMode=no "
        "-o ConnectTimeout=10 "
        "-tt {user}@{ip} "
        "\""
        "set -e; "
        "[ -d /home/{user} ] || exit 10; "
        "sudo -S chown -R {user}:{user} /home/{user} <<< {pw} || exit 11; "
        "sudo -S chmod 700 /home/{user} <<< {pw} || exit 12; "
        "cd /home/{user} || exit 13; "
        "sudo -S true <<< {pw} || exit 14; "
        "command -v nmap >/dev/null 2>&1 || exit 15; "
        "exit 0"
        "\""
    ).format(user=user, ip=zombie_ip, pw=password)
    return subprocess.call(ssh_cmd, shell=True)

def get_current_commit():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None

def get_remote_commit():
    try:
        subprocess.run(["git", "fetch", "--quiet"], check=False)
        result = subprocess.run(
            ["git", "rev-parse", "@{u}"],
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None

def check_for_updates(verbose=False):
    current = get_current_commit()
    remote = get_remote_commit()
    if current and remote and current != remote:
        if verbose:
            print(f"\n [!] Update available!")
            print(f"    Current: {current[:7]}")
            print(f"    Latest : {remote[:7]}")
            print("    Run 'update' to pull the latest code.")
        return True
    if verbose and current and remote:
        print("\n [*] PINGuin is up to date.")
    return False

def perform_update():
    print("[*] Pulling latest code from git...")
    try:
        changes_check = subprocess.run(
            ["git", "diff-index", "--quiet", "HEAD", "--"],
            capture_output=False, check=False
        )
        has_changes = (changes_check.returncode != 0)

        stashed = False
        if has_changes:
            print("[*] Uncommitted changes detected. Stashing them automatically...")
            stash_result = subprocess.run(
                ["git", "stash", "push", "-m", "PINGuin-auto-stash"],
                capture_output=True, text=True, check=False
            )
            if stash_result.returncode != 0:
                print("[!] Failed to stash changes. Aborting update.")
                print(stash_result.stderr)
                return False
            stashed = True
            print("[+] Changes stashed successfully.")

        pull_result = subprocess.run(
            ["git", "pull", "--ff-only"],
            capture_output=True, text=True, check=False
        )

        if pull_result.returncode == 0:
            print("[+] Update successful.")
            if pull_result.stdout:
                print(pull_result.stdout)
            if stashed:
                print("\n [*] Your local changes were stashed automatically.")
                print("    To restore them, run: git stash pop")
                print("    (Resolve any conflicts manually if they occur.)")
            return True
        else:
            print("[!] Update failed. Output:")
            print(pull_result.stderr)
            if stashed:
                print("[*] Restoring your stashed changes...")
                subprocess.run(["git", "stash", "pop"], capture_output=True)
            return False

    except FileNotFoundError:
        print("[!] Git not found. Cannot update.")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def use_case():
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
    banner()
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--config", help="Path to configuration file", type=str)
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()
    if args.config:
        config_loader.load_config(args.config)

    if args.debug:
        os.environ['DEBUG'] = "true"

    if os.environ.get('AUTO_UPDATE_CHECK', 'true').lower() == 'true':
        check_for_updates(verbose=True)

    cmd = ""
    while cmd != "exit":
        cmd = input(" $ ")

        if cmd == "help":
            print(" Available commands:")
            print("   help         - Show this help message")
            print("   scan <ip>    - Run network scan module")
            print("   enum <ip>    - Run enumeration module")
            print("   full <ip>    - Run full reconnaissance module")
            print("   status       - Show current configuration status")
            print("   clear        - Clear the terminal screen")
            print("   exit         - Exit the tool")
            print("   ip           - Show current target IP")
            print("   stype        - Show current scan type")
            print("   fname        - Show results folder")
            print("   service-scan - Show service scan status")
            print("   host-check   - Show host up check status")
            print("   nmap-path    - Show nmap path")
            print("   debug        - Show debug mode status")
            print("   version      - Show tool version")
            print("   auto-update  - Show auto-update check status")
            print("   update       - Pull latest code from git")
            print("   update check - Check if an update exists without pulling")
            print("   zombie status- Show zombie configuration")
            print("   zombie check - Test zombie connectivity")
            print("\n Configuration attributes (use 'set <attr> <value>'):")
            print("   ip           - Target IP address")
            print("   tports       - Target ports (common|all|80,443,22)")
            print("   stype        - Scan type (stealthy/aggressive)")
            print("   fname        - Folder name for results")
            print("   config       - Path to configuration file")
            print("   zombie       - Zombie config (user/pass/ip or config file)")
            print("   service-scan - Enable/disable service version scanning (true/false)")
            print("   host-check   - Enable/disable host up check (true/false)")
            print("   nmap-path    - Custom path to nmap binary")
            print("   debug        - Enable/disable debug mode (true/false)")
            print("   auto-update  - Enable/disable automatic update check (true/false)")
            print("\n Usage: set <attribute> <value>")

        elif cmd.startswith("scan"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            if sys.platform != "win32":
                subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run([sys.executable, f"{module}/network_scan.py"])

        elif cmd.startswith("enum"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            if sys.platform != "win32":
                subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run([sys.executable, f"{module}/enumeration.py"])

        elif cmd.startswith("full"):
            parts = cmd.split()
            module = use_case()
            if len(parts) >= 2:
                os.environ['IP'] = parts[1]
            elif os.environ.get('IP') is None:
                os.environ['IP'] = input(" [?] Enter target IP: ")
            if sys.platform != "win32":
                subprocess.run(["sudo", "-n", "true"], check=False)
            subprocess.run([sys.executable, f"{module}/network_scan.py"])
            subprocess.run([sys.executable, f"{module}/enumeration.py"])

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

                elif attr == "tports":
                    if len(parts) >= 3:
                        value = parts[2]
                        os.environ['TPORTS'] = value
                        print(f" [+] TPORTS set to {value}")
                    else:
                        print(" Usage: set tports common|all|80,443,22")

                elif attr in ("stype"):
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
                    zombie_args = parts[2:]
                    if not zombie_args:
                        print("[-] Usage: set zombie <config|user> [pass] [ip]")
                        continue
                    if zombie_args[0] == "config":
                        if len(zombie_args) >= 2:
                            config_path = zombie_args[1]
                            os.environ['ZOMBIE'] = "enabled"
                        else:
                            config_path = input(" [?] Enter zombie config file path: ")
                            os.environ['ZOMBIE'] = "enabled"
                        config_loader.load_zombie_config(config_path)
                        continue
                    if len(zombie_args) == 1:
                        os.environ['USERNAME'] = zombie_args[0]
                        os.environ['PASSWORD'] = input(" [?] Enter zombie password: ")
                        os.environ['ZOMBIE_IP'] = input(" [?] Enter zombie IP address: ")
                        os.environ['ZOMBIE'] = "enabled"
                        continue
                    if len(zombie_args) == 2:
                        os.environ['USERNAME'] = zombie_args[0]
                        os.environ['PASSWORD'] = zombie_args[1]
                        os.environ['ZOMBIE_IP'] = input(" [?] Enter zombie IP address: ")
                        os.environ['ZOMBIE'] = "enabled"
                        continue
                    if len(zombie_args) == 3:
                        os.environ['USERNAME'] = zombie_args[0]
                        os.environ['PASSWORD'] = zombie_args[1]
                        os.environ['ZOMBIE_IP'] = zombie_args[2]
                        os.environ['ZOMBIE'] = "enabled"
                        continue
                    print("[-] Invalid zombie syntax")

                elif attr == "service-scan":
                    if len(parts) >= 3:
                        choice = parts[2].lower()
                    else:
                        choice = input(" [?] Enable service scan? (true/false): ").lower()
                    if choice in ["true", "t"]:
                        os.environ['SERVICE_SCAN'] = "true"
                        print(" [+] Service scan enabled")
                    elif choice in ["false", "f"]:
                        os.environ['SERVICE_SCAN'] = "false"
                        print(" [+] Service scan disabled")
                    else:
                        print(" [!] Invalid choice.")

                elif attr == "host-check":
                    if len(parts) >= 3:
                        choice = parts[2].lower()
                    else:
                        choice = input(" [?] Perform host up check? (true/false, default true): ").lower()
                    if choice in ["true", "t"]:
                        os.environ['HOST_CHECK'] = "true"
                        print(" [+] Host up check will be performed")
                    elif choice in ["false", "f"]:
                        os.environ['HOST_CHECK'] = "false"
                        print(" [+] Host up check will be skipped")
                    else:
                        print(" [!] Invalid choice.")

                elif attr == "nmap-path":
                    if len(parts) >= 3:
                        os.environ['NMAP_PATH'] = parts[2]
                    else:
                        os.environ['NMAP_PATH'] = input(" [?] Enter custom nmap path: ")
                    print(f" [+] Nmap path set to {os.environ['NMAP_PATH']}")

                elif attr == "debug":
                    if len(parts) >= 3:
                        choice = parts[2].lower()
                    else:
                        choice = input(" [?] Enable debug mode? (true/false): ").lower()
                    if choice in ["true", "t"]:
                        os.environ['DEBUG'] = 'true'
                        print(" [+] Debug mode enabled")
                    elif choice in ["false", "f"]:
                        os.environ['DEBUG'] = 'false'
                        print(" [+] Debug mode disabled")
                    else:
                        print(" [!] Invalid choice.")

                elif attr == "auto-update":
                    if len(parts) >= 3:
                        choice = parts[2].lower()
                    else:
                        choice = input(" [?] Enable automatic update check at startup? (true/false): ").lower()
                    if choice in ["true", "t"]:
                        os.environ['AUTO_UPDATE_CHECK'] = 'true'
                        print(" [+] Auto-update check enabled")
                    elif choice in ["false", "f"]:
                        os.environ['AUTO_UPDATE_CHECK'] = 'false'
                        print(" [+] Auto-update check disabled")
                    else:
                        print(" [!] Invalid choice.")

        elif cmd.startswith("update"):
            parts = cmd.split()
            if len(parts) == 1:
                perform_update()
            elif len(parts) == 2 and parts[1] == "check":
                check_for_updates(verbose=True)
            else:
                print(" Usage: update          - Pull latest code from git")
                print("        update check    - Check if an update exists without pulling")

        elif cmd.startswith("zombie"):
            parts = cmd.split()
            if len(parts) < 2:
                print(" [!] Usage: zombie status/check")
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
                        ready = check_zombie_ready(zombie_ip, user, password)
                        if ready == 0:
                            print(" [+] Zombie is ready for use.")
                        else:
                            print(f" [!] Zombie check failed with code {ready}.")
                    else:
                        print(" [!] Zombie configuration is not set.")

        elif cmd == "ip":
            print(f" [*] Current IP: {os.environ.get('IP', 'Not set')}")

        elif cmd == "tports":
            print(f" [*] TPORTS: {os.environ.get('TPORTS', 'Not set (use Shodan)')}")

        elif cmd == "stype":
            print(f" [*] Current scan type: {os.environ.get('SCAN_TYPE', 'Not set')}")

        elif cmd == "fname":
            fname = os.environ.get('FNAME')
            if fname and not os.path.exists(f"{fname}"):
                os.mkdir(f"{fname}")
            print(f" [*] Current results folder: {fname}")

        elif cmd == "service-scan":
            print(f" [*] Service scan is {'enabled' if os.environ.get('SERVICE_SCAN', 'true') == 'true' else 'disabled'}")

        elif cmd == "host-check":
            print(f" [*] Host up check is {'enabled' if os.environ.get('HOST_CHECK', 'true') == 'true' else 'disabled'}")

        elif cmd == "nmap-path":
            print(f" [*] Current nmap path: {os.environ.get('NMAP_PATH', 'nmap (default)')}")

        elif cmd == "debug":
            print(f" [*] Debug mode is {'enabled' if os.environ.get('DEBUG', 'false') == 'true' else 'disabled'}")

        elif cmd == "version":
            print(f" [*] PINGuin version: {os.environ.get('VERSION')}")

        elif cmd == "status":
            print(" [*] Current configuration:")
            print(f"     IP: {os.environ.get('IP', 'Not set')}")
            print(f"     TPORTS: {os.environ.get('TPORTS', 'Not set (use Shodan)')}")
            print(f"     Scan Type: {os.environ.get('SCAN_TYPE', 'Not set')}")
            print(f"     Results Folder: {os.environ.get('FNAME', 'Not set')}")
            print(f"     Service Scan: {'enabled' if os.environ.get('SERVICE_SCAN', 'true') == 'true' else 'disabled'}")
            print(f"     Host Check: {'enabled' if os.environ.get('HOST_CHECK', 'true') == 'true' else 'disabled'}")
            print(f"     Nmap Path: {os.environ.get('NMAP_PATH', 'nmap (default)')}")
            print(f"     Debug Mode: {'enabled' if os.environ.get('DEBUG', 'false') == 'true' else 'disabled'}")
            print(f"     Auto Update Check: {'enabled' if os.environ.get('AUTO_UPDATE_CHECK', 'true') == 'true' else 'disabled'}")
            if os.environ.get('ZOMBIE') == 'enabled':
                print("     Zombie Mode: enabled")
                print(f"        Username: {os.environ.get('USERNAME', 'Not set')}")
                print(f"        IP: {os.environ.get('ZOMBIE_IP', 'Not set')}")
                print(f"        Password: {'*' * len(os.environ.get('PASSWORD', '')) if os.environ.get('PASSWORD') else 'Not set'}")
            else:
                print("     Zombie Mode: disabled")

        elif cmd == "auto-update":
            print(f" [*] Auto-update check is {'enabled' if os.environ.get('AUTO_UPDATE_CHECK', 'true') == 'true' else 'disabled'}")

        elif cmd == "clear":
            os.system('cls' if sys.platform == 'win32' else 'clear')
            banner()

if __name__ == "__main__":
    main()