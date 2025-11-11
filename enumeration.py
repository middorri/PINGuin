#!/usr/bin/env python3
"""
PINGuin - Stealthy Scan Results Analyzer
Combines stealthy enumeration techniques with comprehensive service detection
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import glob
import time
import random

# Initial environment-based IP attempt
ip = os.environ.get("IP")
if not ip:
    ip = input(" [?] Enter target IP: ").strip()
    if not ip:
        print(" [!] No IP provided. Exiting.")
        sys.exit(1)

ports_scan = Path("nmap_ports_scan.txt")
fname = os.environ.get("FNAME")

if fname is not None:
    folder_name = fname
else:
    folder_name = f"{ip}_stealth_results"


def parse_nmap_xml(xml_file):
    """Parse Nmap XML output and extract service information"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        services = []
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"

                service_elem = port.find("service")
                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    service_product = service_elem.get("product", "")
                    service_version = service_elem.get("version", "")
                    service_extrainfo = service_elem.get("extrainfo", "")

                    services.append({
                        'port': port_id,
                        'protocol': protocol,
                        'state': state,
                        'service': service_name,
                        'product': service_product,
                        'version': service_version,
                        'extrainfo': service_extrainfo
                    })

        return services
    except ET.ParseError as e:
        print(f" [!] Error parsing {xml_file}: {e}")
        return []
    except Exception as e:
        print(f" [!] Unexpected error parsing {xml_file}: {e}")
        return []


def analyze_scan_results():
    """Analyze all scan results and identify services"""
    print(" [*] Analyzing scan results...")

    # Look for both possible file locations and names
    port_scan_files = []
    
    # Check for combined XML
    possible_files = [
        f"{folder_name}/merged_results.xml",
        f"{folder_name}/nmap_output.xml", 
        "merged_results.xml",
        "nmap_output.xml"
    ]
    
    for xml_file in possible_files:
        if os.path.exists(xml_file):
            port_scan_files.append(xml_file)
            print(f" [*] Found scan results: {xml_file}")

    # Also check for individual port scans and combine them
    individual_scans = glob.glob(f"{folder_name}/nmap_port_*.xml")
    if individual_scans:
        print(f" [*] Found {len(individual_scans)} individual port scans")
        port_scan_files.extend(individual_scans)

    if not port_scan_files:
        print(" [!] No scan results found. Please run network_scan.py first.")
        print(f" [!] Expected files in: {folder_name}/")
        return []

    all_services = []
    for xml_file in port_scan_files:
        print(f" [*] Parsing {xml_file}")
        services = parse_nmap_xml(xml_file)
        all_services.extend(services)

    return all_services


def add_scan_options(cmd):
    """Add stealth options to Nmap command"""
    stealth_opts = ["-T2", "--scan-delay", "1s", "--max-rtt-timeout", "500ms"]
    cmd[1:1] = stealth_opts
    return cmd


def run_targeted_scans(services, target_ip):
    """Run targeted Nmap scans based on discovered services"""
    print(f" [*] Running stealthy targeted scans for {target_ip}")

    for service in services:
        if service['state'] != 'open':
            continue

        port = service['port']
        service_name = service['service'].lower()
        product = service['product'].lower() if service['product'] else ""

        print(f" [*] Found {service_name} on port {port} ({product})")

        # Add delays for stealthy scans
        delay = random.uniform(2, 10)
        print(f" [*] Waiting {delay:.1f} seconds before next scan...")
        time.sleep(delay)

        # Service detection and routing
        if any(ssh_indicator in service_name for ssh_indicator in ['ssh']):
            run_ssh_scan(target_ip, port)
        elif any(http_indicator in service_name for http_indicator in ['http', 'www']):
            if 'ssl' in service_name or 'ssl' in product or 'https' in service_name:
                run_https_scan(target_ip, port)
            else:
                run_http_scan(target_ip, port)
        elif any(ftp_indicator in service_name for ftp_indicator in ['ftp']):
            run_ftp_scan(target_ip, port)
        elif any(smb_indicator in service_name for smb_indicator in ['smb', 'microsoft-ds', 'netbios']):
            run_smb_scan(target_ip, port)
        elif any(mysql_indicator in service_name for mysql_indicator in ['mysql']):
            run_mysql_scan(target_ip, port)
        elif any(pgsql_indicator in service_name for pgsql_indicator in ['postgresql', 'pgsql']):
            run_pgsql_scan(target_ip, port)
        elif any(rdp_indicator in service_name for rdp_indicator in ['rdp']):
            run_rdp_scan(target_ip, port)
        elif any(vnc_indicator in service_name for vnc_indicator in ['vnc']):
            run_vnc_scan(target_ip, port)
        else:
            run_generic_scan(target_ip, port, service_name)


def run_ssh_scan(target_ip, port):
    """Run SSH-specific security scans"""
    print(f" [SSH] Running stealthy SSH scans on port {port}")

    scripts = "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/ssh_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "SSH security audit")


def run_http_scan(target_ip, port):
    """Run HTTP-specific enumeration scans"""
    print(f" [HTTP] Running stealthy HTTP scans on port {port}")

    base_scripts = [
        "http-enum", "http-headers", "http-methods", "http-title",
        "http-server-header", "http-robots.txt"
    ]

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", ",".join(base_scripts),
        "-oN", f"{folder_name}/http_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "HTTP enumeration")


def run_https_scan(target_ip, port):
    """Run HTTPS and SSL-specific scans"""
    print(f" [HTTPS] Running stealthy HTTPS scans on port {port}")

    base_scripts = [
        "ssl-cert", "ssl-enum-ciphers", "http-enum", "http-headers",
        "http-methods", "http-title", "http-server-header"
    ]

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", ",".join(base_scripts),
        "-oN", f"{folder_name}/https_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "HTTPS and SSL scan")


def run_ftp_scan(target_ip, port):
    """Run FTP-specific security scans"""
    print(f" [FTP] Running stealthy FTP scans on port {port}")

    scripts = "ftp-anon,ftp-bounce,ftp-syst"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/ftp_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "FTP security audit")


def run_smb_scan(target_ip, port):
    """Run SMB-specific enumeration scans"""
    print(f" [SMB] Running stealthy SMB scans on port {port}")

    scripts = "smb-enum-shares,smb-os-discovery,smb-security-mode"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/smb_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "SMB enumeration")


def run_mysql_scan(target_ip, port):
    """Run MySQL-specific enumeration scans"""
    print(f" [MySQL] Running stealthy MySQL scans on port {port}")

    scripts = "mysql-enum,mysql-info"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/mysql_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "MySQL enumeration")


def run_pgsql_scan(target_ip, port):
    """Run PostgreSQL-specific scans"""
    print(f" [PostgreSQL] Running stealthy PostgreSQL scans on port {port}")

    scripts = "pgsql-brute"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/pgsql_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "PostgreSQL scan")


def run_rdp_scan(target_ip, port):
    """Run RDP-specific security scans"""
    print(f" [RDP] Running stealthy RDP scans on port {port}")

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "rdp-enum-encryption,rdp-ntlm-info",
        "-oN", f"{folder_name}/rdp_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "RDP security audit")


def run_vnc_scan(target_ip, port):
    """Run VNC-specific security scans"""
    print(f" [VNC] Running stealthy VNC scans on port {port}")

    scripts = "vnc-info"

    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", scripts,
        "-oN", f"{folder_name}/vnc_scan_port_{port}.txt"
    ]
    cmd = add_scan_options(cmd)
    execute_scan(cmd, "VNC security audit")


def run_generic_scan(target_ip, port, service_name):
    """Run generic service version detection"""
    print(f" [*] Running stealthy generic scan for {service_name} on port {port}")

    cmd = [
        "nmap", "-p", port, target_ip,
        "-sV", "--version-intensity", "2",
        "-oN", f"{folder_name}/generic_scan_{service_name}_port_{port}.txt"
    ]

    cmd = add_scan_options(cmd)
    execute_scan(cmd, f"generic {service_name} scan")


def execute_scan(cmd, scan_type_desc):
    """Execute a scan command with error handling"""
    print(f" [*] Running {scan_type_desc}: {' '.join(cmd)}")

    # Adjust timeout based on scan type
    timeout = 600 if "stealthy" in scan_type_desc.lower() else 300

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            print(f" [*] {scan_type_desc} completed successfully")
        else:
            print(f" [!] {scan_type_desc} had issues: {result.stderr}")
    except subprocess.TimeoutExpired:
        print(f" [!] {scan_type_desc} timed out")
    except Exception as e:
        print(f" [!] Error running {scan_type_desc}: {e}")


def generate_summary_report(services):
    """Generate a summary report of discovered services"""
    print("\n" + "=" * 60)
    print(" SCAN SUMMARY REPORT")
    print("=" * 60)

    open_services = [s for s in services if s['state'] == 'open']

    if not open_services:
        print(" [!] No open services found")
        return

    print(f" Found {len(open_services)} open services:")
    print("-" * 60)

    for service in open_services:
        print(f"  Port {service['port']}/{service['protocol']}: {service['service']}")
        if service['product']:
            print(f"  Product: {service['product']} {service['version']}")
        if service['extrainfo']:
            print(f"  Info: {service['extrainfo']}")
        print()


def main():
    """Main analyzer function"""
    target_ip = os.environ.get("IP")
    if not target_ip:
        target_ip = input(" [?] Enter target IP: ").strip()
        if not target_ip:
            print(" [!] No IP provided. Exiting.")
            return

    # Create results directory if it doesn't exist
    Path(folder_name).mkdir(parents=True, exist_ok=True)

    # Analyze existing scan results
    services = analyze_scan_results()

    if not services:
        print(" [!] No scan results found. Please run network_scan.py first.")
        print(f" [!] Expected file: {folder_name}/all_ports.xml")
        return

    # Generate summary
    generate_summary_report(services)

    # Run targeted scans
    run_targeted_scans(services, target_ip)

    print(f"\n [*] Stealthy analysis complete!")
    print(" [*] Check the generated .txt files for detailed results")


if __name__ == "__main__":
    main()