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
    except Exception as e:
        print(f" [!] Error parsing {xml_file}: {e}")
        return []

def analyze_scan_results(ip, folder_name):
    """Analyze all scan results and identify services for a specific IP"""
    print(f" [*] Analyzing scan results for {ip}...")
    safe_ip = ip.replace('/', '_')
    possible_locations = [
        f"{folder_name}/{safe_ip}",
        folder_name,
        "."
    ]
    port_scan_files = []
    for location in possible_locations:
        merged_xml = f"{location}/merged_results.xml"
        if os.path.exists(merged_xml):
            port_scan_files.append(merged_xml)
            print(f" [*] Found scan results: {merged_xml}")
        ip_merged_xml = f"{folder_name}/merged_results_{safe_ip}.xml"
        if os.path.exists(ip_merged_xml):
            port_scan_files.append(ip_merged_xml)
            print(f" [*] Found scan results: {ip_merged_xml}")
        individual_scans = glob.glob(f"{location}/scan_*.xml") + glob.glob(f"{location}/nmap_port_*.xml")
        if individual_scans:
            print(f" [*] Found {len(individual_scans)} individual scan files in {location}")
            port_scan_files.extend(individual_scans)
    seen = set()
    unique_files = []
    for f in port_scan_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)
    if not unique_files:
        print(" [!] No scan results found. Please run network_scan.py first.")
        return []
    all_services = []
    for xml_file in unique_files:
        print(f" [*] Parsing {xml_file}")
        services = parse_nmap_xml(xml_file)
        all_services.extend(services)
    return all_services

def run_targeted_scans(services, target_ip, folder_name):
    """Run targeted enumeration using specialized tools"""
    print(f" [*] Running stealthy targeted scans for {target_ip}")
    safe_ip = target_ip.replace('/', '_')
    ip_folder = Path(folder_name) / safe_ip
    ip_folder.mkdir(parents=True, exist_ok=True)

    no_special_tool = []  # services that still use Nmap scripts

    for service in services:
        if service['state'] != 'open':
            continue
        port = service['port']
        service_name = service['service'].lower()
        product = service['product'].lower() if service['product'] else ""

        print(f" [*] Found {service_name} on port {port} ({product})")
        delay = random.uniform(2, 10)
        print(f" [*] Waiting {delay:.1f} seconds before next scan...")
        time.sleep(delay)

        # Service routing with specialized tools
        if any(ssh_indicator in service_name for ssh_indicator in ['ssh']):
            run_ssh_audit(target_ip, port, str(ip_folder))
        elif any(http_indicator in service_name for http_indicator in ['http', 'www']):
            if 'ssl' in service_name or 'ssl' in product or 'https' in service_name:
                run_https_scan(target_ip, port, str(ip_folder))
            else:
                run_http_scan(target_ip, port, str(ip_folder))
        elif any(ftp_indicator in service_name for ftp_indicator in ['ftp']):
            run_ftp_scan(target_ip, port, str(ip_folder))
        elif any(smb_indicator in service_name for smb_indicator in ['smb', 'microsoft-ds', 'netbios']):
            run_smb_scan(target_ip, port, str(ip_folder))
        elif any(mysql_indicator in service_name for mysql_indicator in ['mysql']):
            run_mysql_scan(target_ip, port, str(ip_folder))
        elif any(pgsql_indicator in service_name for pgsql_indicator in ['postgresql', 'pgsql']):
            run_pgsql_scan(target_ip, port, str(ip_folder))
        elif any(rdp_indicator in service_name for rdp_indicator in ['rdp']):
            run_rdp_scan(target_ip, port, str(ip_folder))
        elif any(vnc_indicator in service_name for vnc_indicator in ['vnc']):
            run_vnc_scan(target_ip, port, str(ip_folder))
        else:
            run_generic_scan(target_ip, port, service_name, str(ip_folder))
            no_special_tool.append(f"{service_name} on port {port}")

    if no_special_tool:
        print("\n [*] The following services had no specialized tool and were scanned with Nmap scripts:")
        for s in no_special_tool:
            print(f"     - {s}")

# ------------------- New specialized tool functions -------------------

def run_ssh_audit(target_ip, port, ip_folder):
    """Run ssh-audit for comprehensive SSH security assessment"""
    print(f" [SSH] Running ssh-audit on port {port}")
    output_file = f"{ip_folder}/ssh_audit_port_{port}.txt"
    cmd = ["ssh-audit", f"{target_ip}:{port}"]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        print(f" [*] ssh-audit results saved to {output_file}")
    except Exception as e:
        print(f" [!] ssh-audit failed: {e}")

def run_http_scan(target_ip, port, ip_folder):
    """Run whatweb and optional nikto for HTTP enumeration"""
    print(f" [HTTP] Running whatweb on port {port}")
    output_file = f"{ip_folder}/http_whatweb_port_{port}.txt"
    url = f"http://{target_ip}:{port}"
    cmd = ["whatweb", "-a", "3", url]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=180)
        print(f" [*] whatweb results saved to {output_file}")
    except Exception as e:
        print(f" [!] whatweb failed: {e}")
    # Optional nikto (commented out for speed)
    # print(f" [HTTP] Running nikto on port {port}")
    # nikto_cmd = ["nikto", "-h", url, "-output", f"{ip_folder}/nikto_port_{port}.txt"]
    # subprocess.run(nikto_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_https_scan(target_ip, port, ip_folder):
    """Run testssl.sh and whatweb for HTTPS"""
    print(f" [HTTPS] Running testssl.sh on port {port}")
    output_file = f"{ip_folder}/https_testssl_port_{port}.txt"
    cmd = ["testssl.sh", "--quiet", f"{target_ip}:{port}"]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        print(f" [*] testssl.sh results saved to {output_file}")
    except Exception as e:
        print(f" [!] testssl.sh failed: {e}")
    # Also run whatweb with HTTPS
    print(f" [HTTPS] Running whatweb on port {port}")
    url = f"https://{target_ip}:{port}"
    ww_file = f"{ip_folder}/https_whatweb_port_{port}.txt"
    cmd = ["whatweb", "-a", "3", url]
    try:
        with open(ww_file, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=180)
        print(f" [*] whatweb results saved to {ww_file}")
    except Exception as e:
        print(f" [!] whatweb failed: {e}")

def run_ftp_scan(target_ip, port, ip_folder):
    """FTP anonymous check using ftp client"""
    print(f" [FTP] Checking anonymous login on port {port}")
    output_file = f"{ip_folder}/ftp_anon_port_{port}.txt"
    # Simple anonymous check using netcat or ftp command
    cmd = f"echo 'quit' | ftp -n {target_ip} {port} 2>&1 | tee {output_file}"
    subprocess.run(cmd, shell=True, executable='/bin/bash')
    # Could also use nmap script as fallback, but we'll note it as limited.

def run_smb_scan(target_ip, port, ip_folder):
    """Run enum4linux for SMB enumeration"""
    print(f" [SMB] Running enum4linux on port {port}")
    output_file = f"{ip_folder}/smb_enum4linux_port_{port}.txt"
    cmd = ["enum4linux", "-a", target_ip]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=600)
        print(f" [*] enum4linux results saved to {output_file}")
    except Exception as e:
        print(f" [!] enum4linux failed: {e}")

def run_mysql_scan(target_ip, port, ip_folder):
    """MySQL enumeration using nmap scripts (no great standalone tool)"""
    print(f" [MySQL] Using Nmap scripts for enumeration on port {port}")
    scripts = "mysql-enum,mysql-info"
    run_nmap_script_scan(target_ip, port, "mysql", scripts, ip_folder)

def run_pgsql_scan(target_ip, port, ip_folder):
    """PostgreSQL using nmap script"""
    print(f" [PostgreSQL] Using Nmap script for enumeration on port {port}")
    scripts = "pgsql-brute"
    run_nmap_script_scan(target_ip, port, "pgsql", scripts, ip_folder)

def run_rdp_scan(target_ip, port, ip_folder):
    """RDP using nmap scripts"""
    print(f" [RDP] Using Nmap scripts for enumeration on port {port}")
    scripts = "rdp-enum-encryption,rdp-ntlm-info"
    run_nmap_script_scan(target_ip, port, "rdp", scripts, ip_folder)

def run_vnc_scan(target_ip, port, ip_folder):
    """VNC using nmap script"""
    print(f" [VNC] Using Nmap script for enumeration on port {port}")
    scripts = "vnc-info"
    run_nmap_script_scan(target_ip, port, "vnc", scripts, ip_folder)

def run_generic_scan(target_ip, port, service_name, ip_folder):
    """Generic service version detection using Nmap"""
    print(f" [*] Running generic Nmap version scan for {service_name} on port {port}")
    safe_name = service_name.replace('/', '_')
    output_file = f"{ip_folder}/generic_scan_{safe_name}_port_{port}.txt"
    cmd = ["nmap", "-p", port, target_ip, "-sV", "--version-intensity", "1", "-oN", output_file]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f" [*] Generic scan results saved to {output_file}")

def run_nmap_script_scan(target_ip, port, service_label, scripts, ip_folder):
    """Helper to run Nmap script scan"""
    output_file = f"{ip_folder}/{service_label}_scan_port_{port}.txt"
    cmd = ["nmap", "-p", port, target_ip, "--script", scripts, "-oN", output_file]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f" [*] {service_label.upper()} Nmap scan saved to {output_file}")

def generate_summary_report(services, ip):
    """Generate a summary report of discovered services"""
    print("\n" + "=" * 60)
    print(f" SCAN SUMMARY REPORT for {ip}")
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
    target_ip = ip
    services = analyze_scan_results(target_ip, folder_name)
    if not services:
        print(" [!] No scan results found. Please run network_scan.py first.")
        return
    generate_summary_report(services, target_ip)
    run_targeted_scans(services, target_ip, folder_name)
    print(f"\n [*] Stealthy analysis complete!")
    safe_ip = target_ip.replace('/', '_')
    print(f" [*] Check the generated .txt files in {folder_name}/{safe_ip}/ for detailed results")

if __name__ == "__main__":
    main()