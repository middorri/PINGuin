#!/usr/bin/env python3
"""
AGGRESSIVE
PINGuin - Scan Results Analyzer - Aggressive version
Analyzes network scan results and runs targeted follow-up scans
"""

import os
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import glob

ip = os.environ.get("IP")
if not ip:
    ip = input(" [?] Enter target IP: ").strip()
    if not ip:
        print(" [!] No IP provided. Exiting.")
        sys.exit(1)

ports_scan = Path("nmap_ports_scan.txt")
fname = os.environ.get("FNAME")

if fname != None:
    folder_name = fname
else:
    folder_name = f"{ip}_aggressive_results"


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


def analyze_scan_results(ip, folder_name):
    """Analyze all scan results and identify services for a specific IP"""
    print(f" [*] Analyzing scan results for {ip}...")
    
    safe_ip = ip.replace('/', '_')
    
    # Look for results in multiple possible locations
    possible_locations = [
        # IP-specific subdirectory
        f"{folder_name}/{safe_ip}",
        # Directly in folder_name (for backward compatibility or symbolic links)
        folder_name,
        # Current directory (fallback)
        "."
    ]
    
    port_scan_files = []
    
    for location in possible_locations:
        # Check for all_ports.xml
        all_ports_xml = f"{location}/all_ports.xml"
        if os.path.exists(all_ports_xml):
            port_scan_files.append(all_ports_xml)
            print(f" [*] Found scan results: {all_ports_xml}")
        
        # Check for IP-specific all_ports
        ip_all_ports_xml = f"{folder_name}/all_ports_{safe_ip}.xml"
        if os.path.exists(ip_all_ports_xml):
            port_scan_files.append(ip_all_ports_xml)
            print(f" [*] Found scan results: {ip_all_ports_xml}")
        
        # Check for nmap_output.xml
        nmap_output = f"{location}/nmap_output.xml"
        if os.path.exists(nmap_output):
            port_scan_files.append(nmap_output)
            print(f" [*] Found scan results: {nmap_output}")
        
        # Check for individual port scans
        individual_scans = glob.glob(f"{location}/nmap_port_*.xml")
        if individual_scans:
            print(f" [*] Found {len(individual_scans)} individual port scans in {location}")
            port_scan_files.extend(individual_scans)

    # Remove duplicates while preserving order
    seen = set()
    unique_files = []
    for f in port_scan_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    if not unique_files:
        print(" [!] No scan results found. Please run network_scan.py first.")
        print(f" [!] Expected files in: {folder_name}/{safe_ip}/")
        print(f" [!] Searched locations: {possible_locations}")
        return []

    all_services = []
    for xml_file in unique_files:
        print(f" [*] Parsing {xml_file}")
        services = parse_nmap_xml(xml_file)
        all_services.extend(services)

    return all_services


def run_targeted_scans(services, target_ip, folder_name):
    """Run targeted Nmap scans based on discovered services"""
    print(f" [*] Running targeted scans for {target_ip}")
    
    safe_ip = target_ip.replace('/', '_')
    ip_folder = Path(folder_name) / safe_ip
    ip_folder.mkdir(parents=True, exist_ok=True)
    
    for service in services:
        if service['state'] != 'open':
            continue
            
        port = service['port']
        service_name = service['service'].lower()
        product = service['product'].lower() if service['product'] else ""
        
        print(f" [*] Found {service_name} on port {port} ({product})")
        
        # Flexible service detection
        if any(ssh_indicator in service_name for ssh_indicator in ['ssh']):
            run_ssh_scan(target_ip, port, str(ip_folder))
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


def run_ssh_scan(target_ip, port, ip_folder):
    """Run SSH-specific scans"""
    print(f" [SSH] Running SSH scans on port {port}")
    
    # SSH security audit
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
        "-oN", f"{ip_folder}/ssh_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "SSH security audit")


def run_http_scan(target_ip, port, ip_folder):
    """Run HTTP-specific scans"""
    print(f" [HTTP] Running HTTP scans on port {port}")
    
    # Basic HTTP enumeration
    scripts = [
        "http-enum", "http-headers", "http-methods", "http-title",
        "http-server-header", "http-robots.txt"
    ]
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", ",".join(scripts),
        "-oN", f"{ip_folder}/http_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "HTTP enumeration")


def run_https_scan(target_ip, port, ip_folder):
    """Run HTTPS-specific scans"""
    print(f" [HTTPS] Running HTTPS scans on port {port}")
    
    # SSL/TLS and HTTP scans
    scripts = [
        "ssl-cert", "ssl-enum-ciphers", "http-enum", "http-headers",
        "http-methods", "http-title", "http-server-header"
    ]
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", ",".join(scripts),
        "-oN", f"{ip_folder}/https_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "HTTPS and SSL scan")


def run_ftp_scan(target_ip, port, ip_folder):
    """Run FTP-specific scans"""
    print(f" [FTP] Running FTP scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-brute",
        "-oN", f"{ip_folder}/ftp_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "FTP security audit")


def run_smb_scan(target_ip, port, ip_folder):
    """Run SMB-specific scans"""
    print(f" [SMB] Running SMB scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode",
        "-oN", f"{ip_folder}/smb_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "SMB enumeration")


def run_mysql_scan(target_ip, port, ip_folder):
    """Run MySQL-specific scans"""
    print(f" [MySQL] Running MySQL scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "mysql-enum,mysql-info,mysql-databases,mysql-users",
        "-oN", f"{ip_folder}/mysql_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "MySQL enumeration")


def run_pgsql_scan(target_ip, port, ip_folder):
    """Run PostgreSQL-specific scans"""
    print(f" [PostgreSQL] Running PostgreSQL scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "pgsql-brute",
        "-oN", f"{ip_folder}/pgsql_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "PostgreSQL scan")


def run_rdp_scan(target_ip, port, ip_folder):
    """Run RDP-specific scans"""
    print(f" [RDP] Running RDP scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "rdp-enum-encryption,rdp-ntlm-info",
        "-oN", f"{ip_folder}/rdp_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "RDP security audit")


def run_vnc_scan(target_ip, port, ip_folder):
    """Run VNC-specific scans"""
    print(f" [VNC] Running VNC scans on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "--script", "vnc-info,realvnc-auth-bypass",
        "-oN", f"{ip_folder}/vnc_scan_port_{port}.txt"
    ]
    execute_scan(cmd, "VNC security audit")


def run_generic_scan(target_ip, port, service_name, ip_folder):
    """Run generic service scan"""
    print(f" [*] Running generic scan for {service_name} on port {port}")
    
    cmd = [
        "nmap", "-p", port, target_ip,
        "-sV", "--version-all",
        "-oN", f"{ip_folder}/generic_scan_{service_name}_port_{port}.txt"
    ]
    execute_scan(cmd, f"Generic {service_name} scan")


def execute_scan(cmd, scan_type):
    """Execute a scan command with error handling"""
    print(f" [>] Running {scan_type}: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f" [√] {scan_type} completed successfully")
        else:
            print(f" [!] {scan_type} had issues: {result.stderr}")
    except subprocess.TimeoutExpired:
        print(f" [!] {scan_type} timed out")
    except Exception as e:
        print(f" [!] Error running {scan_type}: {e}")


def generate_summary_report(services, ip):
    """Generate a summary report of discovered services"""
    print("\n" + " " + "="*60)
    print(f" SCAN SUMMARY REPORT for {ip}")
    print(" " + "="*60)
    
    open_services = [s for s in services if s['state'] == 'open']
    
    if not open_services:
        print(" [!] No open services found")
        return
    
    print(f" [*] Found {len(open_services)} open services:")
    print(" " + "-" * 60)
    
    for service in open_services:
        print(f" [+] Port {service['port']}/{service['protocol']}: {service['service']}")
        if service['product']:
            print(f" [+] Product: {service['product']} {service['version']}")
        if service['extrainfo']:
            print(f" [+] Info: {service['extrainfo']}")
        print()


def main():
    """Main analyzer function"""
    target_ip = os.environ.get("IP")
    if not target_ip:
        target_ip = input(" [?] Enter target IP: ").strip()
        if not target_ip:
            print(" [!] No IP provided. Exiting.")
            return
    
    # Create main results directory if it doesn't exist
    Path(folder_name).mkdir(parents=True, exist_ok=True)
    
    print(f" [*] Starting analysis for target: {target_ip}")
    
    # Analyze existing scan results
    services = analyze_scan_results(target_ip, folder_name)
    
    if not services:
        print(" [!] No scan results found. Please run network_scan.py first.")
        safe_ip = target_ip.replace('/', '_')
        print(f" [!] Expected file: {folder_name}/{safe_ip}/all_ports.xml")
        return
    
    # Generate summary
    generate_summary_report(services, target_ip)
    
    # Run targeted scans
    run_targeted_scans(services, target_ip, folder_name)
    
    print("\n [*] Analysis complete!")
    safe_ip = target_ip.replace('/', '_')
    print(f" [*] Check the generated .txt files in {folder_name}/{safe_ip}/ for detailed results")
    

if __name__ == "__main__":
    main()