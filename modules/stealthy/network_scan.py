#!/usr/bin/env python3
"""
PINGuin - Stealthy Network Scanner
Comprehensive 4-scan chain with stealth optimization
Handles both single IP and CIDR ranges
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
import ipaddress
import tempfile

def is_cidr_range(ip):
    """Check if the target is a CIDR range (like /24)"""
    return '/' in ip

def expand_cidr_range(cidr_range):
    """Expand a CIDR range to individual IPs"""
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        return [str(ip) for ip in network.hosts()]  # Exclude network and broadcast addresses
    except ValueError as e:
        print(f" [!] Invalid CIDR range: {e}")
        return []

def get_open_ports_from_xml(xml_file, protocol):
    """Extract open ports from XML results for a specific protocol"""
    open_ports = []
    try:
        if not xml_file.exists():
            return []
            
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                state_elem = port.find("state")
                if state_elem is None:
                    continue
                state = state_elem.get("state")
                port_protocol = port.get("protocol")
                portid = port.get("portid")
                
                if port_protocol == protocol and state == "open" and portid:
                    try:
                        open_ports.append(int(portid))
                    except ValueError:
                        continue
                        
        return sorted(set(open_ports))
    except Exception as e:
        print(f" [!] Error parsing {xml_file}: {e}")
        return []

def is_host_up(ip):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        xml_output = tmp.name
    
    if os.environ.get('ZOMBIE') == 'enabled':
        ZOMBIE_USER = os.environ.get('USERNAME')
        ZOMBIE_PASS = os.environ.get('PASSWORD')
        ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
        nmap_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-tt",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
            f"echo '{ZOMBIE_PASS}' | sudo -S nmap -sn "
            "-PE -PP -PM "
            "-PS21,22,25,53,80,443 "
            "-PA80,443,53 "
            "-PU53,123,161 "
            "-T1 "
            "--max-retries 2 "
            "--host-timeout 5m "
            f"-oX /tmp/host_up_check.xml "
            f"{ip}"
        ]
        print(f" [*] Checking if {ip} is up via zombie host...")
    else:
        nmap_cmd = [
            "nmap",
            "-sn",
            "-PE", "-PP", "-PM",
            "-PS21,22,25,53,80,443",
            "-PA80,443,53",
            "-PU53,123,161",
            "-T1",
            "--max-retries", "2",
            "--host-timeout", "5m",
            "-oX", xml_output,
            ip
        ]
        print(f" [*] Checking if {ip} is up...")
    subprocess.run(nmap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        tree = ET.parse(xml_output)
        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                return True

        return False
    except ET.ParseError as e:
        print(f" [!] Failed to parse XML for {ip}: {e}")
        return False
    finally:
        if os.path.exists(xml_output):
            os.remove(xml_output)

def run_scan_chain(ip, folder_name):
    """Run the 5-scan chain for a single IP"""
    # Create IP-specific subfolder
    safe_ip = ip.replace('/', '_')
    ip_folder = Path(folder_name) / safe_ip
    ip_folder.mkdir(parents=True, exist_ok=True)
    
    base = f"{ip_folder}"

    # Prepare zombie SSH command if enabled
    if os.environ.get('ZOMBIE') == 'enabled':
        ZOMBIE_USER = os.environ.get('USERNAME')
        ZOMBIE_PASS = os.environ.get('PASSWORD')
        ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
        ssh_command = f"sshpass -p '{ZOMBIE_PASS}' ssh -o BatchMode=yes {ZOMBIE_USER}@{ZOMBIE_IP} && sudo su && "

    # Command 1: Initial TCP SYN Discovery
    if os.environ.get('ZOMBIE') == 'enabled':
        scan1_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-tt",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
            f"echo '{ZOMBIE_PASS}' | sudo -S nmap -sS -p- -T2 "
            "--host-timeout 0 "
            "--max-rate 100 "
            "--scan-delay 500ms "
            "--max-retries 3 "
            "-f "
            "--data-length 24 "
            "--source-port 53 "
            "-PS21,22,23,25,53,80,110,143,443,993,995 "
            "-PA21,22,23,25,53,80,110,143,443,993,995 "
            f"-oA /tmp/scan_tcp_syn_all "
            f"{ip}"
        ]
        scp1_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "scp",
            "-o", "StrictHostKeyChecking=no",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}:/tmp/scan_tcp_syn_all.*",
            f"{base}/"
        ]
    else:
        scan1_cmd = [
            "nmap", "-sS", "-p-", "-T2", "--host-timeout", "0", "--max-rate", "100", "--scan-delay", "500ms", 
            "--max-retries", "3", "-f", "--data-length", "24", "--source-port", "53",
            "-PS21,22,23,25,53,80,110,143,443,993,995", 
            "-PA21,22,23,25,53,80,110,143,443,993,995",
            "-oA", f"{base}_tcp_syn_all", ip
        ]
    
    # Command 2: TCP Service Detection (will be built after scan1)
    # Command 3: UDP Discovery (Common Services)
    if os.environ.get('ZOMBIE') == 'enabled':
        scan3_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-tt",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
            f"echo '{ZOMBIE_PASS}' | sudo -S nmap -sU -T1 "
            "--max-rate 10 "
            "--scan-delay 2s "
            "-p 53,67,68,69,123,135,137,138,139,161,162,445,500,514,631,1434,1701,1900,1812,1813,4500,5353,11211,27015,47808,49152 "
            f"-oA {base}_udp_key_ports "
            f"{ip}"
        ]
        scp3_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "scp",
            "-o", "StrictHostKeyChecking=no",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}:/tmp/scan_udp_key_ports.*",
            f"{base}/"
        ]
    else:
        scan3_cmd = [
            "nmap", "-sU", "-T1",
            "--max-rate", "10",
            "--scan-delay", "2s",
            "-p", "53,67,68,69,123,135,137,138,139,161,162,445,500,514,631,1434,1701,1900,1812,1813,4500,5353,11211,27015,47808,49152",
            "-oA", f"{base}_udp_key_ports",
            ip
        ]

    if os.environ.get('ZOMBIE') == 'enabled':
        scan_definitions = [
            {"name": "tcp_syn_discovery", "cmd": scan1_cmd, "xml": f"{base}_tcp_syn_all.xml"},
            {"name": "tcp_scp_local_save", "cmd": scp1_cmd},
            {"name": "udp_discovery", "cmd": scan3_cmd, "xml": f"{base}_udp_key_ports.xml"},
            {"name": "udp_scp_local_save", "cmd": scp3_cmd}
        ]
    else:
        scan_definitions = [
            {"name": "tcp_syn_discovery", "cmd": scan1_cmd, "xml": f"{base}_tcp_syn_all.xml"},
            {"name": "udp_discovery", "cmd": scan3_cmd, "xml": f"{base}_udp_key_ports.xml"}
        ]

    # Use sudo only if needed and available
    try:
        if os.environ.get('ZOMBIE') != 'enabled':
            for scan in scan_definitions:
                scan["cmd"].insert(0, "sudo")
            print(f" [*] Using sudo for raw socket privileges for {ip}")
    except:
        print(f" [*] Running without sudo for {ip} (some scan types may be limited)")

    # Run initial scans
    for scan in scan_definitions:
        print(f"\n [*] Running {scan['name']} for {ip}")
        print(f" [CMD]: {' '.join(scan['cmd'])}")
        
        try:
            proc = subprocess.Popen(scan["cmd"], stdout=subprocess.PIPE, 
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)

            # Stream output in real time
            if proc.stdout:
                for line in proc.stdout:
                    print(f" [{ip} {scan['name']}] {line.rstrip()}")

            rc = proc.wait()
            if rc != 0:
                print(f" [!] {scan['name']} for {ip} exited with return code {rc}")
            else:
                print(f" [*] {scan['name']} for {ip} finished successfully")

        except Exception as e:
            print(f" [!] Error during {scan['name']} for {ip}: {e}")
            continue

    # Get open TCP ports from scan1 results
    tcp_xml = Path(f"{base}/scan_tcp_syn_all.xml")
    tcp_open_ports = get_open_ports_from_xml(tcp_xml, "tcp")
    
    # Command 2: TCP Service Detection (only if we found open ports)
    if tcp_open_ports:
        ports_str = ",".join(map(str, tcp_open_ports))
        if os.environ.get('ZOMBIE') == 'enabled':
            scan2_cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-tt",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
                f"echo '{ZOMBIE_PASS}' | sudo -S nmap -sS -T1 "
                "--max-rate 50 "
                "--scan-delay 1s "
                "-sV "
                "--version-intensity 5 "
                "-f "
                "--data-length 24 "
                f"-p {ports_str} "
                f"-oA /tmp/scan_tcp_service_versions "
                f"{ip}"
            ]
            scp2_cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "scp",
                "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}:/tmp/scan_tcp_service_versions.*",
                f"{base}/"
            ]
        else:
            scan2_cmd = [
                "nmap", "-sS", "-T1", "--max-rate", "50", "--scan-delay", "1s",
                "-sV", "--version-intensity", "5", "-f", "--data-length", "24",
                "-p", ports_str, "-oA", f"{base}_tcp_service_versions", ip
            ]
        
        # Add sudo if needed
        if os.environ.get('ZOMBIE') != 'enabled':
            if "sudo" in scan_definitions[0]["cmd"]:
                scan2_cmd.insert(0, "sudo")
            
        print(f"\n [*] Running TCP service detection for {ip} on ports: {ports_str}")
        print(f" [CMD]: {' '.join(scan2_cmd)}")
        
        try:
            proc = subprocess.Popen(scan2_cmd, stdout=subprocess.PIPE, 
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
            subprocess.run(scp2_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if proc.stdout:
                for line in proc.stdout:
                    print(f" [{ip} tcp_service] {line.rstrip()}")

            rc = proc.wait()
            if rc != 0:
                print(f" [!] TCP service detection for {ip} exited with return code {rc}")
            else:
                print(f" [*] TCP service detection for {ip} finished successfully")
        except Exception as e:
            print(f" [!] Error during TCP service detection for {ip}: {e}")

    # Get open UDP ports from scan3 results  
    udp_xml = Path(f"{base}/scan_udp_key_ports.xml")
    udp_open_ports = get_open_ports_from_xml(udp_xml, "udp")
    
    # Command 4: UDP Service Detection (only if we found open ports)
    if udp_open_ports:
        ports_str = ",".join(map(str, udp_open_ports))
        if os.environ.get('ZOMBIE') == 'enabled':
            scan4_cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-tt",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
                f"echo '{ZOMBIE_PASS}' | sudo -S nmap -sU -T0 "
                "--max-rate 5 "
                "--scan-delay 3s "
                "-sV "
                "--version-intensity 3 "
                "-sC "
                f"-p {ports_str} "
                f"-oA /tmp/scan_udp_service_versions "
                f"{ip}"
            ]
            scp4_cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "scp",
                "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}:/tmp/scan_udp_service_versions.*",
                f"{base}/"
            ]
        else:
            scan4_cmd = [
                "nmap", "-sU", "-T0", "--max-rate", "5", "--scan-delay", "3s",
                "-sV", "--version-intensity", "3", "-sC", "-p", ports_str,
                "-oA", f"{base}_udp_service_versions", ip
            ]
        
        # Add sudo if needed
        if os.environ.get('ZOMBIE') != 'enabled':
            if "sudo" in scan_definitions[0]["cmd"]:
                scan4_cmd.insert(0, "sudo")
            
        print(f"\n [*] Running UDP service detection for {ip} on ports: {ports_str}")
        print(f" [CMD]: {' '.join(scan4_cmd)}")
        
        try:
            proc = subprocess.Popen(scan4_cmd, stdout=subprocess.PIPE, 
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)

            subprocess.run(scp4_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if proc.stdout:
                for line in proc.stdout:
                    print(f" [{ip} udp_service] {line.rstrip()}")

            rc = proc.wait()
            if rc != 0:
                print(f" [!] UDP service detection for {ip} exited with return code {rc}")
            else:
                print(f" [*] UDP service detection for {ip} finished successfully")
        except Exception as e:
            print(f" [!] Error during UDP service detection for {ip}: {e}")

    # Merge all XML results for this IP
    print(f"\n [*] Merging scan results for {ip}...")
    all_xml_files = [
        Path(f"{base}_tcp_syn_all.xml"),
        Path(f"{base}_tcp_service_versions.xml") if tcp_open_ports else None,
        Path(f"{base}_udp_key_ports.xml"),
        Path(f"{base}_udp_service_versions.xml") if udp_open_ports else None
    ]
    
    # Only include files that actually exist
    existing_xml_files = [xml for xml in all_xml_files if xml and xml.exists()]
    
    if existing_xml_files:
        merged_xml = ip_folder / "merged_results.xml"
        success = merge_all_xml_results(existing_xml_files, merged_xml)
        
        if success:
            # Also create a symbolic link in the main folder for backward compatibility
            main_merged_xml = Path(folder_name) / f"merged_results_{safe_ip}.xml"
            try:
                if main_merged_xml.exists():
                    main_merged_xml.unlink()
                main_merged_xml.symlink_to(merged_xml)
            except:
                pass  # If symlink fails, just continue
            
            print(f" [*] All scans for {ip} completed and merged into {merged_xml}")
            return True
        else:
            print(f" [!] Failed to merge scan results for {ip}")
            return False
    else:
        print(f" [!] No scan results were produced for {ip}")
        return False

def merge_all_xml_results(xml_files, output_path):
    """Merge multiple XML scan results into one, removing duplicates"""
    try:
        merged_root = None
        all_hosts = {}
        
        for xml_file in xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                # Initialize merged_root from first file if not set
                if merged_root is None:
                    merged_root = ET.Element(root.tag, root.attrib)
                    # Copy non-host elements from first file
                    for child in root:
                        if not child.tag.endswith("host"):
                            merged_root.append(child)
                
                # Process all hosts in this file
                for host in root.findall("host"):
                    # Get host address
                    address_elem = host.find("address")
                    if address_elem is None:
                        continue
                    host_addr = address_elem.get("addr")
                    if not host_addr:
                        continue
                    
                    # If we haven't seen this host, add it directly
                    if host_addr not in all_hosts:
                        all_hosts[host_addr] = host
                    else:
                        # Merge ports from duplicate host
                        existing_host = all_hosts[host_addr]
                        merge_host_ports(existing_host, host)
                        
            except ET.ParseError as e:
                print(f" [!] Failed to parse {xml_file}: {e}")
                continue
        
        # Add all unique hosts to merged root
        if merged_root is not None:
            for host in all_hosts.values():
                merged_root.append(host)
        else:
            print(" [!] Failed to initialize merged_root")
            return False
        
        # Write merged XML
        merged_tree = ET.ElementTree(merged_root)
        merged_tree.write(str(output_path), encoding="utf-8", xml_declaration=True)
        print(f" [*] Merged {len(all_hosts)} unique hosts into {output_path}")
        return True
        
    except Exception as e:
        print(f" [!] Error merging XML files: {e}")
        return False

def merge_host_ports(existing_host, new_host):
    """Merge ports from new_host into existing_host, avoiding duplicates"""
    existing_ports = {}
    
    # Get all existing ports
    for port in existing_host.findall(".//port"):
        protocol = port.get("protocol")
        portid = port.get("portid")
        if protocol and portid:
            existing_ports[f"{protocol}/{portid}"] = port
    
    # Add new ports that don't exist
    for port in new_host.findall(".//port"):
        protocol = port.get("protocol")
        portid = port.get("portid")
        if protocol and portid:
            port_key = f"{protocol}/{portid}"
            if port_key not in existing_ports:
                # Find the ports element and append new port
                ports_elem = existing_host.find("ports")
                if ports_elem is not None:
                    ports_elem.append(port)
                else:
                    # Create ports element if it doesn't exist
                    ports_elem = ET.SubElement(existing_host, "ports")
                    ports_elem.append(port)

def scan_single_ip(ip, folder_name):
    """Perform comprehensive scan on a single IP"""
    print(f"\n [*] Starting comprehensive 5-scan chain for {ip}")
    print(" [*] Scan chain: Host Up Check → TCP SYN Discovery → TCP Service Detection → UDP Discovery → UDP Service Detection")
    print(" [*] Note: This will take significant time due to stealth settings")
    
    success = run_scan_chain(ip, folder_name)
    
    if success:
        print(f" [*] Comprehensive scan for {ip} completed successfully")
        return True
    else:
        print(f" [!] Comprehensive scan for {ip} failed")
        return False

def main():
    """Main function that handles both single IP and CIDR ranges"""
    ip = os.environ.get("IP")
    if not ip:
        ip = input(" [?] Enter target IP or CIDR (e.g., 192.168.1.0/24): ").strip()
        if not ip:
            print(" [!] No IP provided. Exiting.")
            sys.exit(1)

    fname = os.environ.get("FNAME")
    if fname:
        folder_name = fname
    else:
        # Create a safe folder name from the IP/CIDR
        safe_name = ip.replace('/', '_')
        folder_name = f"{safe_name}_results"

    # Create main results directory
    Path(folder_name).mkdir(parents=True, exist_ok=True)

    if is_cidr_range(ip):
        print(f" [*] CIDR range detected: {ip}")
        ip_list = expand_cidr_range(ip)
        
        if not ip_list:
            print(" [!] No valid IPs to scan. Exiting.")
            return
            
        print(f" [*] Expanded to {len(ip_list)} IP addresses")
        print(f" [*] Results will be stored in: {folder_name}/")
        print(" [*] WARNING: This will take a VERY long time (days) for a /24 range!")
        
        for i, target_ip in enumerate(ip_list, 1):
            print(f"\n [*] Scanning IP {i}/{len(ip_list)}: {target_ip}")
            if is_host_up(target_ip):
                print(" [*] Host is up. Proceeding with scan.")
                scan_single_ip(target_ip, folder_name)
            else:
                print(f" [!] Host {target_ip} appears to be down. Going to next IP.")
                continue

        print(f"\n [*] Completed scanning all IPs in range {ip}")
        print(f" [*] Results are in: {folder_name}/")
        
    else:
        # Single IP scan
        print(f" [*] Scanning single IP: {ip}")
        if is_host_up(ip):
            print(" [*] Host is up. Proceeding with scan.")
            scan_single_ip(ip, folder_name)
        else:
            print(f" [!] Host {ip} appears to be down. Exiting.")
            sys.exit(1)

if __name__ == "__main__":
    main()