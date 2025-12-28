#!/usr/bin/env python3
"""
PINGuin - Aggressive Network Scanner
Parallel nmap scanning optimized for speed and coverage
Handles both single IP and CIDR ranges
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import shutil
import sys
from datetime import datetime
import ipaddress

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

def scan_single_ip(ip, folder_name):
    """Perform network scan on a single IP"""
    print(f"\n [*] Scanning IP: {ip}")
    
    # Create IP-specific subfolder
    folder_path = Path(folder_name)
    folder_path.mkdir(parents=True, exist_ok=True)
    
    ports_scan = folder_path / f"nmap_ports_scan_{ip.replace('/', '_')}.txt"
    XML_OUT = folder_path / f"nmap_output_{ip.replace('/', '_')}.xml"
    
    # Aggressive nmap command
    nmap_cmd = ["sudo", "nmap", "-T4", "-sS", "--open", "-oX", str(XML_OUT), ip]

    print(f" [CMD]: {' '.join(nmap_cmd)}")
    # Merge stderr into stdout to avoid blocking on separate pipes
    proc = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    # Stream output in real time
    if proc.stdout:
        for line in proc.stdout:
            print(f" [{ip}] {line.rstrip()}")

    # Wait for process to finish
    rc = proc.wait()
    if rc != 0:
        print(f" [!] Nmap scan for {ip} exited with return code {rc}. Check {XML_OUT} and nmap output.", file=sys.stderr)
        # Still attempt to parse the XML file if it exists
    else:
        print(f" [*] Nmap finished successfully for {ip}")

    # Check XML exists and parse it
    if not XML_OUT.exists():
        print(f" [!] XML output file not found for {ip}. Nmap may have failed to write the XML.", file=sys.stderr)
        return

    try:
        tree = ET.parse(XML_OUT)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f" [!] Failed to parse XML for {ip}: {e}", file=sys.stderr)
        # Optionally dump the beginning of the file for debugging
        if XML_OUT.exists():
            head = XML_OUT.read_text()[:1000]
            print(f" [!] XML head for {ip} (first 1000 chars):\n", head)
        return

    open_ports = []
    for host in root.findall(".//host"):
        for port in host.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None:
                continue
            state = state_elem.get("state")
            protocol = port.get("protocol")
            portid = port.get("portid")
            if protocol == "tcp" and state == "open" and portid:
                try:
                    open_ports.append(int(portid))
                except ValueError:
                    continue
    open_ports = sorted(set(open_ports))

    print(f" [*] Found {len(open_ports)} open TCP port(s) on {ip}: {open_ports}")

    # Prepare a combined root for all_ports.xml (will hold combined <host> entries)
    combined_root = None
    combined_path = ip_folder / "all_ports.xml"

    # Run nmap for each open port and merge results into all_ports.xml
    if open_ports:
        print(f" [*] Starting service/version scans on {len(open_ports)} ports for {ip}...")
        for port in open_ports:
            nmap_out = ip_folder / f"nmap_port_{port}.xml"
            nmap_2_cmd = ["sudo", "nmap", "-sV", "-p", str(port), "-oX", str(nmap_out), ip]
            print(f" [NMAP] {ip} Port {port}: ", end="", flush=True)

            try:
                proc = subprocess.run(nmap_2_cmd, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except subprocess.TimeoutExpired:
                print("NMAP TIMEOUT")
                with open(ports_scan, "a") as f:
                    f.write(f"Port {port}:\n  NMAP TIMEOUT\n\n" + "-" * 30 + "\n\n")
                continue

            # If nmap returned non-zero, log and continue (but still try to parse file if present)
            if proc.returncode != 0:
                print(f"NMAP exit {proc.returncode} (see stderr)")
                with open(ports_scan, "a") as f:
                    f.write(f"Port {port}:\n  NMAP exit {proc.returncode}\n  STDERR:\n{proc.stderr}\n\n" + "-" * 30 + "\n\n")
                # continue to parse the XML if it was created
            else:
                print("OK")

            # If the per-port xml doesn't exist, skip merging
            if not nmap_out.exists():
                print(f" [!] Missing XML {nmap_out}, skipping merge for port {port}")
                continue

            # Parse the per-port XML
            try:
                tree_port = ET.parse(nmap_out)
                root_port = tree_port.getroot()
            except ET.ParseError as e:
                print(f" [!] Failed to parse {nmap_out}: {e}")
                with open(ports_scan, "a") as f:
                    f.write(f"Port {port}:\n  FAILED TO PARSE XML: {e}\n\n")
                continue

            # Initialize combined_root from the first parsed file if not set
            if combined_root is None:
                # Use a shallow copy of the root_port as the combined root, but remove existing <host> children
                combined_root = ET.Element(root_port.tag, root_port.attrib)
                # copy over (non-host) children like <scaninfo>, <verbose> etc to keep metadata if present
                for child in root_port:
                    if child.tag.endswith("host"):
                        continue
                    combined_root.append(child)

            # Append all <host> children from this per-port result into combined_root
            for host in root_port.findall(".//host"):
                # ElementTree append will move/copy the element; to be safe create a deep copy
                combined_root.append(host)

            # Write out the combined XML after each merge so the file is always up-to-date
            try:
                combined_tree = ET.ElementTree(combined_root)
                combined_tree.write(str(combined_path), encoding="utf-8", xml_declaration=True)
                print(f" [*] Merged results for {ip} written to {combined_path}")
            except Exception as e:
                print(f" [!] Failed to write combined XML for {ip}: {e}")
                with open(ports_scan, "a") as f:
                    f.write(f"Port {port}:\n  FAILED TO WRITE combined XML: {e}\n\n")
    else:
        print(f" [!] No open TCP ports found on {ip} for service/version scanning")

def main():
    """Main function that handles both single IP and CIDR ranges"""
    ip = os.environ.get("IP")
    if not ip:
        ip = input(" [?] Enter target IP or CIDR (e.g., 192.168.1.0/24): ").strip()
        if not ip:
            print(" [!] No IP provided. Exiting.")
            sys.exit(1)

    fname = os.environ.get("FNAME")
    
    if fname != None:
        folder_name = fname
    else:
        # Create a safe folder name from the IP/CIDR
        safe_name = ip.replace('/', '_')
        folder_name = f"{safe_name}_aggressive_results"

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
        
        for target_ip in ip_list:
            scan_single_ip(target_ip, folder_name)
            
        print(f"\n [*] Completed scanning all IPs in range {ip}")
        print(f" [*] Results are in: {folder_name}/")
        
    else:
        # Single IP scan
        print(f" [*] Scanning single IP: {ip}")
        scan_single_ip(ip, folder_name)

if __name__ == "__main__":
    main()
