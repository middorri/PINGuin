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
import random
import requests
import time
import argparse

# Global debug flag
DEBUG = True if os.environ.get('DEBUG', 'false').lower() == 'true' else False

def debug_print(*args, **kwargs):
    """Print only when DEBUG is True."""
    if DEBUG:
        print(*args, **kwargs)

def run_cmd(cmd, **kwargs):
    """
    Run a command, always capture output.
    If DEBUG is False, suppress printing of stdout/stderr.
    Returns the subprocess.CompletedProcess object.
    """
    # Ensure capture_output and text are enabled for consistent behavior
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    result = subprocess.run(cmd, **kwargs)
    if DEBUG:
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
    return result

def shodan_scan():
    """Perform a quick Shodan scan to gather basic info about the target IP"""
    ip = os.environ.get("IP")
    if not ip:
        print(" [!] IP environment variable not set")
        return []
    try:
        host = requests.get(f"https://internetdb.shodan.io/{ip}").json()
        debug_print(host)
        return host.get("ports", [])
    except Exception as e:
        print(f" [!] Shodan scan failed: {e}")
        return []

def is_cidr_range(ip):
    """Check if the target is a CIDR range (like /24)"""
    return '/' in ip

def expand_cidr_range(cidr_range):
    """Expand a CIDR range to individual IPs"""
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        return [str(ip) for ip in network.hosts()]
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
    """Check if host is up using stealthy ping sweep. Returns True if up, False otherwise."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        xml_output = tmp.name
    nmap_path = os.environ.get("NMAP_PATH", "nmap")
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
            f"echo '{ZOMBIE_PASS}' | sudo -S {nmap_path} -sn "
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
        debug_print(f" [*] Checking if {ip} is up via zombie host...")
        result = run_cmd(nmap_cmd)

        if result.returncode != 0:
            print(f" [!] Nmap command failed: {result.stderr}")
            if os.path.exists(xml_output):
                os.remove(xml_output)
            return False

        scp_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "scp",
            "-o", "StrictHostKeyChecking=no",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}:/tmp/host_up_check.xml",
            xml_output
        ]
        result = run_cmd(scp_cmd)

        if result.returncode != 0:
            print(f" [!] Failed to copy XML from zombie: {result.stderr}")
            if os.path.exists(xml_output):
                os.remove(xml_output)
            return False

    else:
        nmap_cmd = [
            f"{nmap_path}",
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
        debug_print(f" [*] Checking if {ip} is up...")
        run_cmd(nmap_cmd)

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

def scan_single_tcp_port(ip, port, base_name, zombie=False):
    """Perform a TCP SYN scan on a single port with randomized parameters"""
    delay = random.randint(1, 10)
    data = random.randint(0, 100)
    rate = random.randint(1, 15)
    nmap_path = os.environ.get("NMAP_PATH", "nmap")
    xml_output = f"{base_name}_port_{port}.xml"
    
    if zombie:
        ZOMBIE_USER = os.environ.get('USERNAME')
        ZOMBIE_PASS = os.environ.get('PASSWORD')
        ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
        remote_xml = f"/tmp/scan_tcp_syn_port_{port}.xml"
        
        cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-tt",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
            f"echo '{ZOMBIE_PASS}' | sudo -S {nmap_path} -sS -p {port} -T1 "
            "--host-timeout 0 "
            f"--max-rate {rate} "
            f"--scan-delay {delay}s "
            "--max-retries 3 "
            f"--data-length {data} "
            f"--source-port {port} "
            "-PS21,22,23,25,53,80,110,143,443,993,995 "
            "-PA21,22,23,25,53,80,110,143,443,993,995 "
            f"-oX {remote_xml} "
            f"{ip}"
        ]
        
        debug_print(f" [*] Scanning port {port} on {ip} via zombie (delay={delay}s, data={data}, rate={rate})")
        result = run_cmd(cmd)
        if result.returncode != 0:
            print(f" [!] Zombie scan for port {port} failed: {result.stderr}")
            return None
        
        scp_cmd = [
            "sshpass", "-p", ZOMBIE_PASS,
            "scp",
            "-o", "StrictHostKeyChecking=no",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}:{remote_xml}",
            xml_output
        ]
        # Special handling for scp to show progress only in debug mode
        if DEBUG:
            process = subprocess.Popen(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                print(line, end="")
            process.wait()
            result_code = process.returncode
        else:
            result = run_cmd(scp_cmd)
            result_code = result.returncode
        
        if result_code != 0:
            print(f" [!] Failed to copy XML for port {port}")
            return None
        
        run_cmd([
            "sshpass", "-p", ZOMBIE_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{ZOMBIE_USER}@{ZOMBIE_IP}", f"rm {remote_xml}"
        ])
        
    else:
        cmd = [
            "sudo", f"{nmap_path}", "-sS", "-p", str(port), "-T1", "--host-timeout", "0",
            "--max-rate", str(rate), "--scan-delay", f"{delay}s",
            "--max-retries", "3", "--data-length", str(data),
            "--source-port", str(port),
            "-oX", xml_output, ip
        ]
        debug_print(f" [*] Scanning port {port} on {ip} (delay={delay}s, data={data}, rate={rate})")
        result = run_cmd(cmd)
        if result.returncode != 0:
            print(f" [!] Local scan for port {port} failed: {result.stderr}")
            return None
    
    return xml_output

def generate_random_chunks(start, end, chunk_size):
    ports = list(range(start, end + 1))
    random.shuffle(ports)

    return [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]


def adaptive_chunk_size(total_ports, duration):
    # inverse relation: more time = smaller chunks
    base = max(5, total_ports // 50)
    time_factor = max(1, int(duration / 60))  # scale by minutes

    chunk_size = max(5, base // time_factor)
    return chunk_size


def scan(ip, port_range, duration, base_name):
    delay = random.randint(1, 10)
    data = random.randint(0, 100)
    rate = random.randint(1, 15)
    nmap_path = os.environ.get("NMAP_PATH", "nmap")
    xml_output = f"{base_name}_ports_{port_str}.xml"
    start, end = port_range
    total_ports = end - start + 1

    chunks = adaptive_chunk_size(total_ports, duration)
    groups = generate_random_chunks(start, end, chunks)

    sleep_base = duration / max(len(groups), 1)

    print(f"[+] Total ports: {total_ports}")
    print(f"[+] Chunks: {len(groups)}")
    print(f"[+] Base sleep: {sleep_base:.2f}s")

    for i, group in enumerate(groups):
        port_str = ",".join(str(p) for p in group)

        cmd = [
            "sudo", f"{nmap_path}", "-sS", "-p", str(port_str), "-T1", "--host-timeout", "0",
            "--max-rate", str(rate), "--scan-delay", f"{delay}s",
            "--max-retries", "3", "--data-length", str(data),
            "--source-port", str(port_str.split(",")[0]),
            "-oX", xml_output, ip
        ]

        print(f"[{i+1}/{len(groups)}] Scanning {len(group)} ports")

        subprocess.run(cmd)

        jitter = random.uniform(0.5, 1.5)
        sleep_time = sleep_base * jitter

        time.sleep(sleep_time)

def run_scan_chain(ip, folder_name):
    """Run the 5-scan chain for a single IP"""
    safe_ip = ip.replace('/', '_')
    ip_folder = Path(folder_name) / safe_ip
    ip_folder.mkdir(parents=True, exist_ok=True)

    base = f"{ip_folder}/port"
    zombie_mode = os.environ.get('ZOMBIE') == 'enabled'
    service_scan_enabled = os.environ.get('SERVICE_SCAN', 'true').lower() == 'true'
    
    open_ports = shodan_scan()
    if not open_ports:
        print(" [!] No open ports found via Shodan. you can choose to scan a custom range or exit. scan/exit")
        ans = input("Option: ").strip().lower()
        if ans == "exit":
            print(" [*] Exiting.")
            sys.exit(0)
        else:
            PORT_OPTIONS = {
                "1": (1, 100),
                "2": (1, 1000),
                "3": (1, 10000),
                "4": (1, 65535)
            }

            print("Select scan range:")
            print("1. 1-100")
            print("2. 1-1000")
            print("3. 1-10000")
            print("4. 1-65535")

            choice = input("Option: ").strip()
            if choice not in PORT_OPTIONS:
                print("Invalid option")
                return

            duration = int(input("Scan duration (seconds): ").strip())

            scan(ip, PORT_OPTIONS[choice], duration, base)
        
    print(f" [*] Will scan {len(open_ports)} ports individually for {ip}")
    
    xml_files = []
    for idx, port in enumerate(open_ports, 1):
        print(f"\n [*] Port {idx}/{len(open_ports)}: {port}")
        xml_file = scan_single_tcp_port(ip, port, base, zombie=zombie_mode)
        if xml_file:
            xml_files.append(Path(xml_file))
        
        if idx < len(open_ports):
            sleep_time = random.randint(5, 30)
            print(f" [*] Sleeping {sleep_time}s before next port...")
            time.sleep(sleep_time)
    
    merged_tcp_xml = Path(f"{base}_tcp_syn_all.xml")
    if xml_files:
        debug_print(f"\n [*] Merging {len(xml_files)} TCP scan results into {merged_tcp_xml}")
        merge_all_xml_results(xml_files, merged_tcp_xml)
    else:
        print(" [!] No TCP scan results produced")
        merged_tcp_xml = None
    
    tcp_open_ports = []
    if merged_tcp_xml and merged_tcp_xml.exists():
        tcp_open_ports = get_open_ports_from_xml(merged_tcp_xml, "tcp")
    
    non_responding_ports = [p for p in open_ports if p not in tcp_open_ports]
    print(f" [*] TCP open ports: {tcp_open_ports}")
    print(f" [*] Non-responding TCP ports (will be scanned via UDP): {non_responding_ports}")
    
    udp_port_set = set(non_responding_ports)
    udp_ports = ",".join(map(str, sorted(udp_port_set)))
    
    if udp_port_set:
        print(f"\n [*] Running UDP discovery for {ip} on ports: {udp_ports}")
        sleep_time = random.randint(5, 20)
        print(f" [*] Sleeping {sleep_time}s before UDP scan...")
        time.sleep(sleep_time)
        
        nmap_path = os.environ.get("NMAP_PATH", "nmap")

        delay = random.randint(1, 10)
        rate = random.randint(1, 15)
        
        if zombie_mode:
            ZOMBIE_USER = os.environ.get('USERNAME')
            ZOMBIE_PASS = os.environ.get('PASSWORD')
            ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
            remote_udp_xml = "/tmp/scan_udp_key_ports.xml"
            local_udp_xml = f"{base}_udp_key_ports.xml"
            
            cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "ssh", "-o", "StrictHostKeyChecking=no", "-tt",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
                f"echo '{ZOMBIE_PASS}' | sudo -S {nmap_path} -sU -T1 "
                f"--max-rate {rate} --scan-delay {delay}s "
                f"-p {udp_ports} -oX {remote_udp_xml} {ip}"
            ]
            run_cmd(cmd)
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "scp", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}:{remote_udp_xml}", local_udp_xml
            ])
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", f"rm {remote_udp_xml}"
            ])
        else:
            cmd = [
                "sudo", f"{nmap_path}", "-sU", "-T1", "--max-rate", str(rate), "--scan-delay", f"{delay}s",
                "-p", udp_ports, "-oA", f"{base}_udp_key_ports", ip
            ]
            run_cmd(cmd)
    else:
        print(" [*] No UDP ports to scan (all TCP ports responded). Skipping UDP discovery.")
    
    # TCP Service Detection (only if enabled)
    if service_scan_enabled and tcp_open_ports:
        sleep_time = random.randint(5, 30)
        print(f" [*] Sleeping {sleep_time}s before TCP service detection...")
        time.sleep(sleep_time)
        
        ports_str = ",".join(map(str, tcp_open_ports))
        delay = random.randint(1, 10)
        data = random.randint(0, 100)
        rate = random.randint(1, 15)
        
        if zombie_mode:
            ZOMBIE_USER = os.environ.get('USERNAME')
            ZOMBIE_PASS = os.environ.get('PASSWORD')
            ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
            remote_svc_xml = "/tmp/scan_tcp_service_versions.xml"
            local_svc_xml = f"{base}_tcp_service_versions.xml"
            nmap_path = os.environ.get("NMAP_PATH", "nmap")

            cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "ssh", "-o", "StrictHostKeyChecking=no", "-tt",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
                f"echo '{ZOMBIE_PASS}' | sudo -S {nmap_path} -sS -T1 "
                f"--max-rate {rate} --scan-delay {delay}s "
                "-sV --version-intensity 5 "
                f"--data-length {data} -p {ports_str} -oX {remote_svc_xml} {ip}"
            ]
            run_cmd(cmd)
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "scp", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}:{remote_svc_xml}", local_svc_xml
            ])
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", f"rm {remote_svc_xml}"
            ])
        else:
            cmd = [
                "sudo", f"{nmap_path}", "-sS", "-T1", "--max-rate", str(rate), "--scan-delay", f"{delay}s",
                "-sV", "--version-intensity", "5", "--data-length", str(data),
                "-p", ports_str, "-oA", f"{base}_tcp_service_versions", ip
            ]
            run_cmd(cmd)
    elif not service_scan_enabled:
        print(" [*] Service scan disabled. Skipping TCP service detection.")
    else:
        print(" [*] No open TCP ports for service detection.")
    
    # UDP Service Detection (only if enabled)
    udp_xml = Path(f"{base}_udp_key_ports.xml")
    udp_open_ports = get_open_ports_from_xml(udp_xml, "udp") if udp_xml.exists() else []
    
    if service_scan_enabled and udp_open_ports:
        sleep_time = random.randint(5, 30)
        print(f" [*] Sleeping {sleep_time}s before UDP service detection...")
        time.sleep(sleep_time)
        
        ports_str = ",".join(map(str, udp_open_ports))
        delay = random.randint(1, 10)
        data = random.randint(0, 100)
        rate = random.randint(1, 15)
        
        if zombie_mode:
            ZOMBIE_USER = os.environ.get('USERNAME')
            ZOMBIE_PASS = os.environ.get('PASSWORD')
            ZOMBIE_IP = os.environ.get('ZOMBIE_IP')
            remote_udpsvc_xml = "/tmp/scan_udp_service_versions.xml"
            local_udpsvc_xml = f"{base}_udp_service_versions.xml"
            cmd = [
                "sshpass", "-p", ZOMBIE_PASS,
                "ssh", "-o", "StrictHostKeyChecking=no", "-tt",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", "cd /tmp &&",
                f"echo '{ZOMBIE_PASS}' | sudo -S {nmap_path} -sU -T0 "
                f"--max-rate {rate} --scan-delay {delay}s "
                "-sV --version-intensity 1 -sC "
                f"-p {ports_str} -oX {remote_udpsvc_xml} {ip}"
            ]
            run_cmd(cmd)
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "scp", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}:{remote_udpsvc_xml}", local_udpsvc_xml
            ])
            run_cmd([
                "sshpass", "-p", ZOMBIE_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{ZOMBIE_USER}@{ZOMBIE_IP}", f"rm {remote_udpsvc_xml}"
            ])
        else:
            cmd = [
                "sudo", f"{nmap_path}", "-sU", "-T0", "--max-rate", str(rate), "--scan-delay", f"{delay}s",
                "-sV", "--version-intensity", "1", "-sC", "-p", ports_str,
                "-oA", f"{base}_udp_service_versions", ip
            ]
            run_cmd(cmd)
    elif not service_scan_enabled:
        print(" [*] Service scan disabled. Skipping UDP service detection.")
    else:
        print(" [*] No open UDP ports for service detection.")
    
    # Merge all final results
    print(f"\n [*] Merging all scan results for {ip}...")
    all_xml_files = [
        Path(f"{base}_tcp_syn_all.xml"),
        Path(f"{base}_tcp_service_versions.xml") if tcp_open_ports and service_scan_enabled else None,
        Path(f"{base}_udp_key_ports.xml") if udp_port_set else None,
        Path(f"{base}_udp_service_versions.xml") if udp_open_ports and service_scan_enabled else None
    ]
    existing_xml_files = [xml for xml in all_xml_files if xml and xml.exists()]
    
    if existing_xml_files:
        merged_xml = ip_folder / "merged_results.xml"
        success = merge_all_xml_results(existing_xml_files, merged_xml)
        if success:
            main_merged_xml = Path(folder_name) / f"merged_results_{safe_ip}.xml"
            try:
                if main_merged_xml.exists():
                    main_merged_xml.unlink()
                main_merged_xml.symlink_to(merged_xml)
            except:
                pass
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
                if merged_root is None:
                    merged_root = ET.Element(root.tag, root.attrib)
                    for child in root:
                        if not child.tag.endswith("host"):
                            merged_root.append(child)
                for host in root.findall("host"):
                    address_elem = host.find("address")
                    if address_elem is None:
                        continue
                    host_addr = address_elem.get("addr")
                    if not host_addr:
                        continue
                    if host_addr not in all_hosts:
                        all_hosts[host_addr] = host
                    else:
                        merge_host_ports(all_hosts[host_addr], host)
            except ET.ParseError as e:
                print(f" [!] Failed to parse {xml_file}: {e}")
                continue
        if merged_root is not None:
            for host in all_hosts.values():
                merged_root.append(host)
        else:
            return False
        merged_tree = ET.ElementTree(merged_root)
        merged_tree.write(str(output_path), encoding="utf-8", xml_declaration=True)
        debug_print(f" [*] Merged {len(all_hosts)} unique hosts into {output_path}")
        return True
    except Exception as e:
        print(f" [!] Error merging XML files: {e}")
        return False

def merge_host_ports(existing_host, new_host):
    """Merge ports from new_host into existing_host, avoiding duplicates"""
    existing_ports = {}
    for port in existing_host.findall(".//port"):
        protocol = port.get("protocol")
        portid = port.get("portid")
        if protocol and portid:
            existing_ports[f"{protocol}/{portid}"] = port
    for port in new_host.findall(".//port"):
        protocol = port.get("protocol")
        portid = port.get("portid")
        if protocol and portid:
            port_key = f"{protocol}/{portid}"
            if port_key not in existing_ports:
                ports_elem = existing_host.find("ports")
                if ports_elem is not None:
                    ports_elem.append(port)
                else:
                    ports_elem = ET.SubElement(existing_host, "ports")
                    ports_elem.append(port)

def scan_single_ip(ip, folder_name):
    """Perform comprehensive scan on a single IP"""
    print(f"\n [*] Starting comprehensive 5-scan chain for {ip}")
    print(" [*] Scan chain: Host Up Check → TCP SYN Discovery (per‑port) → TCP Service Detection → UDP Discovery → UDP Service Detection")
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
    global DEBUG
    DEBUG = os.environ.get('DEBUG')

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
        safe_name = ip.replace('/', '_')
        folder_name = f"{safe_name}_results"

    Path(folder_name).mkdir(parents=True, exist_ok=True)

    perform_host_check = os.environ.get('HOST_CHECK', 'true').lower() == 'true'

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
            if perform_host_check:
                if is_host_up(target_ip):
                    print(" [*] Host is up. Proceeding with scan.")
                    scan_single_ip(target_ip, folder_name)
                else:
                    print(f" [!] Host {target_ip} appears to be down. Going to next IP.")
                    continue
            else:
                print(" [*] Skipping host up check as per configuration.")
                scan_single_ip(target_ip, folder_name)
        print(f"\n [*] Completed scanning all IPs in range {ip}")
        print(f" [*] Results are in: {folder_name}/")
    else:
        print(f" [*] Scanning single IP: {ip}")
        if perform_host_check:
            if is_host_up(ip):
                print(" [*] Host is up. Proceeding with scan.")
                scan_single_ip(ip, folder_name)
            else:
                print(f" [!] Host {ip} appears to be down. Exiting.")
                sys.exit(1)
        else:
            print(" [*] Skipping host up check as per configuration.")
            scan_single_ip(ip, folder_name)

if __name__ == "__main__":
    main()