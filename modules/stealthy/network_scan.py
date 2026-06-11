#!/usr/bin/env python3
"""
PINGuin - Ultra Stealthy Network Scanner with Full Decoy Support
- Every probe (TCP SYN, TCP connect, UDP, ICMP) is duplicated from decoy IPs.
- Realistic packet crafting: TCP timestamps, random options, OS-like fingerprints.
- Lognormal/Pareto delays, background noise, and decoy flags for nmap.
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
import select
import shutil
import socket
import struct
import threading
import math

# ---------------------------
# Global flags & config
# ---------------------------
DEBUG = True if os.environ.get('DEBUG', 'false').lower() == 'true' else False

_WINDOWS_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]

# Decoy IPs – read from env or generate random public IPs
DECOY_IPS = []
ENABLE_DECOYS = False
CAN_RAW_SOCKET = False

def init_decoy_config():
    global DECOY_IPS, ENABLE_DECOYS, CAN_RAW_SOCKET
    if sys.platform.startswith('linux') and os.geteuid() == 0:
        CAN_RAW_SOCKET = True
    enable_env = os.environ.get('ENABLE_DECOYS', 'true').lower()
    ENABLE_DECOYS = (enable_env == 'true') and CAN_RAW_SOCKET
    if not ENABLE_DECOYS and enable_env == 'true':
        print(" [!] Decoys requested but not available (need Linux + root). Disabling.")
    decoy_str = os.environ.get('DECOY_IPS', '')
    if decoy_str:
        DECOY_IPS = [ip.strip() for ip in decoy_str.split(',') if ip.strip()]
    else:
        # Realistic decoy IPs: mix of cloud providers, CDNs, and random public IPs
        public_ranges = [
            "1.1.1.", "8.8.8.", "9.9.9.", "4.4.4.", "208.67.222.", "77.88.8.",
            "91.239.100.", "185.228.168.", "94.140.14.", "76.76.19.",
            "13.107.21.", "20.42.73.", "34.120.192.", "52.95.145.", "3.64.163."
        ]
        for _ in range(4):
            base = random.choice(public_ranges)
            last = random.randint(1, 254)
            DECOY_IPS.append(base + str(last))
    if ENABLE_DECOYS:
        print(f" [*] Decoy mode ENABLED with {len(DECOY_IPS)} IPs: {', '.join(DECOY_IPS)}")
    else:
        print(" [*] Decoy mode DISABLED.")

# ---------------------------
# Stealth helpers: realistic user agents, paths, domains
# ---------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]

HTTP_PATHS = [
    "/favicon.ico", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-content/themes/twentytwenty/style.css", "/js/main.js", "/css/app.css",
    "/api/health", "/images/logo.png", "/index.html", "/about", "/contact",
    "/products", "/services", "/blog", "/wp-json/", "/.env", "/config",
]

TOP_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "amazon.com", "wikipedia.org", "reddit.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "netflix.com", "stackoverflow.com", "cnn.com"
]

CIPHER_SUITES = [
    0x1301, 0x1302, 0x1303,  # TLS 1.3
    0xC02B, 0xC02F, 0xC02C, 0xC030,  # ECDHE + AES GCM
    0xCCA9, 0xCCA8, 0xCCAA,          # ECDHE + CHACHA20
    0xC009, 0xC013, 0xC014,          # RSA + AES
]

def random_domain():
    return random.choice(TOP_DOMAINS)

def http_probe(host="example.com", path=None):
    if path is None:
        path = random.choice(HTTP_PATHS)
    ua = random.choice(USER_AGENTS)
    method = random.choice(["GET", "HEAD", "POST"])
    headers = {
        "Host": host,
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.5", "fr,en;q=0.7", "de,en;q=0.7"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["max-age=0", "no-cache", "no-store"]),
    }
    if random.random() < 0.3:
        headers["Referer"] = f"https://{random_domain()}/"
    if method == "POST" and random.random() < 0.2:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = "foo=bar&baz=qux"
        headers["Content-Length"] = str(len(body))
    else:
        body = ""
    header_items = list(headers.items())
    random.shuffle(header_items)
    request = f"{method} {path} HTTP/1.1\r\n"
    for k, v in header_items:
        request += f"{k}: {v}\r\n"
    request += "\r\n"
    if body:
        request += body
    return request.encode()

# UDP probe map
_UDP_PROBE_MAP = {
    53:    b"\xAA\xBB\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    123:   b"\x1b" + b"\x00"*47,
    161:   b"\x30\x25\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x18\x02\x04\x2b\x06\x01\x02\x01\x02\x01\x00\x02\x01\x00",
    1900:  b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\nST:ssdp:all\r\n\r\n",
}

def get_udp_probe(port):
    return _UDP_PROBE_MAP.get(port, None)

# ---------------------------
# Realistic timing (lognormal / Pareto)
# ---------------------------
def human_delay(mean_seconds=8, max_seconds=30, shape=0.8):
    try:
        sigma = shape
        mu = math.log(mean_seconds) - (sigma ** 2) / 2
        val = random.lognormvariate(mu, sigma)
        return min(max_seconds, max(2.0, val))
    except AttributeError:
        alpha = shape + 0.7
        scale = mean_seconds * (alpha - 1) / alpha
        val = random.paretovariate(alpha) * scale
        return min(max_seconds, max(2.0, val))

# ---------------------------
# Advanced packet crafting
# ---------------------------
def ip_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def tcp_checksum(ip_src, ip_dst, tcp_segment):
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(ip_src),
                         socket.inet_aton(ip_dst),
                         0, socket.IPPROTO_TCP, len(tcp_segment))
    return ip_checksum(pseudo + tcp_segment)

def random_tcp_window():
    return random.choice([8192, 16384, 32768, 65535, 29200, 64240])

def random_ttl():
    return random.choice([64, 128, 255])

def random_ip_id():
    return random.randint(1, 65535)

def random_tos():
    # DSCP values (0x00, 0x08, 0x10, 0x20, 0x28, 0x30) + ECN bits
    dscp = random.choice([0x00, 0x08, 0x10, 0x20, 0x28, 0x30])
    ecn = random.choice([0x00, 0x01, 0x02])  # Non-ECT, ECT(1), ECT(0)
    return (dscp << 2) | ecn

def build_tcp_options():
    """Return realistic TCP options bytes (MSS, window scale, timestamp, SACK, NOP)."""
    opts = []
    # MSS
    mss = random.choice([1460, 1440, 1360, 8960])
    opts.append(b'\x02\x04' + struct.pack('!H', mss))
    # NOP + Window Scale
    scale = random.randint(0, 7)
    opts.append(b'\x03\x03' + struct.pack('!B', scale))
    # SACK permitted
    opts.append(b'\x04\x02')
    # Timestamp (realistic ts_val, ts_ecr)
    ts_val = random.randint(0x10000, 0x7fffffff)
    ts_ecr = 0 if random.random() < 0.7 else random.randint(0x10000, 0x7fffffff)
    opts.append(b'\x08\x0a' + struct.pack('!II', ts_val, ts_ecr))
    # NOP padding to 12 bytes (multiples of 4)
    opts.append(b'\x01' * (12 - (sum(len(o) for o in opts) % 4)))
    return b''.join(opts)

def build_syn_packet(src_ip, dst_ip, dst_port, src_port=None, ttl=None, window=None,
                     seq=None, options=None):
    if src_port is None:
        src_port = random.randint(49152, 65535)
    if ttl is None:
        ttl = random_ttl()
    if window is None:
        window = random_tcp_window()
    if seq is None:
        seq = random.randint(1, 2**32 - 1)
    if options is None:
        options = build_tcp_options()
    # IP header (no options)
    ip_ver_ihl = 0x45  # IPv4, header length 20
    ip_tos = random_tos()
    tcp_header_len = 20 + len(options)
    ip_len = 20 + tcp_header_len
    ip_id = random_ip_id()
    ip_flags_frag = 0x4000  # Don't fragment
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    ip_header_raw = struct.pack('!BBHHHBBH4s4s',
                                ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                                ttl, socket.IPPROTO_TCP, 0, ip_src, ip_dst)
    ip_csum = ip_checksum(ip_header_raw)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                            ttl, socket.IPPROTO_TCP, ip_csum, ip_src, ip_dst)
    # TCP header
    tcp_doff_res = (5 + len(options)//4) << 4  # data offset in 32-bit words
    tcp_flags = 0x02  # SYN
    tcp_urg = 0
    tcp_header_raw = struct.pack('!HHLLBBHHH',
                                 src_port, dst_port, seq, 0,
                                 tcp_doff_res, tcp_flags, window, 0, tcp_urg) + options
    tcp_csum = tcp_checksum(src_ip, dst_ip, tcp_header_raw)
    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port, seq, 0,
                             tcp_doff_res, tcp_flags, window, tcp_csum, tcp_urg) + options
    return ip_header + tcp_header

def send_raw_syn(src_ip, dst_ip, dst_port, sock=None, ttl=None, window=None, seq=None, options=None):
    if not CAN_RAW_SOCKET:
        return False
    own_sock = False
    if sock is None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            own_sock = True
        except PermissionError:
            return False
    packet = build_syn_packet(src_ip, dst_ip, dst_port, ttl=ttl, window=window, seq=seq, options=options)
    try:
        sock.sendto(packet, (dst_ip, 0))
    except Exception:
        return False
    finally:
        if own_sock and sock:
            sock.close()
    return True

def send_raw_udp(src_ip, dst_ip, dst_port, payload, sock=None):
    """Craft and send a UDP packet from src_ip to dst_ip:dst_port with payload."""
    if not CAN_RAW_SOCKET:
        return False
    own_sock = False
    if sock is None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            own_sock = True
        except PermissionError:
            return False
    # IP header
    ip_ver_ihl = 0x45
    ip_tos = random_tos()
    ip_len = 20 + 8 + len(payload)  # IP + UDP + payload
    ip_id = random_ip_id()
    ip_flags_frag = 0x4000
    ip_ttl = random_ttl()
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                            ip_ttl, socket.IPPROTO_UDP, 0, ip_src, ip_dst)
    ip_csum = ip_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                            ip_ttl, socket.IPPROTO_UDP, ip_csum, ip_src, ip_dst)
    # UDP header
    src_port = random.randint(49152, 65535)
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    udp_csum = 0  # optional for IPv4, set to 0
    udp_packet = udp_header + payload
    packet = ip_header + udp_packet
    try:
        sock.sendto(packet, (dst_ip, 0))
        return True
    except Exception:
        return False
    finally:
        if own_sock and sock:
            sock.close()

def send_icmp_echo(src_ip, dst_ip, sock=None):
    """Send ICMP Echo Request from src_ip to dst_ip."""
    if not CAN_RAW_SOCKET:
        return False
    own_sock = False
    if sock is None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            own_sock = True
        except PermissionError:
            return False
    # ICMP Echo Request
    icmp_type = 8
    icmp_code = 0
    icmp_csum = 0
    icmp_id = random.randint(1, 65535)
    icmp_seq = random.randint(1, 65535)
    payload = os.urandom(random.randint(32, 64))
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq)
    icmp_csum = ip_checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq)
    packet = header + payload
    # IP header
    ip_ver_ihl = 0x45
    ip_tos = random_tos()
    ip_len = 20 + len(packet)
    ip_id = random_ip_id()
    ip_flags_frag = 0x4000
    ip_ttl = random_ttl()
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                            ip_ttl, socket.IPPROTO_ICMP, 0, ip_src, ip_dst)
    ip_csum = ip_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag,
                            ip_ttl, socket.IPPROTO_ICMP, ip_csum, ip_src, ip_dst)
    full_packet = ip_header + packet
    try:
        sock.sendto(full_packet, (dst_ip, 0))
        return True
    except Exception:
        return False
    finally:
        if own_sock and sock:
            sock.close()

# ---------------------------
# SYN scan with decoys (identical packets)
# ---------------------------
def syn_scan_with_decoys(ip, port, timeout=5):
    """SYN scan using real IP + decoys. Returns True if SYN/ACK received."""
    if not ENABLE_DECOYS:
        return tcp_connect_probe(ip, port)

    send_sock = None
    recv_sock = None
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.setblocking(False)          # non‑blocking for select()
    except PermissionError:
        print(" [!] Raw socket permission denied. Falling back to connect() scan.")
        return tcp_connect_probe(ip, port)

    # Pre‑build identical SYN parameters for this probe
    src_port = random.randint(49152, 65535)
    ttl = random_ttl()
    window = random_tcp_window()
    seq = random.randint(1, 2**32 - 1)
    options = build_tcp_options()
    real_ip = get_real_ip()

    # Send decoy SYNs first, then the real SYN (to hide our IP among the noise)
    for decoy in DECOY_IPS:
        send_raw_syn(decoy, ip, port, sock=send_sock, ttl=ttl, window=window, seq=seq, options=options)
    send_raw_syn(real_ip, ip, port, sock=send_sock, ttl=ttl, window=window, seq=seq, options=options)

    # Wait for SYN/ACK using select with a timeout
    start_time = time.time()
    while time.time() - start_time < timeout:
        ready, _, _ = select.select([recv_sock], [], [], 0.1)   # check every 100ms
        if not ready:
            continue
        try:
            data, _ = recv_sock.recvfrom(65535)
        except BlockingIOError:
            continue

        # Parse IP header
        if len(data) < 20:
            continue
        ip_header = data[:20]
        ip_len = (ip_header[0] & 0x0F) * 4
        if len(data) < ip_len + 20:
            continue
        tcp_segment = data[ip_len:ip_len+40]
        tcp_flags = tcp_segment[13]
        if (tcp_flags & 0x12) == 0x12:  # SYN+ACK
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            tcp_src_port = struct.unpack('!H', tcp_segment[0:2])[0]
            tcp_dst_port = struct.unpack('!H', tcp_segment[2:4])[0]
            if dst_ip == real_ip and tcp_dst_port == src_port and tcp_src_port == port:
                return True

    # Clean up
    if send_sock:
        send_sock.close()
    if recv_sock:
        recv_sock.close()
    return False

# ---------------------------
# TCP connect probe + decoy SYNs
# ---------------------------
def tcp_connect_probe(ip, port):
    """Normal TCP connect + decoy SYNs sent in background."""
    # Send decoy SYNs before connecting (to mask real connection)
    if ENABLE_DECOYS:
        threading.Thread(target=_send_decoy_syns, args=(ip, port), daemon=True).start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        # Application layer mimicry
        if port == 22:
            ssh_exchange_and_quit(ip, port)
        elif port == 25:
            smtp_ehlo_quit(ip, port)
        elif port in [80, 8080, 8000, 8888]:
            sock.send(http_probe(host=ip))
            try: sock.recv(1024)
            except: pass
        elif port in [443, 993, 8443]:
            tls_hello = build_tls_client_hello()
            sock.send(tls_hello)
            try: sock.recv(1024)
            except: pass
        else:
            time.sleep(random.uniform(0.5, 1.5))
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()

def _send_decoy_syns(ip, port):
    """Send decoy SYNs (identical parameters) for a connect probe."""
    send_sock = None
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        return
    src_port = random.randint(49152, 65535)
    ttl = random_ttl()
    window = random_tcp_window()
    seq = random.randint(1, 2**32 - 1)
    options = build_tcp_options()
    for decoy in DECOY_IPS:
        send_raw_syn(decoy, ip, port, sock=send_sock, ttl=ttl, window=window, seq=seq, options=options)
    if send_sock:
        send_sock.close()

# ---------------------------
# UDP probe with decoys (identical payload)
# ---------------------------
def udp_probe_with_decoys(ip, port):
    payload = get_udp_probe(port)
    if payload is None:
        return False
    # Real probe (normal UDP socket)
    real_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    real_sock.settimeout(3)
    try:
        real_sock.sendto(payload, (ip, port))
        data, _ = real_sock.recvfrom(1024)
        if data:
            return True
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        real_sock.close()
    # Decoy noise (identical payload from each decoy IP)
    if ENABLE_DECOYS:
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            for decoy in DECOY_IPS:
                send_raw_udp(decoy, ip, port, payload, sock=raw_sock)
            raw_sock.close()
        except Exception:
            pass
    return False

# ---------------------------
# Host up check with ICMP decoys
# ---------------------------
def is_host_up(ip):
    if sys.platform == "win32":
        return _is_host_up_windows(ip)
    # Use nmap -sn with decoy flag (already done) AND send decoy ICMP echoes
    if ENABLE_DECOYS:
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            for decoy in DECOY_IPS:
                send_icmp_echo(decoy, ip, sock=raw_sock)
            raw_sock.close()
        except Exception:
            pass
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        xml_output = tmp.name
    nmap_path = resolve_nmap()
    cmd = [nmap_path, "-sn", "-PE", "--data-length", "56", "--max-retries", "1",
           "--host-timeout", "5s", "-oX", xml_output] + decoy_flags() + [ip]
    run_cmd(cmd)
    try:
        tree = ET.parse(xml_output)
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                return True
        return False
    except ET.ParseError:
        return False
    finally:
        if os.path.exists(xml_output):
            os.remove(xml_output)

def _is_host_up_windows(ip):
    result = subprocess.run(["ping", "-n", "1", "-w", "2000", ip], capture_output=True)
    if result.returncode == 0:
        return True
    for port in [80,443,22,25,53]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except:
            pass
    return False

# ---------------------------
# Background noise (enhanced)
# ---------------------------
def background_noise(duration=3600):
    end_time = time.time() + duration
    if sys.platform == "win32":
        dns_cmd = ["nslookup"]
    else:
        dns_cmd = ["dig", "+short"]
    # Also perform random ARP and ICMP noise
    while time.time() < end_time:
        domain = random_domain()
        try:
            subprocess.run(dns_cmd + [domain], capture_output=True, timeout=5)
        except Exception:
            pass
        if random.random() < 0.3:
            try:
                requests.get("https://www.google.com/", timeout=2, headers={"User-Agent": random.choice(USER_AGENTS)})
            except:
                pass
        # Random ICMP echo to random public IP
        if random.random() < 0.2 and CAN_RAW_SOCKET:
            rand_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            try:
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_icmp_echo(get_real_ip(), rand_ip, sock=raw)
                raw.close()
            except:
                pass
        time.sleep(human_delay(mean_seconds=60, max_seconds=180, shape=1.2))

def start_background_noise():
    t = threading.Thread(target=background_noise, daemon=True)
    t.start()
    return t

# ---------------------------
# SSH / SMTP helpers (unchanged)
# ---------------------------
def ssh_exchange_and_quit(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        client_banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        sock.send(client_banner.encode())
        sock.recv(1024).decode(errors='ignore')
        disconnect = b"\x00\x00\x00\x0c\x01\x00\x00\x00\x0bBye"
        sock.send(disconnect)
        time.sleep(0.5)
        sock.close()
        return True
    except:
        sock.close()
        return False

def smtp_ehlo_quit(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        sock.recv(1024)
        hostname = f"client-{random.randint(1000,9999)}"
        sock.send(f"EHLO {hostname}\r\n".encode())
        sock.recv(1024)
        sock.send(b"QUIT\r\n")
        sock.close()
        return True
    except:
        sock.close()
        return False

# ---------------------------
# TLS ClientHello (randomised)
# ---------------------------
def build_tls_client_hello():
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = bytes([random.randint(0, 255) for _ in range(32)])
    num_ciphers = random.randint(10, 16)
    ciphers = random.sample(CIPHER_SUITES, num_ciphers)
    cipher_suites = b''.join(struct.pack('!H', c) for c in ciphers)
    ext_list = [
        b'\x00\x2b\x00\x03\x02\x03\x04',  # supported versions
        b'\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01',  # sig alg
        b'\x00\x16\x00\x00', b'\x00\x17\x00\x00', b'\x00\x23\x00\x00', b'\xff\x01\x00\x01\x00'
    ]
    random.shuffle(ext_list)
    extensions = b''.join(ext_list)
    handshake_type = 0x01
    length = 2 + 32 + 1 + 32 + 2 + len(cipher_suites) + 1 + 0 + 2 + len(extensions)
    client_hello = struct.pack('!B', handshake_type) + struct.pack('!I', length)[1:4] + \
                   struct.pack('!H', 0x0303) + random_bytes + \
                   struct.pack('!B', len(session_id)) + session_id + \
                   struct.pack('!H', len(cipher_suites)) + cipher_suites + \
                   b'\x01\x00' + struct.pack('!H', len(extensions)) + extensions
    record = b'\x16\x03\x03' + struct.pack('!H', len(client_hello)) + client_hello
    return record

# ---------------------------
# Nmap helpers (decoy flags already present)
# ---------------------------
def resolve_nmap():
    path = os.environ.get("NMAP_PATH")
    if path:
        return path
    found = shutil.which("nmap")
    if found:
        return found
    if sys.platform == "win32":
        for p in _WINDOWS_NMAP_PATHS:
            if os.path.isfile(p):
                return p
    print(" [!] nmap not found.")
    sys.exit(1)

def nmap_scan_type():
    return ["-sS"] if not sys.platform == "win32" else ["-sT"]

def nmap_unprivileged():
    return ["--unprivileged"] if sys.platform == "win32" else []

def decoy_flags():
    if ENABLE_DECOYS and DECOY_IPS:
        decoy_str = ','.join(DECOY_IPS) + ',ME'
        return ["-D", decoy_str]
    return []

def random_source_port():
    if sys.platform == "win32":
        return []
    return ["--source-port", str(random.randint(49152, 65535))]

def windows_fingerprint_flags():
    if sys.platform == "win32":
        return []
    return ["--ttl", str(random_ttl())]

def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

def run_cmd(cmd, **kwargs):
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    if DEBUG:
        print(f" [CMD] {' '.join(str(a) for a in cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if DEBUG:
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
    return result

# ---------------------------
# Port selection (unchanged)
# ---------------------------
COMMON_PORTS = [21,22,23,25,53,80,110,111,123,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,
                20,26,69,81,88,113,137,138,161,162,179,194,199,389,427,443,445,465,514,515,543,544,548,
                554,587,631,646,873,990,992,993,994,995,1025,1026,1027,1028,1029,1030,1720,1723,2000,3128,
                3268,3269,3306,3389,5432,5555,5631,5632,5666,5800,5801,5900,5901,6000,6001,6379,7001,7002,
                8000,8001,8008,8009,8080,8081,8443,8888,9000,9090,10000,12345,27017,28017,50000,50030,50070]

def parse_tports(value):
    if value == 'common':
        return COMMON_PORTS
    if value == 'all':
        return list(range(1, 65536))
    ports = set()
    for part in value.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            start, end = int(start), int(end)
            ports.update(range(start, end+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def get_target_ports(ip):
    tports_env = os.environ.get('TPORTS')
    if tports_env:
        return parse_tports(tports_env)
    open_ports = shodan_scan()
    if open_ports:
        return open_ports
    print(" [!] No open ports found via Shodan. Using interactive selection.")
    choice = input("Option (1=range,2=common,3=manual,4=exit): ").strip()
    if choice == '1':
        print("Select range: a=1-100 b=1-1000 c=1-10000 d=1-65535")
        range_choice = input("Range (a/b/c/d): ").strip().lower()
        ranges = {'a': (1,100), 'b': (1,1000), 'c': (1,10000), 'd': (1,65535)}
        if range_choice in ranges:
            start, end = ranges[range_choice]
            duration = int(input("Scan duration (seconds): "))
            base = f"{Path(os.environ.get('FNAME', 'results')) / ip.replace('/', '_')}/port"
            scan(ip, (start, end), duration, base)
            sys.exit(0)
    elif choice == '2':
        return COMMON_PORTS
    elif choice == '3':
        ports_input = input("Ports (e.g., 80,443,1000-2000): ")
        return parse_tports(ports_input)
    else:
        sys.exit(0)

# ---------------------------
# Probe wrappers that use decoy features
# ---------------------------
def probe_single_tcp_port(ip, port, base_name):
    if ENABLE_DECOYS and CAN_RAW_SOCKET:
        is_open = syn_scan_with_decoys(ip, port)
        # Application mimicry if open (performed inside tcp_connect_probe if needed)
        if is_open and port in [22,25,80,443,8080,8443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                if port == 22:
                    ssh_exchange_and_quit(ip, port)
                elif port == 25:
                    smtp_ehlo_quit(ip, port)
                elif port in [80,8080,8000,8888]:
                    sock.send(http_probe(host=ip))
                elif port in [443,8443,993]:
                    sock.send(build_tls_client_hello())
                time.sleep(random.uniform(0.5,1.5))
                sock.close()
            except:
                pass
        return port, is_open
    else:
        is_open = tcp_connect_probe(ip, port)
        return port, is_open

def probe_single_udp_port(ip, port):
    return udp_probe_with_decoys(ip, port)

# ---------------------------
# Scan chain (updated)
# ---------------------------
def run_scan_chain(ip, folder_name):
    safe_ip = ip.replace('/', '_')
    ip_folder = Path(folder_name) / safe_ip
    ip_folder.mkdir(parents=True, exist_ok=True)
    base = f"{ip_folder}/port"
    open_ports = get_target_ports(ip)
    if not open_ports:
        print(" [!] No ports to scan. Exiting.")
        return False
    random.shuffle(open_ports)
    print(f" [*] Scanning {len(open_ports)} ports with {'decoy' if ENABLE_DECOYS else 'normal'} TCP probes")
    tcp_open_ports = []
    for idx, port in enumerate(open_ports, 1):
        print(f"\n [*] Port {idx}/{len(open_ports)}: {port}")
        _, is_open = probe_single_tcp_port(ip, port, base)
        if is_open:
            tcp_open_ports.append(port)
            print(f" [*] Port {port} is open")
        else:
            print(f" [*] Port {port} is closed/filtered")
        if idx < len(open_ports):
            sleep_time = human_delay(mean_seconds=8, max_seconds=30)
            print(f" [*] Sleeping {sleep_time:.1f}s before next port...")
            time.sleep(sleep_time)
    with open(ip_folder / "tcp_open_ports.txt", "w") as f:
        for p in tcp_open_ports:
            f.write(f"{p}\n")
    non_responding = [p for p in open_ports if p not in tcp_open_ports]
    udp_open_ports = []
    if non_responding:
        print(f"\n [*] UDP probing {len(non_responding)} ports")
        for port in non_responding:
            if get_udp_probe(port):
                print(f" [*] UDP probe on port {port}...")
                if probe_single_udp_port(ip, port):
                    udp_open_ports.append(port)
                    print(f" [*] UDP port {port} is open")
                else:
                    print(f" [*] UDP port {port} closed/filtered")
            else:
                print(f" [*] No probe for UDP {port}, skipping")
            time.sleep(human_delay(mean_seconds=4, max_seconds=15))
    with open(ip_folder / "udp_open_ports.txt", "w") as f:
        for p in udp_open_ports:
            f.write(f"{p}\n")
    # Service detection with nmap (decoy flags already included)
    service_scan_enabled = os.environ.get('SERVICE_SCAN', 'true').lower() == 'true'
    if service_scan_enabled and (tcp_open_ports or udp_open_ports):
        print(" [*] Running nmap service detection with decoy flags")
        time.sleep(human_delay(mean_seconds=10, max_seconds=30))
        if tcp_open_ports:
            ports_str = ",".join(map(str, tcp_open_ports))
            cmd = [resolve_nmap()] + nmap_unprivileged() + nmap_scan_type() + \
                  ["-T1", "--max-rate", str(random.randint(1,15)), "--scan-delay", f"{human_delay(mean_seconds=5)}s",
                   "-sV", "--version-intensity", "5"] + random_source_port() + windows_fingerprint_flags() + \
                  decoy_flags() + ["-p", ports_str, "-oA", f"{base}_tcp_service_versions", ip]
            run_cmd(cmd)
        if udp_open_ports:
            ports_str = ",".join(map(str, udp_open_ports))
            cmd = (["sudo"] if not sys.platform.startswith('win') else []) + [resolve_nmap()] + nmap_unprivileged() + \
                  ["-sU", "-T0", "--max-rate", str(random.randint(1,10)), "--scan-delay", f"{human_delay(mean_seconds=5)}s",
                   "-sV", "--version-intensity", "1", "-sC"] + random_source_port() + windows_fingerprint_flags() + \
                  decoy_flags() + ["-p", ports_str, "-oA", f"{base}_udp_service_versions", ip]
            run_cmd(cmd)
    return True

def merge_all_xml_results(xml_files, output_path):
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
                    addr = host.find("address")
                    if addr is None: continue
                    host_addr = addr.get("addr")
                    if not host_addr: continue
                    if host_addr not in all_hosts:
                        all_hosts[host_addr] = host
                    else:
                        merge_host_ports(all_hosts[host_addr], host)
            except ET.ParseError:
                continue
        if merged_root is not None:
            for host in all_hosts.values():
                merged_root.append(host)
        else:
            return False
        ET.ElementTree(merged_root).write(str(output_path), encoding="utf-8", xml_declaration=True)
        return True
    except Exception:
        return False

def merge_host_ports(existing_host, new_host):
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
            key = f"{protocol}/{portid}"
            if key not in existing_ports:
                ports_elem = existing_host.find("ports")
                if ports_elem is None:
                    ports_elem = ET.SubElement(existing_host, "ports")
                ports_elem.append(port)

def scan_single_ip(ip, folder_name):
    print(f"\n [*] Starting stealth scan for {ip}")
    return run_scan_chain(ip, folder_name)

def shodan_scan():
    ip = os.environ.get("IP")
    if not ip: return []
    try:
        host = requests.get(f"https://internetdb.shodan.io/{ip}").json()
        return host.get("ports", [])
    except Exception:
        return []

def is_cidr_range(ip):
    return '/' in ip

def expand_cidr_range(cidr_range):
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def scan(ip, port_range, duration, base_name):
    nmap_path = resolve_nmap()
    start, end = port_range
    total_ports = end - start + 1
    chunks = max(5, total_ports // 50)
    ports = list(range(start, end+1))
    random.shuffle(ports)
    groups = [ports[i:i+chunks] for i in range(0, len(ports), chunks)]
    sleep_base = duration / max(len(groups), 1)
    for i, group in enumerate(groups):
        port_str = ",".join(map(str, group))
        cmd = [nmap_path] + nmap_unprivileged() + nmap_scan_type() + \
              ["-p", port_str, "-T1", "--host-timeout", "30m",
               "--max-rate", str(random.randint(1,15)), "--scan-delay", f"{human_delay(mean_seconds=5)}s",
               "--max-retries", "3"] + random_source_port() + windows_fingerprint_flags() + decoy_flags() + \
              ["-oX", f"{base_name}_ports_{port_str.replace(',','_')}.xml", ip]
        subprocess.run(cmd)
        time.sleep(sleep_base * random.uniform(0.5, 1.5))

def get_real_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ---------------------------
# Main
# ---------------------------
def main():
    global DEBUG
    DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'
    init_decoy_config()
    ip = os.environ.get("IP")
    if not ip:
        ip = input(" [?] Enter target IP or CIDR: ").strip()
        if not ip:
            sys.exit(1)
    fname = os.environ.get("FNAME")
    folder_name = fname if fname else f"{ip.replace('/', '_')}_results"
    Path(folder_name).mkdir(parents=True, exist_ok=True)
    perform_host_check = os.environ.get('HOST_CHECK', 'true').lower() == 'true'
    if is_cidr_range(ip):
        ip_list = expand_cidr_range(ip)
        if not ip_list:
            print(" [!] No IPs in range.")
            return
        print(f" [*] Scanning {len(ip_list)} IPs")
        for target_ip in ip_list:
            if perform_host_check and not is_host_up(target_ip):
                print(f" [!] {target_ip} down, skipping.")
                continue
            scan_single_ip(target_ip, folder_name)
    else:
        if perform_host_check and not is_host_up(ip):
            print(f" [!] Host {ip} down.")
            sys.exit(1)
        scan_single_ip(ip, folder_name)

if __name__ == "__main__":
    main()