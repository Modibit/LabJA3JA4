"""
Sample PCAP Generator and Catalog.
Generates fully valid, authentic binary PCAP captures containing real TLS ClientHello packets
for educational demonstration and offline testing.
"""

import struct
import socket
import os
from typing import List, Dict, Any
from app.tls_parser import parse_pcap_bytes

def build_client_hello_bytes(
    client_version: int,
    ciphers: List[int],
    extensions: List[int],
    sni: str = "",
    alpn: List[str] = None,
    curves: List[int] = None,
    point_formats: List[int] = None,
    sig_algs: List[int] = None,
    supported_versions: List[int] = None,
) -> bytes:
    """Build binary TLS ClientHello payload."""
    alpn = alpn or []
    curves = curves or []
    point_formats = point_formats or []
    sig_algs = sig_algs or []
    supported_versions = supported_versions or []

    # Build extensions binary
    ext_bytes = bytearray()

    for ext in extensions:
        data = bytearray()
        if ext == 0x0000 and sni: # SNI
            sni_name = sni.encode("utf-8")
            data.extend(struct.pack("!H", len(sni_name) + 3)) # list len
            data.append(0) # host_name type
            data.extend(struct.pack("!H", len(sni_name)))
            data.extend(sni_name)
        elif ext == 0x000a and curves: # Supported Groups
            data.extend(struct.pack("!H", len(curves) * 2))
            for c in curves:
                data.extend(struct.pack("!H", c))
        elif ext == 0x000b and point_formats: # EC Point Formats
            data.append(len(point_formats))
            for pf in point_formats:
                data.append(pf)
        elif ext == 0x000d and sig_algs: # Signature Algorithms
            data.extend(struct.pack("!H", len(sig_algs) * 2))
            for sa in sig_algs:
                data.extend(struct.pack("!H", sa))
        elif ext == 0x0010 and alpn: # ALPN
            alpn_data = bytearray()
            for proto in alpn:
                pb = proto.encode("latin-1")
                alpn_data.append(len(pb))
                alpn_data.extend(pb)
            data.extend(struct.pack("!H", len(alpn_data)))
            data.extend(alpn_data)
        elif ext == 0x002b and supported_versions: # Supported Versions
            data.append(len(supported_versions) * 2)
            for sv in supported_versions:
                data.extend(struct.pack("!H", sv))
        else:
            # Generic dummy padding or empty extension data
            data = bytearray()

        ext_bytes.extend(struct.pack("!HH", ext, len(data)))
        ext_bytes.extend(data)

    # ClientHello body
    ch_body = bytearray()
    ch_body.extend(struct.pack("!H", client_version)) # legacy version
    ch_body.extend(b"\x11\x22\x33\x44" * 8) # 32 bytes random
    ch_body.append(0) # session_id_len = 0

    # Ciphers
    ch_body.extend(struct.pack("!H", len(ciphers) * 2))
    for c in ciphers:
        ch_body.extend(struct.pack("!H", c))

    # Compression
    ch_body.append(1) # 1 byte length
    ch_body.append(0) # null compression

    # Extensions
    ch_body.extend(struct.pack("!H", len(ext_bytes)))
    ch_body.extend(ext_bytes)

    # Handshake Header: Type=1 (ClientHello), Length=3 bytes
    hs_len = len(ch_body)
    hs_bytes = bytearray([0x01, (hs_len >> 16) & 0xff, (hs_len >> 8) & 0xff, hs_len & 0xff])
    hs_bytes.extend(ch_body)

    # TLS Record Header: ContentType=22 (Handshake), Version=0x0301 (TLS 1.0 record), Length=2 bytes
    rec_len = len(hs_bytes)
    rec_bytes = bytearray([0x16, 0x03, 0x01, (rec_len >> 8) & 0xff, rec_len & 0xff])
    rec_bytes.extend(hs_bytes)

    return bytes(rec_bytes)

def build_pcap_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ts_sec: int = 1714000000) -> bytes:
    """Build single Ethernet/IPv4/TCP frame in libpcap packet format."""
    # TCP header
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000, # seq
        1,    # ack
        (5 << 4), # data offset = 20 bytes
        0x18, # PSH, ACK
        64240, # window
        0,    # checksum (0 for capture)
        0     # urgent pointer
    )
    tcp_data = tcp_hdr + payload

    # IPv4 header
    ip_len = 20 + len(tcp_data)
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, # ver=4, ihl=5
        0,    # tos
        ip_len,
        0xabcd, # id
        0x4000, # don't fragment
        64,     # ttl
        6,      # protocol TCP
        0,      # checksum
        src_ip_b,
        dst_ip_b
    )
    ip_data = ip_hdr + tcp_data

    # Ethernet header (14 bytes)
    eth_hdr = struct.pack("!6s6sH", b"\x52\x54\x00\x12\x34\x56", b"\x08\x00\x27\xaa\xbb\xcc", 0x0800)
    eth_data = eth_hdr + ip_data

    # PCAP packet header (16 bytes)
    pkt_len = len(eth_data)
    pcap_pkt_hdr = struct.pack("!IIII", ts_sec, 123456, pkt_len, pkt_len)
    return pcap_pkt_hdr + eth_data

def create_pcap_file(frames: List[bytes]) -> bytes:
    """Assemble global PCAP header (big-endian) with list of packet frames."""
    # Global header (24 bytes): magic 0xa1b2c3d4, major=2, minor=4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    return hdr + b"".join(frames)

# Predefined realistic client profiles
SAMPLE_PROFILES = {
    "chrome_browser.pcap": {
        "title": "مرورگر Chrome 124+ (همراه با GREASE و TLS 1.3)",
        "client_name": "Google Chrome (Desktop)",
        "description": "ارتباط واقعی کلاینت مدرن شامل افزونه‌های تصادفی GREASE، پروتکل TLS 1.3، ALPN برابر h2 و مرتب‌سازی استاندارد کروم.",
        "src_ip": "192.168.1.105",
        "dst_ip": "142.250.180.206",
        "src_port": 54320,
        "dst_port": 443,
        "version": 0x0303,
        "ciphers": [0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
        "extensions": [0x3a3a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b],
        "sni": "www.google.com",
        "alpn": ["h2", "http/1.1"],
        "curves": [0x4a4a, 0x001d, 0x0017, 0x0018],
        "point_formats": [0],
        "sig_algs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "supported_versions": [0x5a5a, 0x0304, 0x0303],
    },
    "curl_client.pcap": {
        "title": "دستور curl 8.x (مبتنی بر کتابخانه OpenSSL)",
        "client_name": "cURL CLI Tool",
        "description": "درخواست خط فرمان curl برای وب‌سایت curl.se، با پیکربندی پیش‌فرض OpenSSL 3.0، فاقد مقادیر GREASE.",
        "src_ip": "10.0.0.15",
        "dst_ip": "151.101.193.91",
        "src_port": 49812,
        "dst_port": 443,
        "version": 0x0303,
        "ciphers": [0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035],
        "extensions": [0x0000, 0x002b, 0x000a, 0x000b, 0x000d, 0x0016, 0x0017, 0x0033, 0x002d, 0x0029, 0x0010],
        "sni": "curl.se",
        "alpn": ["h2", "http/1.1"],
        "curves": [0x001d, 0x0017, 0x001e, 0x0019, 0x0018],
        "point_formats": [0],
        "sig_algs": [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301],
        "supported_versions": [0x0304, 0x0303],
    },
    "python_requests.pcap": {
        "title": "اسکریپت پایتون (Python Requests / Urllib3)",
        "client_name": "Python Automation Client",
        "description": "ترافیک اسکریپت خودکار پایتون برای واکشی API، فاقد پشتیبانی HTTP/2 ALPN در حالت عادی، ترتیب افزونه‌های خاص OpenSSL.",
        "src_ip": "172.16.2.80",
        "dst_ip": "104.26.10.78",
        "src_port": 38104,
        "dst_port": 443,
        "version": 0x0303,
        "ciphers": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x002f, 0x0035],
        "extensions": [0x0000, 0x000a, 0x000b, 0x000d, 0x0016, 0x0017, 0x002b, 0x002d, 0x0033],
        "sni": "api.github.com",
        "alpn": [], # Python requests doesn't enable ALPN h2 by default
        "curves": [0x001d, 0x0017, 0x0018],
        "point_formats": [0],
        "sig_algs": [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601],
        "supported_versions": [0x0304, 0x0303],
    },
    "automated_scanner.pcap": {
        "title": "ربات اسکنر امنیتی / ابزار شناسایی خودکار",
        "client_name": "Automated Port/TLS Scanner",
        "description": "ترافیک ابزار بررسی شبکه، با کمترین تعداد افزونه ممکن، اتصال با IP مستقیم فاقد SNI جهت کشف آسیب‌پذیری سرور.",
        "src_ip": "198.51.100.42",
        "dst_ip": "203.0.113.10",
        "src_port": 61200,
        "dst_port": 443,
        "version": 0x0301, # legacy TLS 1.0 probe
        "ciphers": [0x002f, 0x0035, 0x0005, 0x000a],
        "extensions": [0x000a, 0x000b],
        "sni": "", # Direct IP probe
        "alpn": [],
        "curves": [0x0017],
        "point_formats": [0],
        "sig_algs": [],
        "supported_versions": [],
    }
}

def generate_sample_pcap_bytes(profile_key: str) -> bytes:
    """Generate PCAP binary bytes for a given profile."""
    if profile_key not in SAMPLE_PROFILES:
        raise ValueError(f"Unknown profile: {profile_key}")

    p = SAMPLE_PROFILES[profile_key]
    payload = build_client_hello_bytes(
        client_version=p["version"],
        ciphers=p["ciphers"],
        extensions=p["extensions"],
        sni=p["sni"],
        alpn=p["alpn"],
        curves=p["curves"],
        point_formats=p["point_formats"],
        sig_algs=p["sig_algs"],
        supported_versions=p["supported_versions"],
    )
    frame = build_pcap_frame(p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], payload)
    return create_pcap_file([frame])

def save_sample_pcaps(output_dir: str):
    """Save all sample PCAPs to disk for local testing and downloads."""
    os.makedirs(output_dir, exist_ok=True)
    for filename in SAMPLE_PROFILES:
        path = os.path.join(output_dir, filename)
        pcap_data = generate_sample_pcap_bytes(filename)
        with open(path, "wb") as f:
            f.write(pcap_data)
