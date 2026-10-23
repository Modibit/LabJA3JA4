"""
Pure Python PCAP and PCAPNG Parser for TLS ClientHello packets.
Extracts ClientHello records, Cipher Suites, Extensions, SNI, ALPN, Supported Groups,
EC Point Formats, Signature Algorithms, and Supported Versions.
Zero external C-library dependency.
"""

import struct
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from app.fingerprint import compute_ja3, compute_ja4

def parse_client_hello_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a TLS record payload looking for Handshake ClientHello (0x16 -> 0x01).
    Returns structured data or None if not a valid ClientHello.
    """
    if len(payload) < 9:
        return None

    # Check TLS Record Header
    # Byte 0: Content Type (22 = Handshake = 0x16)
    content_type = payload[0]
    if content_type != 0x16:
        return None

    record_version = struct.unpack("!H", payload[1:3])[0]
    record_len = struct.unpack("!H", payload[3:5])[0]

    if len(payload) < 5 + record_len:
        # Partial or fragmented, try parsing what we have if long enough
        pass

    # Handshake Header
    hs_type = payload[5]
    if hs_type != 0x01: # ClientHello
        return None

    # hs_len is 3 bytes
    hs_len = int.from_bytes(payload[6:9], byteorder="big")
    offset = 9

    if len(payload) < offset + 34:
        return None

    client_version = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2

    # Random (32 bytes)
    random_bytes = payload[offset:offset+32]
    offset += 32

    # Session ID
    if offset >= len(payload):
        return None
    session_id_len = payload[offset]
    offset += 1
    session_id = payload[offset:offset+session_id_len].hex()
    offset += session_id_len

    # Cipher Suites
    if offset + 2 > len(payload):
        return None
    cipher_suites_len = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2

    if offset + cipher_suites_len > len(payload):
        return None

    ciphers = []
    for i in range(0, cipher_suites_len, 2):
        ciphers.append(struct.unpack("!H", payload[offset+i:offset+i+2])[0])
    offset += cipher_suites_len

    # Compression Methods
    if offset >= len(payload):
        return None
    comp_len = payload[offset]
    offset += 1 + comp_len

    # Extensions
    extensions = []
    curves = []
    point_formats = []
    sig_algs = []
    alpn_protocols = []
    supported_versions = []
    sni = ""

    if offset + 2 <= len(payload):
        ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(payload))

        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
            ext_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
            offset += 4
            ext_data = payload[offset:offset+ext_len]
            offset += ext_len

            extensions.append(ext_type)

            # Parse known extensions
            if ext_type == 0x0000: # SNI (server_name)
                try:
                    if len(ext_data) >= 5:
                        sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
                        sni_type = ext_data[2]
                        if sni_type == 0: # host_name
                            name_len = struct.unpack("!H", ext_data[3:5])[0]
                            sni = ext_data[5:5+name_len].decode("utf-8", errors="replace")
                except Exception:
                    pass

            elif ext_type == 0x000a: # Supported Groups (elliptic_curves)
                try:
                    if len(ext_data) >= 2:
                        curves_len = struct.unpack("!H", ext_data[0:2])[0]
                        for c_idx in range(2, min(2 + curves_len, len(ext_data)), 2):
                            curves.append(struct.unpack("!H", ext_data[c_idx:c_idx+2])[0])
                except Exception:
                    pass

            elif ext_type == 0x000b: # EC Point Formats
                try:
                    if len(ext_data) >= 1:
                        pf_len = ext_data[0]
                        for pf_idx in range(1, min(1 + pf_len, len(ext_data))):
                            point_formats.append(ext_data[pf_idx])
                except Exception:
                    pass

            elif ext_type == 0x000d: # Signature Algorithms
                try:
                    if len(ext_data) >= 2:
                        sa_len = struct.unpack("!H", ext_data[0:2])[0]
                        for sa_idx in range(2, min(2 + sa_len, len(ext_data)), 2):
                            sig_algs.append(struct.unpack("!H", ext_data[sa_idx:sa_idx+2])[0])
                except Exception:
                    pass

            elif ext_type == 0x0010: # ALPN
                try:
                    if len(ext_data) >= 2:
                        alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                        alpn_offset = 2
                        while alpn_offset < len(ext_data):
                            proto_len = ext_data[alpn_offset]
                            alpn_offset += 1
                            proto = ext_data[alpn_offset:alpn_offset+proto_len].decode("latin-1", errors="replace")
                            alpn_protocols.append(proto)
                            alpn_offset += proto_len
                except Exception:
                    pass

            elif ext_type == 0x002b: # Supported Versions
                try:
                    if len(ext_data) >= 1:
                        sv_len = ext_data[0]
                        for sv_idx in range(1, min(1 + sv_len, len(ext_data)), 2):
                            supported_versions.append(struct.unpack("!H", ext_data[sv_idx:sv_idx+2])[0])
                except Exception:
                    pass

    return {
        "record_version": record_version,
        "client_version": client_version,
        "ciphers": ciphers,
        "extensions": extensions,
        "curves": curves,
        "point_formats": point_formats,
        "sig_algs": sig_algs,
        "alpn": alpn_protocols,
        "supported_versions": supported_versions,
        "sni": sni,
        "session_id": session_id,
        "random": random_bytes.hex(),
    }

def parse_ip_packet(packet_data: bytes, link_type: int = 1) -> Optional[Tuple[str, str, int, int, bytes]]:
    """
    Given raw link/packet data and link layer type, extract (src_ip, dst_ip, src_port, dst_port, tcp_payload).
    Supported link types:
      1: DLT_EN10MB (Ethernet)
      12 or 101: Raw IP
      113: SLL (Linux Cooked)
    """
    offset = 0

    if link_type == 1: # Ethernet
        if len(packet_data) < 14:
            return None
        eth_type = struct.unpack("!H", packet_data[12:14])[0]
        offset = 14
        if eth_type == 0x8100: # 802.1Q VLAN
            if len(packet_data) < 18:
                return None
            eth_type = struct.unpack("!H", packet_data[16:18])[0]
            offset = 18
    elif link_type == 113: # Linux Cooked
        if len(packet_data) < 16:
            return None
        eth_type = struct.unpack("!H", packet_data[14:16])[0]
        offset = 16
    elif link_type in (12, 101): # Raw IP
        if len(packet_data) < 1:
            return None
        ip_ver = (packet_data[0] >> 4) & 0x0f
        eth_type = 0x0800 if ip_ver == 4 else 0x86dd
        offset = 0
    else:
        # Fallback heuristic: check if start looks like IPv4 or IPv6
        ip_ver = (packet_data[0] >> 4) & 0x0f
        if ip_ver == 4:
            eth_type = 0x0800
            offset = 0
        else:
            return None

    if eth_type == 0x0800: # IPv4
        if len(packet_data) < offset + 20:
            return None
        ihl = (packet_data[offset] & 0x0f) * 4
        proto = packet_data[offset + 9]
        src_ip = socket.inet_ntoa(packet_data[offset+12:offset+16])
        dst_ip = socket.inet_ntoa(packet_data[offset+16:offset+20])
        offset += ihl
    elif eth_type == 0x86dd: # IPv6
        if len(packet_data) < offset + 40:
            return None
        proto = packet_data[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, packet_data[offset+8:offset+24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, packet_data[offset+24:offset+40])
        offset += 40
    else:
        return None

    if proto != 6: # TCP
        return None

    if len(packet_data) < offset + 20:
        return None

    src_port, dst_port = struct.unpack("!HH", packet_data[offset:offset+4])
    data_offset = ((packet_data[offset + 12] >> 4) & 0x0f) * 4
    tcp_payload = packet_data[offset + data_offset:]

    return src_ip, dst_ip, src_port, dst_port, tcp_payload

def parse_pcap_bytes(file_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Parse a complete PCAP or PCAPNG byte stream, extract TLS ClientHello records,
    and calculate both JA3 and JA4 fingerprints for each.
    """
    results = []

    if len(file_bytes) < 24:
        return results

    magic = file_bytes[0:4]

    # Standard PCAP
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        is_little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        endian = "<" if is_little else ">"
        link_type = struct.unpack(f"{endian}I", file_bytes[20:24])[0]

        offset = 24
        packet_idx = 0
        while offset + 16 <= len(file_bytes):
            packet_idx += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", file_bytes[offset:offset+16])
            offset += 16
            if offset + incl_len > len(file_bytes):
                break
            packet_data = file_bytes[offset:offset+incl_len]
            offset += incl_len

            parsed_ip = parse_ip_packet(packet_data, link_type)
            if not parsed_ip:
                continue

            src_ip, dst_ip, src_port, dst_port, tcp_payload = parsed_ip
            ch = parse_client_hello_payload(tcp_payload)
            if not ch:
                continue

            # Calculate JA3 & JA4
            raw_ja3, ja3_hash, ja3_meta = compute_ja3(
                version=ch["client_version"],
                ciphers=ch["ciphers"],
                extensions=ch["extensions"],
                curves=ch["curves"],
                point_formats=ch["point_formats"]
            )

            is_ip_sni = False
            if ch["sni"]:
                try:
                    socket.inet_aton(ch["sni"])
                    is_ip_sni = True
                except Exception:
                    pass

            ja4_str, ja4_details = compute_ja4(
                protocol="t",
                version=ch["client_version"],
                has_sni=bool(ch["sni"]),
                sni_is_ip=is_ip_sni,
                ciphers=ch["ciphers"],
                extensions=ch["extensions"],
                alpn_protocols=ch["alpn"],
                signature_algorithms=ch["sig_algs"],
                supported_versions=ch["supported_versions"]
            )

            results.append({
                "packet_index": packet_idx,
                "timestamp": ts_sec + (ts_usec / 1000000.0),
                "timestamp_str": datetime.fromtimestamp(ts_sec, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + f".{ts_usec:06d}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "client_hello": ch,
                "ja3": {
                    "raw": raw_ja3,
                    "hash": ja3_hash,
                    "meta": ja3_meta
                },
                "ja4": {
                    "fingerprint": ja4_str,
                    "details": ja4_details
                }
            })

    # PCAPNG Block Format
    elif magic == b"\x0a\x0d\x0d\x0a":
        # PCAPNG: Section Header Block
        offset = 0
        link_type = 1 # default Ethernet
        packet_idx = 0

        while offset + 8 <= len(file_bytes):
            block_type = struct.unpack("<I", file_bytes[offset:offset+4])[0]
            block_len = struct.unpack("<I", file_bytes[offset+4:offset+8])[0]
            if block_len < 12 or offset + block_len > len(file_bytes):
                break

            block_body = file_bytes[offset+8:offset+block_len-4]

            if block_type == 0x00000001: # Interface Description Block
                if len(block_body) >= 4:
                    link_type = struct.unpack("<H", block_body[0:2])[0]

            elif block_type == 0x00000006: # Enhanced Packet Block
                packet_idx += 1
                if len(block_body) >= 20:
                    interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", block_body[0:20])
                    packet_data = block_body[20:20+cap_len]

                    parsed_ip = parse_ip_packet(packet_data, link_type)
                    if parsed_ip:
                        src_ip, dst_ip, src_port, dst_port, tcp_payload = parsed_ip
                        ch = parse_client_hello_payload(tcp_payload)
                        if ch:
                            raw_ja3, ja3_hash, ja3_meta = compute_ja3(
                                version=ch["client_version"],
                                ciphers=ch["ciphers"],
                                extensions=ch["extensions"],
                                curves=ch["curves"],
                                point_formats=ch["point_formats"]
                            )

                            is_ip_sni = False
                            if ch["sni"]:
                                try:
                                    socket.inet_aton(ch["sni"])
                                    is_ip_sni = True
                                except Exception:
                                    pass

                            ja4_str, ja4_details = compute_ja4(
                                protocol="t",
                                version=ch["client_version"],
                                has_sni=bool(ch["sni"]),
                                sni_is_ip=is_ip_sni,
                                ciphers=ch["ciphers"],
                                extensions=ch["extensions"],
                                alpn_protocols=ch["alpn"],
                                signature_algorithms=ch["sig_algs"],
                                supported_versions=ch["supported_versions"]
                            )

                            ts_val = ((ts_high << 32) | ts_low) / 1000000.0
                            results.append({
                                "packet_index": packet_idx,
                                "timestamp": ts_val,
                                "timestamp_str": datetime.fromtimestamp(int(ts_val), timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "client_hello": ch,
                                "ja3": {
                                    "raw": raw_ja3,
                                    "hash": ja3_hash,
                                    "meta": ja3_meta
                                },
                                "ja4": {
                                    "fingerprint": ja4_str,
                                    "details": ja4_details
                                }
                            })

            offset += block_len

    return results
