"""
JA3 and JA4 TLS Fingerprinting Engine
Strict implementation matching official Salesforce JA3 and FoxIO JA4 specifications.
"""

import hashlib
from typing import List, Optional, Tuple, Dict, Any

# GREASE (RFC 8701) values to ignore in JA3 & JA4
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

def is_grease(val: int) -> bool:
    """Check if 16-bit integer is a GREASE value according to RFC 8701."""
    return val in GREASE_VALUES or ((val & 0x0f0f) == 0x0a0a and ((val >> 8) == (val & 0xff)))

def compute_ja3(
    version: int,
    ciphers: List[int],
    extensions: List[int],
    curves: Optional[List[int]] = None,
    point_formats: Optional[List[int]] = None
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Compute official Salesforce JA3 fingerprint.
    Raw string format: SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
    - GREASE values are filtered out from Ciphers, Extensions, and Elliptic Curves.
    - Fields are joined with '-'
    - Entire sequence joined with ','
    - Final hash is MD5 of UTF-8 raw string.
    """
    curves = curves or []
    point_formats = point_formats or []

    # Filter GREASE
    filtered_ciphers = [c for c in ciphers if not is_grease(c)]
    filtered_extensions = [e for e in extensions if not is_grease(e)]
    filtered_curves = [c for c in curves if not is_grease(c)]
    filtered_point_formats = [p for p in point_formats if not is_grease(p)]

    ciphers_str = "-".join(str(c) for c in filtered_ciphers)
    extensions_str = "-".join(str(e) for e in filtered_extensions)
    curves_str = "-".join(str(c) for c in filtered_curves)
    point_formats_str = "-".join(str(p) for p in filtered_point_formats)

    raw_ja3 = f"{version},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}"
    md5_hash = hashlib.md5(raw_ja3.encode("utf-8")).hexdigest()

    meta = {
        "version": version,
        "ciphers_count": len(filtered_ciphers),
        "extensions_count": len(filtered_extensions),
        "curves_count": len(filtered_curves),
        "point_formats_count": len(filtered_point_formats),
        "grease_filtered_ciphers": len(ciphers) - len(filtered_ciphers),
        "grease_filtered_extensions": len(extensions) - len(filtered_extensions),
    }

    return raw_ja3, md5_hash, meta

def map_tls_version_to_ja4(version: int) -> str:
    """Map TLS numerical version to JA4 2-character representation."""
    if version == 0x0304:
        return "13"
    elif version == 0x0303:
        return "12"
    elif version == 0x0302:
        return "11"
    elif version == 0x0301:
        return "10"
    elif version == 0x0300:
        return "s3"
    elif version == 0x0200:
        return "s2"
    elif version == 0x0100:
        return "s1"
    return "00"

def compute_ja4(
    protocol: str,
    version: int,
    has_sni: bool,
    sni_is_ip: bool,
    ciphers: List[int],
    extensions: List[int],
    alpn_protocols: Optional[List[str]] = None,
    signature_algorithms: Optional[List[int]] = None,
    supported_versions: Optional[List[int]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Compute official FoxIO JA4 fingerprint: ja4_a_ja4_b_ja4_c
    - protocol: 't' (TCP), 'q' (QUIC), 'd' (DTLS)
    - version: resolved from supported_versions if present (highest non-grease), else version
    - has_sni / sni_is_ip: 'd' if domain, 'i' if IP or no SNI
    - ciphers: filtered (no GREASE), sorted ascending hex, sha256[:12]
    - extensions: filtered (no GREASE, no 0000 SNI, no 0010 ALPN), sorted ascending hex
    - signature_algorithms: appended unsorted after '_' if present
    """
    alpn_protocols = alpn_protocols or []
    signature_algorithms = signature_algorithms or []
    supported_versions = supported_versions or []

    # 1. Resolve actual TLS version
    effective_version = version
    if supported_versions:
        # Filter grease and pick highest
        valid_versions = [v for v in supported_versions if not is_grease(v)]
        if valid_versions:
            effective_version = max(valid_versions)

    # JA4_a: Protocol (1 char) + Version (2 chars) + SNI (1 char) + CipherCount (2 chars) + ExtCount (2 chars) + ALPN (2 chars)
    proto_char = protocol[0].lower() if protocol else "t"
    ver_str = map_tls_version_to_ja4(effective_version)
    sni_char = "d" if (has_sni and not sni_is_ip) else "i"

    # Filter GREASE for counts
    filtered_ciphers = [c for c in ciphers if not is_grease(c)]
    filtered_extensions = [e for e in extensions if not is_grease(e)]

    cipher_count_str = f"{min(len(filtered_ciphers), 99):02d}"
    ext_count_str = f"{min(len(filtered_extensions), 99):02d}"

    # ALPN calculation
    if alpn_protocols and len(alpn_protocols) > 0 and len(alpn_protocols[0]) > 0:
        first_alpn = alpn_protocols[0]
        alpn_str = f"{first_alpn[0]}{first_alpn[-1]}"
    else:
        alpn_str = "00"

    ja4_a = f"{proto_char}{ver_str}{sni_char}{cipher_count_str}{ext_count_str}{alpn_str}"

    # JA4_b: SHA256 of sorted hex ciphers, 12 chars
    if filtered_ciphers:
        hex_ciphers = [f"{c:04x}" for c in filtered_ciphers]
        hex_ciphers.sort()
        raw_b = ",".join(hex_ciphers)
        ja4_b = hashlib.sha256(raw_b.encode("utf-8")).hexdigest()[:12]
    else:
        raw_b = ""
        ja4_b = "000000000000"

    # JA4_c: SHA256 of sorted hex extensions (excluding SNI=0x0000 & ALPN=0x0010) + '_' + unsorted sig_algs
    c_extensions = [e for e in filtered_extensions if e not in (0x0000, 0x0010)]
    hex_extensions = [f"{e:04x}" for e in c_extensions]
    hex_extensions.sort()
    ext_part = ",".join(hex_extensions)

    filtered_sig_algs = [s for s in signature_algorithms if not is_grease(s)]
    if filtered_sig_algs:
        hex_sig_algs = [f"{s:04x}" for s in filtered_sig_algs]
        sig_part = ",".join(hex_sig_algs)
        raw_c = f"{ext_part}_{sig_part}" if ext_part else f"_{sig_part}"
    else:
        sig_part = ""
        raw_c = ext_part

    if raw_c:
        ja4_c = hashlib.sha256(raw_c.encode("utf-8")).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    full_ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

    details = {
        "ja4_a": ja4_a,
        "ja4_b": ja4_b,
        "ja4_c": ja4_c,
        "raw_b": raw_b,
        "raw_c": raw_c,
        "effective_version": effective_version,
        "ciphers_sorted": hex_ciphers if filtered_ciphers else [],
        "extensions_sorted": hex_extensions,
        "sig_algs_raw": hex_sig_algs if filtered_sig_algs else [],
        "alpn_str": alpn_str,
        "sni_char": sni_char,
    }

    return full_ja4, details
