import pytest
from app.fingerprint import compute_ja3, compute_ja4, is_grease
from app.sample_pcaps import generate_sample_pcap_bytes, SAMPLE_PROFILES
from app.tls_parser import parse_pcap_bytes

def test_ja3_official_vector():
    # Official Salesforce test vector
    version = 769
    ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
    extensions = [0, 10, 11]
    curves = [23, 24, 25]
    point_formats = [0]

    raw, md5_hash, meta = compute_ja3(version, ciphers, extensions, curves, point_formats)
    assert raw == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert md5_hash == "ada70206e40642a3e4461f35503241d5"
    assert meta["ciphers_count"] == len(ciphers)

def test_ja4_extension_shuffle_invariance():
    ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]
    exts1 = [0x0000, 0x0005, 0x000a, 0x000b, 0x0010, 0x0023, 0x002b]
    exts2 = [0x002b, 0x0000, 0x0010, 0x0023, 0x0005, 0x000b, 0x000a]

    ja3_1, md5_1, _ = compute_ja3(771, ciphers, exts1, [29, 23], [0])
    ja3_2, md5_2, _ = compute_ja3(771, ciphers, exts2, [29, 23], [0])

    ja4_1, details_1 = compute_ja4("t", 771, True, False, ciphers, exts1, ["h2"], [0x0403, 0x0804])
    ja4_2, details_2 = compute_ja4("t", 771, True, False, ciphers, exts2, ["h2"], [0x0403, 0x0804])

    assert md5_1 != md5_2, "JA3 must change on extension reorder"
    assert ja4_1 == ja4_2, "JA4 must remain invariant to extension reorder"
    assert details_1["ja4_c"] == details_2["ja4_c"]

def test_sample_pcap_generation_and_parsing():
    for profile_key in SAMPLE_PROFILES:
        pcap_data = generate_sample_pcap_bytes(profile_key)
        assert len(pcap_data) > 0
        parsed = parse_pcap_bytes(pcap_data)
        assert len(parsed) == 1
        pkt = parsed[0]
        assert "ja3" in pkt
        assert "ja4" in pkt
        assert len(pkt["ja3"]["hash"]) == 32
        assert len(pkt["ja4"]["fingerprint"]) > 10
