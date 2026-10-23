import { describe, it, expect } from "vitest";
import { md5, sha256 } from "./crypto";
import { computeJA3, isGrease } from "./ja3";
import { computeJA4 } from "./ja4";

describe("Cryptographic Hash Verification", () => {
  it("computes MD5 standard vectors correctly", () => {
    expect(md5("")).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(md5("The quick brown fox jumps over the lazy dog")).toBe("9e107d9d372bb6826bd81d3542a419d6");
  });

  it("computes SHA-256 standard vectors correctly", () => {
    expect(sha256("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256("FoxIO")).toBe("342a141e76fd1053f37c91bfedfba822c5c64f0965bbd21f24a0aeb3b0afef13");
  });
});

describe("Salesforce JA3 Official Test Vector", () => {
  it("matches the official Salesforce JA3 test vector and MD5 hash", () => {
    // Official test vector from https://github.com/salesforce/ja3
    // Raw: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
    // Expected MD5: ada70206e40642a3e4461f35503241d5
    const version = 769;
    const ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4];
    const extensions = [0, 10, 11];
    const curves = [23, 24, 25];
    const pointFormats = [0];

    const result = computeJA3(version, ciphers, extensions, curves, pointFormats);

    expect(result.raw).toBe("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0");
    expect(result.hash).toBe("ada70206e40642a3e4461f35503241d5");
  });

  it("properly filters GREASE values per RFC 8701", () => {
    expect(isGrease(0x0a0a)).toBe(true);
    expect(isGrease(0x3a3a)).toBe(true);
    expect(isGrease(0x1301)).toBe(false);

    const version = 771;
    const ciphersWithGrease = [0x2a2a, 49195, 49199, 0x5a5a, 49196];
    const extensionsWithGrease = [0x3a3a, 0x0000, 0x000a, 0xaaaa];
    const curvesWithGrease = [0x6a6a, 29, 23];

    const result = computeJA3(version, ciphersWithGrease, extensionsWithGrease, curvesWithGrease, [0]);
    expect(result.ciphers).toEqual([49195, 49199, 49196]);
    expect(result.extensions).toEqual([0x0000, 0x000a]);
    expect(result.curves).toEqual([29, 23]);
    expect(result.greaseFilteredCiphers.length).toBe(2);
    expect(result.greaseFilteredExtensions.length).toBe(2);
  });
});

describe("FoxIO JA4 Specification and Classroom Experiment", () => {
  it("formats JA4_a correctly with 10-character header", () => {
    const ja4 = computeJA4({
      protocol: "t",
      version: 0x0303,
      hasSni: true,
      sniIsIp: false,
      ciphers: [0x1301, 0x1302, 0xc02b, 0xc02f],
      extensions: [0x0000, 0x000a, 0x000b, 0x0010, 0x0023, 0x002b],
      alpnProtocols: ["h2", "http/1.1"],
      supportedVersions: [0x0304, 0x0303],
    });

    expect(ja4.ja4_a.length).toBe(10);
    // Protocol 't', version '13' (from supported_versions), sni 'd', ciphers 04, extensions 06, alpn 'h2'
    expect(ja4.ja4_a).toBe("t13d0406h2");
  });

  it("CRITICAL EXPERIMENT: Shuffling extensions changes JA3, but preserves JA4", () => {
    const ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
    const originalExtensions = [0x0000, 0x0005, 0x000a, 0x000b, 0x0010, 0x0023, 0x002b];
    const shuffledExtensions = [0x002b, 0x0010, 0x0005, 0x0023, 0x0000, 0x000b, 0x000a];
    const curves = [29, 23];
    const pointFormats = [0];
    const alpn = ["h2"];
    const sigAlgs = [0x0403, 0x0804];

    // Compute JA3 before and after
    const ja3Before = computeJA3(771, ciphers, originalExtensions, curves, pointFormats);
    const ja3After = computeJA3(771, ciphers, shuffledExtensions, curves, pointFormats);

    // Compute JA4 before and after
    const ja4Before = computeJA4({
      protocol: "t",
      version: 771,
      hasSni: true,
      sniIsIp: false,
      ciphers,
      extensions: originalExtensions,
      alpnProtocols: alpn,
      signatureAlgorithms: sigAlgs,
    });

    const ja4After = computeJA4({
      protocol: "t",
      version: 771,
      hasSni: true,
      sniIsIp: false,
      ciphers,
      extensions: shuffledExtensions,
      alpnProtocols: alpn,
      signatureAlgorithms: sigAlgs,
    });

    // Verification
    expect(ja3Before.hash).not.toBe(ja3After.hash); // JA3 alters because extensions order is preserved
    expect(ja4Before.full).toBe(ja4After.full); // JA4 remains identical because extensions are sorted
    expect(ja4Before.ja4_c).toBe(ja4After.ja4_c); // JA4_c hash is identical
  });
});
