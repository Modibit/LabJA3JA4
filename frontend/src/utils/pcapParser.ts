/**
 * Client-Side Binary PCAP & PCAPNG Parser (Zero External Dependencies)
 * Parses .pcap and .pcapng files directly in the browser using DataView.
 * Extracts TLS ClientHello packets, cipher suites, extensions, SNI, ALPN, etc.
 * Computes JA3 and JA4 completely offline.
 */

import { computeJA3, type JA3Result } from "./ja3";
import { computeJA4, type JA4Result } from "./ja4";

export interface ParsedClientHelloPacket {
  packetIndex: number;
  timestamp: number;
  timestampStr: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  clientHello: {
    recordVersion: number;
    clientVersion: number;
    ciphers: number[];
    extensions: number[];
    curves: number[];
    pointFormats: number[];
    sigAlgs: number[];
    alpn: string[];
    supportedVersions: number[];
    sni: string;
    sessionId: string;
  };
  ja3: JA3Result;
  ja4: JA4Result;
}

function parseClientHelloPayload(bytes: Uint8Array): {
  recordVersion: number;
  clientVersion: number;
  ciphers: number[];
  extensions: number[];
  curves: number[];
  pointFormats: number[];
  sigAlgs: number[];
  alpn: string[];
  supportedVersions: number[];
  sni: string;
  sessionId: string;
} | null {
  if (bytes.length < 9) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // ContentType must be Handshake (0x16 = 22)
  if (view.getUint8(0) !== 0x16) return null;
  const recordVersion = view.getUint16(1);

  // Handshake type must be ClientHello (0x01)
  if (view.getUint8(5) !== 0x01) return null;

  let offset = 9; // Handshake header (1 byte type + 3 bytes length)
  if (offset + 34 > bytes.length) return null;

  const clientVersion = view.getUint16(offset);
  offset += 2;

  // Random: 32 bytes
  offset += 32;

  // Session ID
  if (offset >= bytes.length) return null;
  const sessionIdLen = view.getUint8(offset);
  offset += 1;
  let sessionId = "";
  for (let i = 0; i < sessionIdLen && offset + i < bytes.length; i++) {
    sessionId += view.getUint8(offset + i).toString(16).padStart(2, "0");
  }
  offset += sessionIdLen;

  // Cipher Suites
  if (offset + 2 > bytes.length) return null;
  const cipherSuitesLen = view.getUint16(offset);
  offset += 2;

  if (offset + cipherSuitesLen > bytes.length) return null;
  const ciphers: number[] = [];
  for (let i = 0; i < cipherSuitesLen; i += 2) {
    ciphers.push(view.getUint16(offset + i));
  }
  offset += cipherSuitesLen;

  // Compression Methods
  if (offset >= bytes.length) return null;
  const compLen = view.getUint8(offset);
  offset += 1 + compLen;

  // Extensions
  const extensions: number[] = [];
  const curves: number[] = [];
  const pointFormats: number[] = [];
  const sigAlgs: number[] = [];
  const alpn: string[] = [];
  const supportedVersions: number[] = [];
  let sni = "";

  if (offset + 2 <= bytes.length) {
    const extTotalLen = view.getUint16(offset);
    offset += 2;
    const extEnd = Math.min(offset + extTotalLen, bytes.length);

    while (offset + 4 <= extEnd) {
      const extType = view.getUint16(offset);
      const extLen = view.getUint16(offset + 2);
      offset += 4;
      const extDataOffset = offset;
      offset += extLen;

      extensions.push(extType);

      if (extType === 0x0000) {
        // SNI
        try {
          if (extLen >= 5) {
            const nameType = view.getUint8(extDataOffset + 2);
            if (nameType === 0) {
              const nameLen = view.getUint16(extDataOffset + 3);
              const nameBytes = bytes.subarray(extDataOffset + 5, extDataOffset + 5 + nameLen);
              sni = new TextDecoder().decode(nameBytes);
            }
          }
        } catch {}
      } else if (extType === 0x000a) {
        // Supported Groups (Curves)
        try {
          if (extLen >= 2) {
            const curvesLen = view.getUint16(extDataOffset);
            for (let c = 2; c < Math.min(2 + curvesLen, extLen); c += 2) {
              curves.push(view.getUint16(extDataOffset + c));
            }
          }
        } catch {}
      } else if (extType === 0x000b) {
        // EC Point Formats
        try {
          if (extLen >= 1) {
            const pfLen = view.getUint8(extDataOffset);
            for (let p = 1; p <= Math.min(pfLen, extLen - 1); p++) {
              pointFormats.push(view.getUint8(extDataOffset + p));
            }
          }
        } catch {}
      } else if (extType === 0x000d) {
        // Signature Algorithms
        try {
          if (extLen >= 2) {
            const saLen = view.getUint16(extDataOffset);
            for (let s = 2; s < Math.min(2 + saLen, extLen); s += 2) {
              sigAlgs.push(view.getUint16(extDataOffset + s));
            }
          }
        } catch {}
      } else if (extType === 0x0010) {
        // ALPN
        try {
          if (extLen >= 2) {
            let aOffset = extDataOffset + 2;
            const aEnd = extDataOffset + extLen;
            while (aOffset < aEnd) {
              const pLen = view.getUint8(aOffset);
              aOffset += 1;
              if (aOffset + pLen <= aEnd) {
                const protoBytes = bytes.subarray(aOffset, aOffset + pLen);
                alpn.push(new TextDecoder().decode(protoBytes));
              }
              aOffset += pLen;
            }
          }
        } catch {}
      } else if (extType === 0x002b) {
        // Supported Versions
        try {
          if (extLen >= 1) {
            const svLen = view.getUint8(extDataOffset);
            for (let v = 1; v < Math.min(1 + svLen, extLen); v += 2) {
              supportedVersions.push(view.getUint16(extDataOffset + v));
            }
          }
        } catch {}
      }
    }
  }

  return {
    recordVersion,
    clientVersion,
    ciphers,
    extensions,
    curves,
    pointFormats,
    sigAlgs,
    alpn,
    supportedVersions,
    sni,
    sessionId,
  };
}

function parseIpPacket(
  packetBytes: Uint8Array,
  linkType: number
): { srcIp: string; dstIp: string; srcPort: number; dstPort: number; tcpPayload: Uint8Array } | null {
  const view = new DataView(packetBytes.buffer, packetBytes.byteOffset, packetBytes.byteLength);
  let offset = 0;
  let ethType = 0;

  if (linkType === 1) {
    // Ethernet
    if (packetBytes.length < 14) return null;
    ethType = view.getUint16(12);
    offset = 14;
    if (ethType === 0x8100) {
      if (packetBytes.length < 18) return null;
      ethType = view.getUint16(16);
      offset = 18;
    }
  } else if (linkType === 113) {
    // Linux Cooked
    if (packetBytes.length < 16) return null;
    ethType = view.getUint16(14);
    offset = 16;
  } else {
    // Raw IP
    const ipVer = (packetBytes[0] >> 4) & 0x0f;
    ethType = ipVer === 4 ? 0x0800 : 0x86dd;
    offset = 0;
  }

  let proto = 0;
  let srcIp = "";
  let dstIp = "";

  if (ethType === 0x0800) {
    // IPv4
    if (packetBytes.length < offset + 20) return null;
    const ihl = (view.getUint8(offset) & 0x0f) * 4;
    proto = view.getUint8(offset + 9);
    srcIp = `${view.getUint8(offset + 12)}.${view.getUint8(offset + 13)}.${view.getUint8(offset + 14)}.${view.getUint8(offset + 15)}`;
    dstIp = `${view.getUint8(offset + 16)}.${view.getUint8(offset + 17)}.${view.getUint8(offset + 18)}.${view.getUint8(offset + 19)}`;
    offset += ihl;
  } else if (ethType === 0x86dd) {
    // IPv6
    if (packetBytes.length < offset + 40) return null;
    proto = view.getUint8(offset + 6);
    srcIp = "IPv6-Client";
    dstIp = "IPv6-Server";
    offset += 40;
  } else {
    return null;
  }

  if (proto !== 6) return null; // TCP only

  if (packetBytes.length < offset + 20) return null;
  const srcPort = view.getUint16(offset);
  const dstPort = view.getUint16(offset + 2);
  const dataOffset = ((view.getUint8(offset + 12) >> 4) & 0x0f) * 4;
  const tcpPayload = packetBytes.subarray(offset + dataOffset);

  return { srcIp, dstIp, srcPort, dstPort, tcpPayload };
}

/**
 * Parse an ArrayBuffer of a PCAP or PCAPNG file completely in browser.
 */
export function parsePcapArrayBuffer(buffer: ArrayBuffer): ParsedClientHelloPacket[] {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 24) return [];
  const view = new DataView(buffer);
  const results: ParsedClientHelloPacket[] = [];

  const magic = view.getUint32(0, false);

  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
    const isLittle = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
    const linkType = view.getUint32(20, isLittle);

    let offset = 24;
    let packetIndex = 0;

    while (offset + 16 <= bytes.length) {
      packetIndex++;
      const tsSec = view.getUint32(offset, isLittle);
      const tsUsec = view.getUint32(offset + 4, isLittle);
      const inclLen = view.getUint32(offset + 8, isLittle);
      offset += 16;

      if (offset + inclLen > bytes.length) break;
      const packetBytes = bytes.subarray(offset, offset + inclLen);
      offset += inclLen;

      const ipInfo = parseIpPacket(packetBytes, linkType);
      if (!ipInfo) continue;

      const ch = parseClientHelloPayload(ipInfo.tcpPayload);
      if (!ch) continue;

      const ja3 = computeJA3(ch.clientVersion, ch.ciphers, ch.extensions, ch.curves, ch.pointFormats);
      const isSniIp = /^\d+\.\d+\.\d+\.\d+$/.test(ch.sni);
      const ja4 = computeJA4({
        protocol: "t",
        version: ch.clientVersion,
        hasSni: Boolean(ch.sni),
        sniIsIp: isSniIp,
        ciphers: ch.ciphers,
        extensions: ch.extensions,
        alpnProtocols: ch.alpn,
        signatureAlgorithms: ch.sigAlgs,
        supportedVersions: ch.supportedVersions,
      });

      const date = new Date(tsSec * 1000);
      const timestampStr = date.toISOString().replace("T", " ").replace("Z", "");

      results.push({
        packetIndex,
        timestamp: tsSec + tsUsec / 1000000,
        timestampStr,
        srcIp: ipInfo.srcIp,
        dstIp: ipInfo.dstIp,
        srcPort: ipInfo.srcPort,
        dstPort: ipInfo.dstPort,
        clientHello: ch,
        ja3,
        ja4,
      });
    }
  }

  return results;
}
