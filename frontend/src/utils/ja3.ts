/**
 * Salesforce JA3 TLS Client Fingerprint Implementation
 * Strictly conforms to https://github.com/salesforce/ja3 specification.
 */

import { md5 } from "./crypto";

export const GREASE_SET = new Set<number>([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
  0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa
]);

/**
 * Checks if a 16-bit integer is a GREASE value per RFC 8701.
 */
export function isGrease(val: number): boolean {
  if (GREASE_SET.has(val)) return true;
  return (val & 0x0f0f) === 0x0a0a && ((val >> 8) & 0xff) === (val & 0xff);
}

export interface JA3Result {
  raw: string;
  hash: string;
  version: number;
  ciphers: number[];
  extensions: number[];
  curves: number[];
  pointFormats: number[];
  greaseFilteredCiphers: number[];
  greaseFilteredExtensions: number[];
  greaseFilteredCurves: number[];
  parts: {
    versionStr: string;
    ciphersStr: string;
    extensionsStr: string;
    curvesStr: string;
    pointFormatsStr: string;
  };
}

/**
 * Computes official JA3 fingerprint.
 * Official test vector:
 * 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
 * MD5: ada70206e40642a3e4461f35503241d5
 */
export function computeJA3(
  version: number,
  ciphers: number[],
  extensions: number[],
  curves: number[] = [],
  pointFormats: number[] = []
): JA3Result {
  const filteredCiphers = ciphers.filter((c) => !isGrease(c));
  const filteredExtensions = extensions.filter((e) => !isGrease(e));
  const filteredCurves = curves.filter((c) => !isGrease(c));
  const filteredPointFormats = pointFormats.filter((p) => !isGrease(p));

  const greaseCiphers = ciphers.filter((c) => isGrease(c));
  const greaseExtensions = extensions.filter((e) => isGrease(e));
  const greaseCurves = curves.filter((c) => isGrease(c));

  const versionStr = version.toString();
  const ciphersStr = filteredCiphers.join("-");
  const extensionsStr = filteredExtensions.join("-");
  const curvesStr = filteredCurves.join("-");
  const pointFormatsStr = filteredPointFormats.join("-");

  const raw = `${versionStr},${ciphersStr},${extensionsStr},${curvesStr},${pointFormatsStr}`;
  const hash = md5(raw);

  return {
    raw,
    hash,
    version,
    ciphers: filteredCiphers,
    extensions: filteredExtensions,
    curves: filteredCurves,
    pointFormats: filteredPointFormats,
    greaseFilteredCiphers: greaseCiphers,
    greaseFilteredExtensions: greaseExtensions,
    greaseFilteredCurves: greaseCurves,
    parts: {
      versionStr,
      ciphersStr,
      extensionsStr,
      curvesStr,
      pointFormatsStr,
    },
  };
}
