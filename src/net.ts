// ============================================================================
// SSRF PROTECTION
// ============================================================================
//
// Outbound URLs supplied by callers (webhook subscription targets, workflow
// step endpoints) must never be able to reach this host's own network. Without
// these checks a caller can point the service at 169.254.169.254 and read cloud
// instance credentials, or sweep RFC1918 space from inside the perimeter.
//
// Deny ranges mirror the reviewed list in Kleos (kleos-lib/src/webhooks.rs).
//
// Two levels are provided:
//   validateUrl            -- synchronous, literal hostname/IP only. Cheap.
//                             Use at persist time to reject obvious junk early.
//   resolveAndValidateUrl  -- resolves DNS and checks every returned address.
//                             Use at delivery time; catches a hostname that
//                             was public when stored and private when used.
//
// safeFetch composes both and additionally revalidates every redirect hop,
// since an allowed origin can 302 to an internal one.

import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

// Hostnames that resolve to loopback regardless of DNS.
const LOOPBACK_NAMES = new Set(["localhost", "localhost.localdomain"]);

// Cloud instance-metadata hostnames commonly abused for credential theft.
const METADATA_NAMES = new Set(["metadata", "metadata.goog", "metadata.google.internal"]);

// Maximum redirect hops followed by safeFetch before giving up.
const MAX_REDIRECTS = 5;

/// Parse a dotted-quad IPv4 string into its four octets.
/// Returns null when the input is not a well-formed IPv4 literal.
function ipv4Octets(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/// Returns true when an IPv4 address falls in a range that must never be
/// reachable from an outbound request.
export function isIpv4Denied(ip: string): boolean {
  const o = ipv4Octets(ip);
  if (!o) return true; // unparseable means untrusted
  // 0.0.0.0/8 (includes unspecified)
  if (o[0] === 0) return true;
  // 127.0.0.0/8 loopback
  if (o[0] === 127) return true;
  // 10.0.0.0/8 private
  if (o[0] === 10) return true;
  // 172.16.0.0/12 private
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  // 192.168.0.0/16 private
  if (o[0] === 192 && o[1] === 168) return true;
  // 169.254.0.0/16 link-local, includes AWS metadata 169.254.169.254
  if (o[0] === 169 && o[1] === 254) return true;
  // 100.64.0.0/10 CGNAT
  if (o[0] === 100 && (o[1] & 0xc0) === 64) return true;
  // 224.0.0.0/4 multicast
  if (o[0] >= 224 && o[0] <= 239) return true;
  // 255.255.255.255 broadcast
  if (o[0] === 255 && o[1] === 255 && o[2] === 255 && o[3] === 255) return true;
  return false;
}

/// Expand an IPv6 literal into its eight 16-bit segments, handling "::"
/// compression and trailing embedded IPv4. Returns null if unparseable.
function ipv6Segments(ip: string): number[] | null {
  let text = ip.toLowerCase();
  // Strip a zone index such as %eth0.
  const zone = text.indexOf("%");
  if (zone !== -1) text = text.slice(0, zone);

  // A trailing dotted-quad (::ffff:127.0.0.1) is rewritten into the two hex
  // groups it represents, so the rest of the parse has one uniform shape.
  const lastColon = text.lastIndexOf(":");
  const maybeV4 = text.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const o = ipv4Octets(maybeV4);
    if (!o) return null;
    const hi = (((o[0] << 8) | o[1]) >>> 0).toString(16);
    const lo = (((o[2] << 8) | o[3]) >>> 0).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;

  const toSegs = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const piece of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
      out.push(parseInt(piece, 16));
    }
    return out;
  };

  const head = toSegs(halves[0]);
  if (!head) return null;
  if (halves.length === 1) {
    return head.length === 8 ? head : null;
  }
  const rest = toSegs(halves[1]);
  if (!rest) return null;
  const known = head.length + rest.length;
  if (known > 8) return null;
  const gap = new Array(8 - known).fill(0);
  return head.concat(gap, rest);
}

/// Returns true when an IPv6 address falls in a denied range, including
/// IPv4-mapped forms of denied IPv4 ranges (for example ::ffff:127.0.0.1).
export function isIpv6Denied(ip: string): boolean {
  const s = ipv6Segments(ip);
  if (!s) return true; // unparseable means untrusted

  // Unspecified ::
  if (s.every((seg) => seg === 0)) return true;
  // Loopback ::1
  if (s.slice(0, 7).every((seg) => seg === 0) && s[7] === 1) return true;
  // Multicast ff00::/8
  if ((s[0] & 0xff00) === 0xff00) return true;
  // Unique local fc00::/7
  if ((s[0] & 0xfe00) === 0xfc00) return true;
  // Link-local fe80::/10
  if ((s[0] & 0xffc0) === 0xfe80) return true;

  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d
  const firstSixZero = s.slice(0, 5).every((seg) => seg === 0);
  if (firstSixZero && (s[5] === 0xffff || s[5] === 0)) {
    const a = (s[6] >> 8) & 0xff;
    const b = s[6] & 0xff;
    const c = (s[7] >> 8) & 0xff;
    const d = s[7] & 0xff;
    if (isIpv4Denied(`${a}.${b}.${c}.${d}`)) return true;
  }
  return false;
}

/// Returns true when a bare IP string of either family is denied.
export function isIpDenied(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isIpv4Denied(ip);
  if (family === 6) return isIpv6Denied(ip);
  return true; // not an IP at all
}

/// Synchronously validate a caller-supplied URL against scheme and literal
/// host rules. Throws a descriptive Error on rejection, returns the parsed URL
/// on success. Does not resolve DNS -- see resolveAndValidateUrl for that.
export function validateUrl(raw: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`invalid URL: ${raw}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL must use http or https");
  }
  // Embedded credentials are a common way to disguise the real target.
  if (parsed.username || parsed.password) {
    throw new Error("URL must not contain embedded credentials");
  }

  // URL normalises IPv6 literals to bracketed form; strip for classification.
  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) throw new Error("URL is missing a host");

  if (isIP(host)) {
    if (isIpDenied(host)) {
      throw new Error(`URL host ${host} is in a disallowed range`);
    }
    return parsed;
  }

  if (LOOPBACK_NAMES.has(host) || host.endsWith(".localhost")) {
    throw new Error("URL host resolves to loopback");
  }
  if (METADATA_NAMES.has(host)) {
    throw new Error("URL host is a cloud metadata endpoint");
  }
  return parsed;
}

/// Validate a URL and resolve its hostname, rejecting if ANY returned address
/// is in a denied range. Returns the parsed URL together with the addresses
/// that passed, so callers can log what they connected to.
///
/// Call this immediately before dispatch. Validating only at persist time
/// leaves a DNS-rebinding window where a host that was public when stored
/// points somewhere internal by the time it is used.
export async function resolveAndValidateUrl(raw: string): Promise<{ url: URL; addresses: string[] }> {
  const url = validateUrl(raw);
  const host = url.hostname.replace(/^\[|\]$/g, "");

  // A literal IP already passed the range check in validateUrl.
  if (isIP(host)) return { url, addresses: [host] };

  let results: { address: string }[];
  try {
    results = await lookup(host, { all: true });
  } catch (e) {
    throw new Error(`could not resolve URL host ${host}: ${(e as Error).message}`);
  }
  if (!results.length) throw new Error(`URL host ${host} resolved to no addresses`);

  for (const r of results) {
    if (isIpDenied(r.address)) {
      throw new Error(`URL host ${host} resolves to disallowed address ${r.address}`);
    }
  }
  return { url, addresses: results.map((r) => r.address) };
}

/// fetch() wrapper that validates the target before connecting and revalidates
/// every redirect hop. Redirects are followed manually because an allowed
/// origin can redirect to an internal one, which automatic following would
/// hide entirely.
export async function safeFetch(raw: string, init: RequestInit = {}): Promise<Response> {
  let target = raw;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await resolveAndValidateUrl(target);
    const res = await fetch(target, { ...init, redirect: "manual" });
    const isRedirect = res.status >= 300 && res.status < 400 && res.headers.has("location");
    if (!isRedirect) return res;
    const location = res.headers.get("location") as string;
    target = new URL(location, target).toString();
  }
  throw new Error(`too many redirects (max ${MAX_REDIRECTS})`);
}
