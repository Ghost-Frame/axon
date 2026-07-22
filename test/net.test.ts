// Tests for the SSRF protection in src/net.ts.
//
// These guard the property that a caller-supplied webhook URL can never be
// used to reach this host's own network. Each denied range is asserted
// explicitly, and the boundaries just outside each range are asserted as
// allowed, so an over-broad mask fails the suite as loudly as a missing one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { isIpDenied, safeFetch, validateUrl } from "../src/net.ts";

// Addresses that must never be reachable from an outbound request.
const DENIED_IPS = [
  "127.0.0.1",
  "127.255.255.254",
  "10.0.0.1",
  "172.16.5.4",
  "172.31.255.255",
  "192.168.1.1",
  "169.254.169.254", // AWS instance metadata
  "100.64.0.1", // CGNAT
  "100.127.255.255",
  "0.0.0.0",
  "255.255.255.255",
  "224.0.0.1", // multicast
  "::1",
  "::",
  "fe80::1", // link-local
  "fc00::1", // unique local
  "fd00::abcd",
  "ff02::1", // multicast
  "::ffff:127.0.0.1", // IPv4-mapped loopback
  "::ffff:169.254.169.254", // IPv4-mapped metadata
  "::127.0.0.1", // IPv4-compatible loopback
];

// Public addresses, including values one step outside each denied range.
const ALLOWED_IPS = [
  "8.8.8.8",
  "1.1.1.1",
  "93.184.216.34",
  "172.15.0.1", // just below 172.16/12
  "172.32.0.1", // just above 172.16/12
  "100.63.255.255", // just below 100.64/10
  "100.128.0.1", // just above 100.64/10
  "2606:4700:4700::1111",
  "2001:4860:4860::8888",
];

test("denied IP ranges are rejected", () => {
  for (const ip of DENIED_IPS) {
    assert.equal(isIpDenied(ip), true, `${ip} should be denied`);
  }
});

test("public addresses just outside denied ranges are allowed", () => {
  for (const ip of ALLOWED_IPS) {
    assert.equal(isIpDenied(ip), false, `${ip} should be allowed`);
  }
});

test("unparseable addresses are treated as denied", () => {
  for (const junk of ["", "not-an-ip", "999.1.1.1", "1.2.3", "::gggg"]) {
    assert.equal(isIpDenied(junk), true, `${junk} should be denied`);
  }
});

test("validateUrl rejects non-http schemes", () => {
  for (const url of ["ftp://example.com/", "file:///etc/passwd", "gopher://example.com/"]) {
    assert.throws(() => validateUrl(url), /must use http or https/, url);
  }
});

test("validateUrl rejects loopback and metadata hostnames", () => {
  assert.throws(() => validateUrl("http://localhost/x"), /loopback/);
  assert.throws(() => validateUrl("http://LOCALHOST/x"), /loopback/);
  assert.throws(() => validateUrl("http://foo.localhost/x"), /loopback/);
  assert.throws(() => validateUrl("http://localhost.localdomain/x"), /loopback/);
  assert.throws(() => validateUrl("http://metadata.google.internal/"), /metadata/);
});

test("validateUrl rejects literal internal IPs", () => {
  assert.throws(() => validateUrl("http://169.254.169.254/latest/meta-data/"), /disallowed range/);
  assert.throws(() => validateUrl("http://127.0.0.1:8080/"), /disallowed range/);
  assert.throws(() => validateUrl("http://[::1]/"), /disallowed range/);
});

test("validateUrl rejects embedded credentials", () => {
  assert.throws(() => validateUrl("http://user:pass@example.com/"), /embedded credentials/);
});

test("validateUrl accepts ordinary public URLs", () => {
  for (const url of [
    "http://example.com/",
    "https://example.com:8443/a?b=c",
    "http://8.8.8.8/",
    "https://[2606:4700:4700::1111]/",
  ]) {
    assert.doesNotThrow(() => validateUrl(url), url);
  }
});

test("safeFetch rejects a redirect from a public target to an internal address", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;

  // Simulates a public endpoint redirecting to instance metadata. The second
  // target must be rejected before the fetch implementation sees it.
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(null, {
      status: 302,
      headers: { location: "http://169.254.169.254/latest/meta-data/" },
    });
  };

  try {
    await assert.rejects(
      safeFetch("http://8.8.8.8/start"),
      /disallowed range/,
    );
    assert.equal(calls, 1, "internal redirect target must never be dispatched");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
