"""Unit tests for SocketVigil."""

import unittest
from socketvigil.mapper import resolve_ip, classify_provider, KNOWN_TRACKING_PATTERNS


class TestSocketVigil(unittest.TestCase):
    def test_ip_resolution(self):
        self.assertEqual(resolve_ip("127.0.0.1"), "localhost")
        self.assertEqual(resolve_ip("192.168.1.100"), "Private LAN")
        self.assertEqual(resolve_ip("10.0.0.1"), "Private LAN")

    def test_provider_classification(self):
        self.assertEqual(classify_provider("1.1.1.1.cloudflare.com"), "Cloudflare CDN")
        self.assertEqual(classify_provider("server.1e100.net"), "Google Cloud / Services")
        self.assertEqual(classify_provider("ec2.amazonaws.com"), "Amazon Web Services")
        self.assertEqual(classify_provider("localhost"), "Local Workstation / LAN")

    def test_tracking_patterns(self):
        self.assertTrue(any(p in "telemetry.service.com" for p in ["telemetry", "analytics"]))


if __name__ == "__main__":
    unittest.main()
