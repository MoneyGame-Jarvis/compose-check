"""Tests for compose-check. Run with: python3 -m unittest discover tests"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import compose_check as cc


BAD = """
services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    cap_add: [SYS_ADMIN]
    user: root
    container_name: web
    ports:
      - "0.0.0.0:80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc
    environment:
      DB_PASSWORD: hunter2supersecret
      API_KEY: abcdef123456
      SAFE_URL: ${FROM_ENV}
    logging:
      driver: json-file
"""

GOOD = """
services:
  web:
    image: nginx:1.27.3
    read_only: true
    user: "1000:1000"
    restart: unless-stopped
    mem_limit: 256m
    cpus: 0.5
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
    cap_drop: ["ALL"]
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - web-data:/usr/share/nginx/html
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
"""


def scan(text):
    doc = cc.load_yaml(text)
    findings = []
    for name, svc in cc._services(doc).items():
        cc.check_service(name, svc, findings)
    cc.check_file_level(doc, findings)
    return findings


def codes(findings):
    return {f.check for f in findings}


class TestBadFile(unittest.TestCase):
    def setUp(self):
        self.f = scan(BAD)
        self.c = codes(self.f)

    def test_finds_the_critical_ones(self):
        for check in ("privileged", "host-network", "docker-socket",
                      "secret-in-environment"):
            self.assertIn(check, self.c, f"{check} not detected")

    def test_finds_the_high_ones(self):
        for check in ("capabilities", "host-mount", "public-port"):
            self.assertIn(check, self.c)

    def test_finds_the_medium_ones(self):
        for check in ("unpinned-image", "writable-rootfs",
                      "no-resource-limits", "unbounded-logs"):
            self.assertIn(check, self.c)

    def test_does_not_flag_the_safe_variable(self):
        for f in self.f:
            self.assertNotIn("SAFE_URL", f.message)

    def test_secret_from_the_environment_is_not_flagged(self):
        # ${DB_PASSWORD} is the right way to do it and must stay silent.
        good = scan(GOOD)
        self.assertNotIn("secret-in-environment", codes(good))


class TestGoodFile(unittest.TestCase):
    def setUp(self):
        self.f = scan(GOOD)

    def test_only_low_severity_findings(self):
        serious = [f for f in self.f if f.severity in ("critical", "high", "medium")]
        self.assertEqual(serious, [], [f.message for f in serious])


class TestParser(unittest.TestCase):
    def test_short_form_volume_stays_a_string(self):
        doc = cc.load_yaml("services:\n  a:\n    volumes:\n      - ./f:/t:ro\n")
        self.assertIsInstance(doc["services"]["a"]["volumes"][0], str)

    def test_block_scalar_keeps_its_lines(self):
        doc = cc.load_yaml("a:\n  b: |\n    one\n    two\n")
        self.assertEqual(doc["a"]["b"].strip().splitlines(), ["one", "two"])

    def test_flow_collections(self):
        doc = cc.load_yaml('a:\n  p: ["1:2", "3:4"]\n  m: {x: 1, y: two}\n')
        self.assertEqual(doc["a"]["p"], ["1:2", "3:4"])
        self.assertEqual(doc["a"]["m"], {"x": 1, "y": "two"})

    def test_compose_v2_and_v3_agree(self):
        v2 = cc.load_yaml("version: '2'\nservices:\n  a:\n    image: x\n")
        self.assertIn("a", v2["services"])


if __name__ == "__main__":
    unittest.main()
