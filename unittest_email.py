import unittest
from unittest.mock import patch, Mock, MagicMock
import re
import hashlib
from io import BytesIO
from email import policy
from email.parser import BytesParser
from email_for import (
    hash_password,
    verify_password,
    validate_name,
    validate_gmail,
    validate_username,
    validate_password,
    analyze_email_headers,
    calculate_sha256,
    check_malware,
    check_spf,
    check_dkim,
    check_dmarc,
)

SAMPLE_EML = b"""From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 02 Mar 2025 12:00:00 +0000
Message-ID: <12345@example.com>
Received: from mail.example.com ([192.168.1.1]) by mx.example.com
Received: from [10.0.0.1] by mail.example.com

This is a test email body.
"""

class TestEmailForensicTool(unittest.TestCase):

    def test_hash_password(self):
        password = "Test@123"
        hashed = hash_password(password)
        self.assertIsInstance(hashed, str)
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "Wrong@123"))

    def test_validate_name(self):
        self.assertTrue(validate_name("John"))
        self.assertFalse(validate_name("john"))
        self.assertFalse(validate_name("J"))
        self.assertFalse(validate_name("John123"))

    def test_validate_gmail(self):
        self.assertTrue(validate_gmail("test123@gmail.com"))
        self.assertFalse(validate_gmail("test@outlook.com"))
        self.assertFalse(validate_gmail("t@gmail.com"))

    def test_validate_username(self):
        self.assertTrue(validate_username("user123!"))
        self.assertFalse(validate_username("user"))
        self.assertFalse(validate_username("u!1"))

    def test_validate_password(self):
        self.assertTrue(validate_password("Password123!"))
        self.assertFalse(validate_password("password123"))
        self.assertFalse(validate_password("Pw1!"))

    @patch('builtins.open', return_value=BytesIO(SAMPLE_EML))
    def test_analyze_email_headers(self, mock_open):
        headers = analyze_email_headers("dummy.eml")
        self.assertEqual(headers['sender'], "test@example.com")
        self.assertEqual(headers['recipient'], "recipient@example.com")
        self.assertEqual(headers['subject'], "Test Email")
        self.assertIn("192.168.1.1", headers['ip_addresses'])
        self.assertIn("10.0.0.1", headers['ip_addresses'])

    def test_calculate_sha256(self):
        data = b"test data"
        expected_hash = hashlib.sha256(data).hexdigest()
        self.assertEqual(calculate_sha256(data), expected_hash)

    def test_check_malware(self):
        known_hashes = {"abc123", "def456"}
        self.assertTrue(check_malware("abc123", known_hashes))
        self.assertFalse(check_malware("xyz789", known_hashes))

    @patch('dns.resolver.resolve')
    def test_check_spf(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(to_text=lambda: "v=spf1 include:example.com -all")]
        self.assertTrue(check_spf("example.com"))
        mock_resolve.side_effect = Exception("DNS error")
        self.assertFalse(check_spf("example.com"))

    @patch('dns.resolver.resolve')
    def test_check_dkim(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(to_text=lambda: "v=DKIM1; k=rsa; p=publickey")]
        self.assertTrue(check_dkim("example.com"))
        mock_resolve.side_effect = Exception("DNS error")
        self.assertFalse(check_dkim("example.com"))

    @patch('dns.resolver.resolve')
    def test_check_dmarc(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(to_text=lambda: "v=DMARC1; p=reject;")]
        self.assertTrue(check_dmarc("example.com"))
        mock_resolve.side_effect = Exception("DNS error")
        self.assertFalse(check_dmarc("example.com"))

if __name__ == '__main__':
    unittest.main()