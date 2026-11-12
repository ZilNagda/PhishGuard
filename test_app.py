import unittest
from unittest.mock import patch
from app import analyze_url


class TestPhishGuard(unittest.TestCase):

    def test_invalid_domain_format(self):

        result = analyze_url("https://-bad-domain.com")

        self.assertEqual(result[0], "-bad-domain.com")
        self.assertEqual(result[1], 0)
        self.assertEqual(result[3], "Invalid URL")

    @patch("app.socket.getaddrinfo")
    def test_valid_https_url(self, mock_dns):

        mock_dns.return_value = []

        result = analyze_url("https://example.com")

        self.assertEqual(result[0], "example.com")
        self.assertEqual(result[1], 0)
        self.assertEqual(result[3], "Low")

    @patch("app.socket.getaddrinfo")
    def test_suspicious_url(self, mock_dns):

        mock_dns.return_value = []

        result = analyze_url("http://example.com/login")

        self.assertEqual(result[0], "example.com")
        self.assertEqual(result[1], 2)
        self.assertEqual(result[3], "Medium")
        self.assertTrue(len(result[2]) > 0)


if __name__ == "__main__":
    unittest.main()