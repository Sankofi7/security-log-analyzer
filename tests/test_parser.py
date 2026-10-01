import unittest

from src.parser import parse_failed_login


class TestParser(unittest.TestCase):
    def test_parse_ubuntu_iso_failed_login(self):
        line = (
            "2026-10-01T16:41:49.619910+00:00 "
            "sankofi sshd[8028]: "
            "Failed password for admin "
            "from 172.16.112.1 port 52952 ssh2"
        )

        result = parse_failed_login(line)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["username"],
            "admin"
        )
        self.assertEqual(
            result["ip_address"],
            "172.16.112.1"
        )
        self.assertEqual(
            result["timestamp"].year,
            2026
        )
        self.assertEqual(
            result["timestamp"].month,
            10
        )
        self.assertEqual(
            result["timestamp"].day,
            1
        )
    def test_valid_failed_login(self):

        log_line = (
            "Sep 17 10:20:01 server sshd[1030]: "
            "Failed password for admin from "
            "172.16.0.50 port 40101 ssh2"
        )

        result = parse_failed_login(log_line)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["username"],
            "admin"
        )
        self.assertEqual(
            result["ip_address"],
            "172.16.0.50"
        )

    def test_successful_login_is_ignored(self):

        log_line = (
            "Sep 17 10:16:03 server sshd[1024]: "
            "Accepted password for john from "
            "192.168.1.10 port 50120 ssh2"
        )

        result = parse_failed_login(log_line)

        self.assertIsNone(result)

    def test_malformed_log_is_ignored(self):

        log_line = "Failed password broken log"

        result = parse_failed_login(log_line)

        self.assertIsNone(result)

    def test_invalid_user_failed_login(self):

        log_line = (
            "Sep 17 10:25:01 server sshd[1040]: "
            "Failed password for invalid user attacker "
            "from 203.0.113.25 port 45000 ssh2"
        )

        result = parse_failed_login(log_line)

        self.assertIsNotNone(result)

        self.assertEqual(
            result["username"],
            "attacker"
        )

        self.assertEqual(
            result["ip_address"],
            "203.0.113.25"
        )
if __name__ == "__main__":
    unittest.main()