import unittest
from datetime import datetime

from src.detector import (
    detect_repeated_logins,
    detect_account_targeting,
    detect_login_bursts
)


class TestDetector(unittest.TestCase):

    def test_repeated_login_detection(self):

        failed_ips = {
            "192.168.1.25": 3,
            "10.0.0.15": 2,
            "172.16.0.50": 5
        }

        alerts = detect_repeated_logins(
            failed_ips
        )

        self.assertEqual(len(alerts), 2)

        alert_ips = [
            alert["ip_address"]
            for alert in alerts
        ]

        self.assertIn(
            "192.168.1.25",
            alert_ips
        )

        self.assertIn(
            "172.16.0.50",
            alert_ips
        )

        self.assertNotIn(
            "10.0.0.15",
            alert_ips
        )

    def test_account_targeting_detection(self):

        targeted_users = {
            "192.168.1.25": {"admin"},
            "10.0.0.15": {"root"},
            "172.16.0.50": {
                "admin",
                "root",
                "john",
                "guest",
                "test"
            }
        }

        alerts = detect_account_targeting(
            targeted_users
        )

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["ip_address"],
            "172.16.0.50"
        )

        self.assertEqual(
            alerts[0]["unique_accounts"],
            5
        )

    def test_login_burst_detection(self):

        failed_times = {
            "192.168.1.25": [
                datetime(2026, 9, 17, 10, 15, 1),
                datetime(2026, 9, 17, 10, 15, 7),
                datetime(2026, 9, 17, 10, 15, 14)
            ],

            "10.0.0.15": [
                datetime(2026, 9, 17, 10, 17, 11),
                datetime(2026, 9, 17, 10, 17, 18)
            ]
        }

        alerts = detect_login_bursts(
            failed_times
        )

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["ip_address"],
            "192.168.1.25"
        )

        self.assertEqual(
            alerts[0]["attempts"],
            3
        )


if __name__ == "__main__":
    unittest.main()