import os
import tempfile
import unittest

from src.reporter import save_json_report


class TestReporter(unittest.TestCase):

    def test_report_directory_is_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(
                temp_dir,
                "new_reports",
                "security_report.json"
            )

            save_json_report(
                failed_attempts=0,
                failed_ips={},
                targeted_users={},
                ip_targeted_users={},
                repeated_login_alerts=[],
                account_targeting_alerts=[],
                login_burst_alerts=[],
                output_file=output_file
            )

            self.assertTrue(
                os.path.exists(output_file)
            )


if __name__ == "__main__":
    unittest.main()