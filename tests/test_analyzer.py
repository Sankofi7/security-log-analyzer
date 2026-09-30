import subprocess
import sys
import unittest


class TestAnalyzerCLI(unittest.TestCase):

    def test_help_command(self):

        result = subprocess.run(
            [
                sys.executable,
                "src/analyzer.py",
                "--help"
            ],
            capture_output=True,
            text=True
        )

        self.assertEqual(
            result.returncode,
            0
        )

        self.assertIn(
            "--log",
            result.stdout
        )

        self.assertIn(
            "--config",
            result.stdout
        )

        self.assertIn(
            "--output",
            result.stdout
        )

    def test_missing_log_file(self):

        result = subprocess.run(
            [
                sys.executable,
                "src/analyzer.py",
                "--log",
                "logs/does-not-exist.log"
            ],
            capture_output=True,
            text=True
        )

        self.assertNotEqual(
            result.returncode,
            0
        )

        self.assertIn(
            "Log file not found",
            result.stderr
        )


if __name__ == "__main__":
    unittest.main()