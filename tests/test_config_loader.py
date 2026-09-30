import json
import os
import tempfile
import unittest

from src.config_loader import load_config


class TestConfigLoader(unittest.TestCase):

    def create_temp_config(self, data):
        """
        Create a temporary JSON configuration file.
        """

        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            suffix=".json"
        )

        json.dump(data, temp_file)

        temp_file.close()

        return temp_file.name

    def test_valid_configuration(self):

        config_file = self.create_temp_config({
            "repeated_login_threshold": 5,
            "account_targeting_threshold": 4,
            "login_burst_threshold": 3,
            "login_burst_window_seconds": 120
        })

        try:
            config = load_config(config_file)

            self.assertEqual(
                config["repeated_login_threshold"],
                5
            )

            self.assertEqual(
                config["login_burst_window_seconds"],
                120
            )

        finally:
            os.remove(config_file)

    def test_missing_setting_uses_default(self):

        config_file = self.create_temp_config({
            "repeated_login_threshold": 5
        })

        try:
            config = load_config(config_file)

            self.assertEqual(
                config["repeated_login_threshold"],
                5
            )

            self.assertEqual(
                config["account_targeting_threshold"],
                3
            )

            self.assertEqual(
                config["login_burst_window_seconds"],
                60
            )

        finally:
            os.remove(config_file)

    def test_invalid_type_is_rejected(self):

        config_file = self.create_temp_config({
            "repeated_login_threshold": "three"
        })

        try:
            with self.assertRaises(ValueError):
                load_config(config_file)

        finally:
            os.remove(config_file)

    def test_negative_value_is_rejected(self):

        config_file = self.create_temp_config({
            "login_burst_window_seconds": -60
        })

        try:
            with self.assertRaises(ValueError):
                load_config(config_file)

        finally:
            os.remove(config_file)


if __name__ == "__main__":
    unittest.main()