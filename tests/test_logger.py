import logging
import os
import tempfile
import unittest

from src.logger import setup_logger


class TestLogger(unittest.TestCase):

    def tearDown(self):
        """
        Remove handlers after each test.
        """

        logger = logging.getLogger(
            "security_log_analyzer"
        )

        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

    def test_log_rotation(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            log_file = os.path.join(
                temp_dir,
                "test.log"
            )

            logger = setup_logger(
                log_file=log_file,
                max_bytes=200,
                backup_count=2
            )

            for number in range(50):
                logger.info(
                    "Test security analyzer log message %d",
                    number
                )

            # Flush data before checking files
            for handler in logger.handlers:
                handler.flush()

            self.assertTrue(
                os.path.exists(log_file)
            )

            self.assertTrue(
                os.path.exists(
                    log_file + ".1"
                )
            )


if __name__ == "__main__":
    unittest.main()