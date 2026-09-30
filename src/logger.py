import logging
import os

from logging.handlers import RotatingFileHandler


def setup_logger(
    log_file="logs/analyzer.log",
    max_bytes=1_000_000,
    backup_count=3
):
    """
    Configure and return the application logger
    with automatic log rotation.
    """

    log_directory = os.path.dirname(log_file)

    if log_directory:
        os.makedirs(
            log_directory,
            exist_ok=True
        )

    logger = logging.getLogger(
        "security_log_analyzer"
    )

    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger