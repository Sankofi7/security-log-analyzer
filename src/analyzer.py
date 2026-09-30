import argparse

from parser import parse_failed_login

from detector import (
    detect_repeated_logins,
    detect_account_targeting,
    detect_login_bursts
)

from reporter import (
    display_summary,
    display_alerts,
    save_json_report
)

from config_loader import load_config
from logger import setup_logger


def create_argument_parser():
    """
    Create and configure the command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Analyze SSH authentication logs "
            "and detect suspicious login activity."
        )
    )

    parser.add_argument(
        "-l",
        "--log",
        default="logs/auth.log",
        help=(
            "Path to the authentication log file "
            "(default: logs/auth.log)"
        )
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config/config.json",
        help=(
            "Path to the configuration file "
            "(default: config/config.json)"
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default="reports/security_report.json",
        help=(
            "Path for the JSON security report "
            "(default: reports/security_report.json)"
        )
    )

    return parser


def analyze_log(log_file):
    """
    Read an SSH authentication log and collect
    failed-login statistics.
    """

    failed_attempts = 0
    failed_ips = {}
    targeted_users = {}
    ip_targeted_users = {}
    ip_failed_times = {}

    with open(log_file, "r") as file:

        for line in file:

            event = parse_failed_login(line)

            if event is None:
                continue

            failed_attempts += 1

            timestamp = event["timestamp"]
            username = event["username"]
            ip_address = event["ip_address"]

            # Count failures by source IP
            if ip_address in failed_ips:
                failed_ips[ip_address] += 1
            else:
                failed_ips[ip_address] = 1

            # Count failures by username
            if username in targeted_users:
                targeted_users[username] += 1
            else:
                targeted_users[username] = 1

            # Track unique accounts targeted by each IP
            if ip_address not in ip_targeted_users:
                ip_targeted_users[ip_address] = set()

            ip_targeted_users[ip_address].add(
                username
            )

            # Track timestamps by source IP
            if ip_address not in ip_failed_times:
                ip_failed_times[ip_address] = []

            ip_failed_times[ip_address].append(
                timestamp
            )

    return {
        "failed_attempts": failed_attempts,
        "failed_ips": failed_ips,
        "targeted_users": targeted_users,
        "ip_targeted_users": ip_targeted_users,
        "ip_failed_times": ip_failed_times
    }


def main():
    """
    Main entry point for the Security Log Analyzer.
    """

    parser = create_argument_parser()

    args = parser.parse_args()

    # Set up application logging
    logger = setup_logger()

    logger.info(
        "Security Log Analyzer started"
    )

    # Load configuration
    config = load_config(args.config)

    # Analyze authentication log
    try:
        logger.info(
            "Analyzing log file: %s",
            args.log
        )

        analysis = analyze_log(args.log)

    except FileNotFoundError:

        logger.error(
            "Log file not found: %s",
            args.log
        )

        parser.error(
            f"Log file not found: {args.log}"
        )

    except PermissionError:

        logger.error(
            "Permission denied when reading log file: %s",
            args.log
        )

        parser.error(
            f"Permission denied when reading log file: "
            f"{args.log}"
        )

    failed_attempts = analysis["failed_attempts"]
    failed_ips = analysis["failed_ips"]
    targeted_users = analysis["targeted_users"]
    ip_targeted_users = analysis["ip_targeted_users"]
    ip_failed_times = analysis["ip_failed_times"]

    logger.info(
        "Found %d failed login events",
        failed_attempts
    )

    # Run detection engine
    repeated_login_alerts = detect_repeated_logins(
        failed_ips,
        threshold=config[
            "repeated_login_threshold"
        ]
    )

    account_targeting_alerts = detect_account_targeting(
        ip_targeted_users,
        threshold=config[
            "account_targeting_threshold"
        ]
    )

    login_burst_alerts = detect_login_bursts(
        ip_failed_times,
        threshold=config[
            "login_burst_threshold"
        ],
        window_seconds=config[
            "login_burst_window_seconds"
        ]
    )

    # Record alert counts in application log
    logger.info(
        "Generated %d repeated-login alerts",
        len(repeated_login_alerts)
    )

    logger.info(
        "Generated %d account-targeting alerts",
        len(account_targeting_alerts)
    )

    logger.info(
        "Generated %d login-burst alerts",
        len(login_burst_alerts)
    )

    # Display results in Terminal
    display_summary(
        failed_attempts,
        failed_ips,
        targeted_users,
        ip_targeted_users
    )

    display_alerts(
        repeated_login_alerts,
        account_targeting_alerts,
        login_burst_alerts
    )

    # Save JSON report
    save_json_report(
        failed_attempts,
        failed_ips,
        targeted_users,
        ip_targeted_users,
        repeated_login_alerts,
        account_targeting_alerts,
        login_burst_alerts,
        output_file=args.output
    )

    logger.info(
        "JSON security report generated: %s",
        args.output
    )

    logger.info(
        "Security Log Analyzer completed successfully"
    )


if __name__ == "__main__":
    main()