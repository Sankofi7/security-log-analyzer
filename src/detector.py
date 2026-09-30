def detect_repeated_logins(failed_ips, threshold=3):
    """
    Detect IP addresses that reach or exceed
    the failed-login threshold.
    """

    alerts = []

    for ip, count in failed_ips.items():

        if count >= threshold:

            alert = {
                "type": "REPEATED_LOGIN",
                "severity": "HIGH",
                "ip_address": ip,
                "failed_attempts": count,
                "threshold": threshold
            }

            alerts.append(alert)

    return alerts
def detect_account_targeting(ip_targeted_users, threshold=3):
    """
    Detect IP addresses targeting multiple unique accounts.
    """

    alerts = []

    for ip, users in ip_targeted_users.items():

        unique_accounts = len(users)

        if unique_accounts >= threshold:

            alert = {
                "type": "ACCOUNT_TARGETING",
                "severity": "HIGH",
                "ip_address": ip,
                "unique_accounts": unique_accounts,
                "accounts": sorted(users),
                "threshold": threshold
            }

            alerts.append(alert)

    return alerts
def detect_login_bursts(ip_failed_times, threshold=3, window_seconds=60):
    """
    Detect multiple failed logins from the same IP
    within a specified time window.
    """

    alerts = []

    for ip, timestamps in ip_failed_times.items():

        timestamps = sorted(timestamps)

        for i in range(len(timestamps)):

            window_start = timestamps[i]
            attempts_in_window = 0

            for timestamp in timestamps[i:]:

                time_difference = (
                    timestamp - window_start
                ).total_seconds()

                if time_difference <= window_seconds:
                    attempts_in_window += 1
                else:
                    break

            if attempts_in_window >= threshold:

                alert = {
                    "type": "LOGIN_BURST",
                    "severity": "HIGH",
                    "ip_address": ip,
                    "attempts": attempts_in_window,
                    "window_seconds": window_seconds,
                    "window_start": window_start
                }

                alerts.append(alert)

                break

    return alerts