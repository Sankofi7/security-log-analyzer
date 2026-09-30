# Security Log Analyzer

A Python-based defensive cybersecurity tool that analyzes SSH authentication logs, identifies suspicious failed-login activity, generates security alerts, and produces structured JSON reports.

The project was built as a hands-on cybersecurity portfolio project to practice log analysis, security monitoring, detection engineering, Python programming, and automated testing.

---

## Features

The Security Log Analyzer can:

- Parse SSH failed-login events
- Extract usernames, IP addresses, and timestamps
- Handle invalid-user SSH login attempts
- Count failed authentication attempts by IP address
- Track targeted user accounts
- Correlate source IP addresses with targeted accounts
- Detect repeated failed-login attempts
- Detect attempts targeting multiple user accounts
- Detect bursts of failed logins within a time window
- Load detection thresholds from a JSON configuration file
- Generate structured JSON security reports
- Maintain application operational logs
- Automatically rotate application logs
- Handle missing log files through the CLI
- Run automated unit and CLI tests

---

## Detection Rules

The analyzer currently implements three detection rules.

### 1. Repeated Login Detection

Detects a source IP address when its number of failed login attempts reaches or exceeds a configured threshold.

Example:

```text
192.168.1.25 -> 3 failed attempts