"""
Cybersecurity Log Analyzer
A beginner-friendly tool that analyses sample Linux-style authentication logs.
It detects repeated failed login attempts from the same IP address.
"""

import re
from collections import Counter
from datetime import datetime
from pathlib import Path

FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_PATTERN = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")
DEFAULT_THRESHOLD = 3


def analyze_log(log_path, threshold=DEFAULT_THRESHOLD):
    """Read a log file and return counts plus suspicious IP addresses."""
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    failed_events = []
    successful_events = []
    total_lines = 0

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            total_lines += 1
            failed_match = FAILED_PATTERN.search(line)
            success_match = SUCCESS_PATTERN.search(line)

            if failed_match:
                username, ip = failed_match.groups()
                failed_events.append({
                    "username": username,
                    "ip": ip,
                    "line": line_number
                })
            elif success_match:
                username, ip = success_match.groups()
                successful_events.append({
                    "username": username,
                    "ip": ip,
                    "line": line_number
                })

    failed_by_ip = Counter(event["ip"] for event in failed_events)
    suspicious_ips = {
        ip: count for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    return {
        "total_lines": total_lines,
        "failed_attempts": failed_events,
        "successful_attempts": successful_events,
        "failed_by_ip": failed_by_ip,
        "suspicious_ips": suspicious_ips,
        "threshold": threshold,
    }


def create_report(results, output_path):
    """Write a readable text report to disk."""
    report_path = Path(output_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "=" * 58,
        "CYBERSECURITY LOG ANALYSIS REPORT",
        "=" * 58,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total log lines: {results['total_lines']}",
        f"Successful login attempts: {len(results['successful_attempts'])}",
        f"Failed login attempts: {len(results['failed_attempts'])}",
        f"Alert threshold: {results['threshold']} failed attempts per IP",
        "",
        "FAILED ATTEMPTS BY IP",
        "-" * 58,
    ]

    if results["failed_by_ip"]:
        for ip, count in results["failed_by_ip"].most_common():
            lines.append(f"{ip:<20} {count} failed attempt(s)")
    else:
        lines.append("No failed login attempts found.")

    lines.extend(["", "SUSPICIOUS IP ALERTS", "-" * 58])
    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            lines.append(
                f"[ALERT] {ip} generated {count} failed login attempts."
            )
    else:
        lines.append("No IP address crossed the alert threshold.")

    lines.extend(["", "SUCCESSFUL LOGINS", "-" * 58])
    if results["successful_attempts"]:
        for event in results["successful_attempts"]:
            lines.append(
                f"User: {event['username']}, IP: {event['ip']}, "
                f"line: {event['line']}"
            )
    else:
        lines.append("No successful login attempts found.")

    lines.extend([
        "",
        "NOTE: This is a basic educational analyser using sample logs.",
        "An alert is an indicator for review, not proof of an attack.",
        "=" * 58,
    ])

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main():
    project_root = Path(__file__).resolve().parent.parent
    sample_log = project_root / "sample_logs" / "auth.log"
    report_file = project_root / "reports" / "analysis_report.txt"

    try:
        results = analyze_log(sample_log)
        create_report(results, report_file)

        print("\nCYBERSECURITY LOG ANALYZER")
        print("-" * 35)
        print(f"Total log lines       : {results['total_lines']}")
        print(f"Successful logins    : {len(results['successful_attempts'])}")
        print(f"Failed logins        : {len(results['failed_attempts'])}")
        print(f"Suspicious IPs       : {len(results['suspicious_ips'])}")
        print(f"\nReport saved to: {report_file}")
        if results["suspicious_ips"]:
            print("\nALERTS:")
            for ip, count in sorted(results["suspicious_ips"].items()):
                print(f"  {ip} -> {count} failed attempts")
        else:
            print("\nNo suspicious IPs detected.")
    except (FileNotFoundError, OSError) as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
