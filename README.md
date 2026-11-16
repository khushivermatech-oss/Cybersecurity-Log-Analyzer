# Cybersecurity Log Analyzer

A beginner-friendly Python project that analyses sample Linux-style authentication logs, counts successful and failed login attempts, and flags IP addresses that cross a configurable failed-login threshold.

## Features
- Reads a local text authentication log.
- Counts successful and failed SSH login events.
- Groups failed attempts by source IP address.
- Flags IPs with 3 or more failed attempts (default threshold).
- Generates a readable text report in `reports/analysis_report.txt`.
- Includes sample data and a basic unit test.

## Requirements
- Python 3.9 or later
- No third-party Python packages required

## Run the project
From the project root:

```bash
python3 src/log_analyzer.py
```

The sample report is written to `reports/analysis_report.txt`.

## Run tests
```bash
python3 -m unittest discover -s tests -v
```

## How detection works
The program searches each log line for SSH authentication messages. It extracts usernames and IPv4 addresses using regular expressions. A `Counter` groups failed attempts by IP. Any IP with at least three failed attempts is flagged for review.

## Prompt Engineering contribution
The project was planned and implemented with AI assistance using structured prompts:
1. Define a beginner-level cybersecurity log-analysis use case.
2. Ask for a modular Python design with clear functions.
3. Request safe synthetic SSH authentication log examples.
4. Ask for test cases covering repeated failed attempts.
5. Ask for documentation and execution instructions.

AI-generated code was reviewed, run, and tested. The tool is a learning prototype and its alerts are not proof of malicious activity.

## Limitations
- Supports a simple Linux/SSH-style log format only.
- Uses a fixed default threshold of three attempts.
- Does not block IP addresses or take action on a system.
- Sample IP addresses are documentation/example addresses.

## Future improvements
- Add command-line options for custom log paths and thresholds.
- Export reports as CSV or JSON.
- Add charts for login activity.
- Support additional log formats.

## Author
Add your name, course, college, and date here.
