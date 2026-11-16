# Prompt Engineering Documentation

## Project
Cybersecurity Log Analyzer using Python

## Objective
Build a beginner-friendly defensive tool that reads sample authentication logs, identifies successful and failed login attempts, groups failures by IP address, and reports repeated failures.

## Prompts used during development
1. "Act as a Python instructor. Design a beginner-friendly cybersecurity log analyzer that reads synthetic Linux SSH authentication logs."
2. "Write modular Python code with separate functions for reading logs, parsing successful and failed logins, counting failed attempts by IP, and generating a text report."
3. "Create safe synthetic sample log entries that include both successful and failed SSH login events."
4. "Explain each Python concept used: functions, regular expressions, dictionaries, Counter, file handling, exceptions, and pathlib."
5. "Create a unit test to verify that an IP with three failed login attempts is flagged."

## How prompts were improved
The initial broad idea was refined by specifying:
- Role: Python instructor / cybersecurity mentor.
- Task: analyse authentication logs.
- Input: sample Linux SSH log file.
- Output: counts, suspicious IP summary, and report.
- Constraint: educational defensive use only; no blocking or attacking systems.

## Human verification
The code was executed using Python. The sample log and expected output were checked. The project should be tested again on the student's computer before submission.

## Learning outcomes
- Basic log analysis
- Python file handling and regular expressions
- Dictionaries and Counter
- Simple threshold-based alerting
- Software testing and GitHub version control
