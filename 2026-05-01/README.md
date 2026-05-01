# Jenkins Configuration Exposure Scanner

This tool scans for instances of Jenkins exposed to the internet and checks whether sensitive files (such as `/config.xml`, `/credentials`, `/secrets/`) are retrievable. It provides a detection mode and optional active probing capabilities for more detailed assessments.

## Vulnerability Details

Jenkins instances improperly configured to expose sensitive directories or files can reveal critical information:
- Configuration details (`config.xml`) that might include node settings and deployment secrets.
- Keys used for securing Jenkins (`master.key`, `hudson.util.Secret`).
- Credentials that may be stored for connecting to build nodes and repositories.

These exposures can lead to privilege escalation, remote code execution, or information theft, making them high-priority issues for security assessments.

## Features

- Detects Jenkins instances via fingerprinting specific UI and API responses.
- Optionally probes exposed paths for sensitive file retrieval (e.g., `/config.xml`, `/secrets/`).
- Outputs findings to the console and optionally to a JSON file.
- CLI options for single targets, target lists, concurrency, and safe mode.

## Usage

### Single Target
Scan a single Jenkins URL:
