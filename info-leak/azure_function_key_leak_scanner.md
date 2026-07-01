# Azure Function Key Leak Scanner

## Summary

This tool scans Azure Function apps for key leaks caused by misconfigurations that allow anonymous access to sensitive key endpoints. The leaked keys can enable attackers to invoke functions or access restricted APIs within the Function App, potentially causing privilege escalation or misuse of resources.

## Features

- Detects misconfigured Azure Function apps.
- Extracts host-level and function-level keys when possible.
- Offers detection-only mode using the `--safe` flag.
- Supports bulk scanning with tunable concurrency.
- Outputs results in JSON format when provided an output file.

## Installation

1. Clone this repository:
   