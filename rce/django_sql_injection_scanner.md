# Django SQL Injection Scanner

## Overview
The Django SQL Injection Scanner is an asynchronous Python tool designed to detect and validate SQL injection vulnerabilities 
in web applications built using the Django framework. These vulnerabilities typically arise from improper query sanitization, 
and their exploitation may lead to unauthorized data access or worse, remote code execution.

The scanner utilizes fingerprinting techniques to detect Django-powered applications and actively probes common endpoints for 
SQL injection vulnerabilities. With a focus on safe and controlled testing, the scanner provides both detection and active 
probing capabilities.

## Features
- **Detection**: Identifies Django applications and extracts version information if available.
- **Active Probing**: Actively probes endpoints with SQL injection payloads.
- **Safe Mode**: Provides detection-only mode for situations where probing is not authorized.
- **Concurrent Scanning**: Supports configurable concurrency for efficient scanning.
- **JSON Output**: Generates structured JSON reports for further analysis.
- **ANSI Terminal Colors**: Highlights results as INFO (yellow), SAFE (green), and CRITICAL (red).

## Usage

### Scan a Single Target
