# Django Debug Mode SSRF Scanner

## Overview

This tool scans for Django-based web applications running with DEBUG mode enabled,
which can expose sensitive information such as internal IP addresses, tracebacks, and URL paths.
Additionally, it probes for potential server-side request forgery (SSRF) vulnerabilities using benign payloads.

## Key Features

- Detects applications running with DEBUG mode enabled.
- Probes for potential SSRF vulnerabilities in unsafe mode.
- Provides a `--safe` mode for detection-only scans.

## Supported Targets

This scanner supports web applications built with the Django framework.

## Installation

