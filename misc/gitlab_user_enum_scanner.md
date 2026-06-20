# GitLab User Enumeration Scanner

## Overview
This tool scans GitLab instances for a user enumeration vulnerability through its GraphQL API.
It can detect the presence of GitLab instances, identify versions, and test for the existence
of specific usernames to reveal potential security flaws.

## Features
- Detects GitLab installations and attempts version extraction
- Enumerates users via the GitLab GraphQL API
- Supports safe mode for detection-only scans
- Outputs results in both console and JSON formats

## Usage
### Example Commands
Scan a single target:
