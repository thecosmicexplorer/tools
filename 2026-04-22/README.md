# Git Large Object (LFS) Exposure Scanner

The `git_large_object_exposure_scanner` is a tool designed to identify Git repositories 
that have misconfigured Large File Storage (LFS) endpoints, which can result in 
unauthorized access to sensitive files stored as large objects.

## CVE and Vulnerability Details

Git LFS misconfigurations can lead to exposure of sensitive files such as:
- Environment variables (`.env` files)
- Private keys
- Build artifacts
- Other sensitive configuration or binary files

This tool scans Git repositories for evidence of LFS usage, checks for exposed LFS metadata, 
and optionally validates access controls to detect possible leaks.

### Key Features

- Detects whether a Git repository uses Git LFS
- Extracts .gitattributes and attempts to list LFS-tracked files
- Checks exposed files against common sensitive file patterns
- Safe mode for detection-only scans (no active probing)

## Installation

This tool requires Python 3.10+ and the `httpx` library. You can install it using pip:

