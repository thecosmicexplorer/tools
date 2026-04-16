# Jupyter Notebook RCE Scanner

## Overview
The `jupyter_notebook_rce_scanner` is a security tool designed to identify misconfigured or exposed Jupyter Notebook instances that are vulnerable to remote code execution (RCE). It fingerprints Jupyter Notebook servers, assesses their security posture, and actively probes for RCE vulnerabilities when safe mode is disabled.

Jupyter Notebooks are commonly used in data science, machine learning, and other computational fields, with many instances publicly accessible. This tool helps locate and assess the risk of such instances.

## Supported Features
- Detects instances of Jupyter Notebook
- Extracts version information to identify outdated deployments
- Probes for RCE vulnerabilities (with a `--safe` mode to disable active probes)
- Supports single URL scanning, bulk scanning from a file, and outputting results in JSON format
- Allows custom concurrency and SSL verification settings
- Provides detailed scan results with vulnerability indicators

## Installation
1. Clone this repository:
   