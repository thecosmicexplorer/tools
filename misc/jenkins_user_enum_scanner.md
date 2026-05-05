# Jenkins User Enumeration Scanner

## Overview
The `jenkins_user_enum_scanner.py` tool detects username enumeration vulnerabilities in Jenkins servers by probing well-known endpoints and analyzing server responses.

### Vulnerability Details
Jenkins is a popular automation server often used in software development pipelines. However, misconfigured instances may disclose sensitive information about valid usernames via its various endpoints. By identifying valid usernames, attackers can perform targeted brute force attacks or craft advanced exploitation techniques.

This tool leverages multiple enumeration vectors, including login pages, error messages, autocomplete responses, and user profiles, to identify accessible usernames.

## Installation
Ensure that Python 3.10 or later is installed on your system. Install the required dependency `httpx`:
