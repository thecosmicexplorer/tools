# Jenkins Script Console RCE Scanner

## Overview

The `jenkins_script_console_rce_scanner` is a security tool designed to detect and validate remote code execution (RCE) vulnerabilities in Jenkins instances with exposed or improperly secured Script Consoles.

Jenkins' Script Console allows administrators to execute arbitrary Groovy code within the Jenkins runtime. If left exposed or misconfigured, attackers may exploit this to execute arbitrary commands on the server.

### Vulnerability Context
- Jenkins Script Console can pose a grave security risk if accessible to unauthenticated attackers.
- Improperly secured instances allow potential attackers to run OS-level commands leading to complete system compromise.

## Usage

### Scanning a single instance
