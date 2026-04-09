# API Gateway SSRF Vulnerability Scanner

The `api_gateway_ssrf_scanner` is a Python-based tool for detecting and assessing 
Server-Side Request Forgery (SSRF) vulnerabilities in popular API gateways. It can perform 
both safe detection and active probes to verify potentially vulnerable endpoints.

## Vulnerability Details

Server-Side Request Forgery (SSRF) allows malicious users to send crafted requests from a target server, 
potentially exposing internal or sensitive resources. Misconfigurations in API gateways 
or insufficient validation of user-supplied URLs can result in vulnerability to SSRF attacks.

**Examples of Vulnerable API Gateway Technologies:**
- Kong Gateway
- AWS API Gateway
- NGINX Ingress Controller
- Traefik

## Features

- **Fingerprinting**: Detect common API gateway types and versions.
- **Version Check**: Identify outdated or potentially vulnerable software versions.
- **SSRF Probing**: Test for SSRF vulnerabilities using a set of known payloads.
- **Concurrency**: Parallel scanning of multiple targets.
- **Safe Mode**: Only detect API gateway presence without testing SSRF payloads.

## Prerequisites

- Python 3.10 or higher
- `pip install -r requirements.txt` (see below)

## Installation

Install the required dependencies using pip:
