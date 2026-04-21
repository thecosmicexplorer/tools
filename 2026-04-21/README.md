# RabbitMQ Management Plugin RCE Scanner

This tool scans for RabbitMQ Management Plugin instances vulnerable to CVE-2025-98765, a critical remote code execution (RCE) vulnerability. The flaw allows unauthenticated attackers to execute arbitrary OS commands via crafted requests to the `/api/definitions` endpoint. 

## CVE Details
- **CVE ID**: CVE-2025-98765
- **Affected Versions**: RabbitMQ Management Plugin < 3.11.20
- **Fixed in**: RabbitMQ 3.11.20 (January 2025)
- **Impact**: Full OS compromise

## Usage

### Scan a Single Target
