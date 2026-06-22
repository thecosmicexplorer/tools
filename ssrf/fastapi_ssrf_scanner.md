# FastAPI SSRF Scanner (fastapi_ssrf_scanner.py)

FastAPI SSRF Scanner detects and optionally exploits Server-Side Request Forgery (SSRF) vulnerabilities in REST APIs and web services built with FastAPI.

## CVE Information
This tool focuses on detecting and exploiting SSRF vulnerabilities rather than a specific CVE. SSRF vulnerabilities occur when user-provided URLs are processed without proper validation, potentially allowing unauthorized access to internal or external resources.

## Capabilities
- Detects the presence of FastAPI applications via fingerprinting (e.g., `/docs`, OpenAPI specs).
- Actively probes potential SSRF issues (optional, can be disabled with `--safe`).
- Detects responses from internal/external services like AWS metadata endpoints or localhost services during SSRF probing.

## Usage Examples

### Scan a Single Target
