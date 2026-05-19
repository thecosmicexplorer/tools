# Docker API Remote Code Execution Scanner

This tool scans for exposed Docker APIs accessible without authentication and probes for remote code execution vulnerabilities. The Docker daemon API, when improperly exposed, allows attackers to manipulate containers, execute arbitrary commands, and gain control over the host.

## Key Features
- **Fingerprinting:** Detects exposed Docker APIs by querying common endpoints.
- **Version Extraction:** Extracts Docker version information for further analysis.
- **Active Probes:** Checks for RCE capabilities by creating and executing commands in temporary containers (requires Docker API access).
- **Safe Mode:** Detection-only functionality without probing for RCE.
- **Concurrency:** Supports bulk scanning with adjustable concurrency.
- **Output:** Provides JSON-formatted scan results for reporting.

## Usage

### Scan a single target (active probing enabled)
