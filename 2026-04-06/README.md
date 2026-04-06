# Jenkins Script Console RCE Scanner

The `jenkins_script_console_rce_scanner.py` script is a security tool for identifying and testing Jenkins instances that may be vulnerable to Remote Code Execution (RCE) through the Script Console endpoint. Misconfigured Jenkins instances with unauthenticated or improperly secured Script Console access present a critical security risk.

### Features
- **Detection**: Identifies Jenkins instances based on common fingerprints.
- **Version-independent payload**: Tests for exposure of the `/script` endpoint without reliance on specific CVEs.
- **Active probing**: Uses predefined harmless Groovy scripts to test for code execution capabilities.
- **Safe Mode**: Detection-only option without active testing for RCE.
- **Concurrency control**: Configurable number of concurrent HTTP requests.
- **Output**: Colored console messages and optional JSON output for result reports.

### Prerequisites
- Python 3.10+
- Install dependencies: `pip install httpx`

### Usage

#### Scan a Single Jenkins Server
