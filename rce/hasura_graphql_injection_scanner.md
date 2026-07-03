# Hasura GraphQL Injection Scanner

This tool checks for GraphQL Injection vulnerabilities in Hasura GraphQL APIs and optionally attempts to exploit identified vulnerabilities. Hasura is a popular tool and is often used in production systems, making vulnerable endpoints a serious concern for security.

## Features
- Detects Hasura GraphQL APIs by identifying specific response headers and body content.
- Automatically extracts and reports the Hasura server version when detected.
- Tests query/mutation operations for common injection paths.
- Active probing is optional via the `--safe` flag for detection-only scans.
- JSON output to log scan results for analysis.

## Usage
Here are some usage examples:

1. **Scan a single target endpoint:**
   