# Django Insecure Deserialization Scanner  

Detects and actively probes for insecure deserialization vulnerabilities in Django applications.  

## Overview  

This tool identifies insecure deserialization vulnerabilities in Django applications, particularly in scenarios where Python's `pickle` module is used for sessions, cache backends, or serialization. It supports both detection-only mode and active probing (crafting test payloads to confirm severity).  

## Features  
- Session and cache backend detection leveraging insecure `pickle` serialization.  
- Header and fingerprint analysis to confirm Django application instances.  
- Active probe mode to inject test payloads under controlled environments.  
- Concurrency support for bulk scans.  
- CLI configuration options for flexibility and JSON-based output reports.  

## Usage Examples  

### Scan for vulnerabilities in a single target:  
