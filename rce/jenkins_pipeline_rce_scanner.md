# Jenkins Scripted Pipeline RCE Scanner

This is a security scanner designed to identify and exploit remote code execution (RCE) vulnerabilities in misconfigured Jenkins scripted pipelines.

## CVE Information

This scanner targets multiple vulnerabilities often affecting Jenkins instances with improperly configured scripted pipelines. Jenkins installations with disabled script-security or permissive security configurations are especially susceptible to RCE attacks through unvalidated Groovy scripts.

## Features

- Fingerprints Jenkins instances to confirm their presence.
- Extracts Jenkins version and identifies if it matches any known outdated versions.
- Probes for remote code execution (RCE) vulnerabilities on susceptible pipelines.
- Offers a "safe" mode for detection only.

## Requirements

- Python 3.10+
- Install dependencies: `pip install httpx`

## Usage

