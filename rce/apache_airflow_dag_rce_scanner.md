# Apache Airflow DAG Configuration RCE Scanner

This tool scans for Remote Code Execution (RCE) vulnerabilities in misconfigured Apache Airflow DAGs. Vulnerabilities in improperly secured DAG inputs can allow attackers to inject arbitrary Python code, resulting in full server compromise.

## Vulnerability Details

Apache Airflow, a popular workflow orchestration platform, often exposes web interfaces or APIs that are improperly secured. When direct access to DAG definitions or API endpoints like `trigger_dag` is granted to unauthorized users, attackers may exploit this to execute arbitrary Python code.

### Affected Systems
- Apache Airflow DAG configurations on public-facing servers.
- Versions with exposed APIs and default authentication settings, without appropriate access control.

### Impacts
- Full Remote Code Execution (RCE) on target servers.
- Potential exposure of sensitive data, lateral movement across infrastructure, and access to underlying cloud environments.

### References
- [Apache Airflow Official Documentation](https://airflow.apache.org/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [Trellix Airflow RCE Research](https://www.trellix.com/en-us/about/newsroom/stories/research/critical-vulnerabilities-in-apache-airflow.html)

### Usage

