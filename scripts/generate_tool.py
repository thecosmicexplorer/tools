#!/usr/bin/env python3
"""
Daily Security Tool Generator
==============================
Called by GitHub Actions daily. Uses Claude API to generate a new CVE scanner,
writes it to a dated folder, updates root README.md, and commits + pushes.

Requires env var: ANTHROPIC_API_KEY
"""

import os
import re
import sys
import subprocess
from datetime import date
from pathlib import Path

import anthropic


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)


def get_existing_tools() -> str:
    """Return a list of all tracked files to help Claude avoid duplicates."""
    result = run(["git", "ls-files"])
    return result.stdout.strip()


def get_style_reference() -> str:
    """Return the n8n scanner as a style reference (first 4000 chars)."""
    ref = Path("n8n_rce_scanner/n8n_rce_scanner.py")
    if ref.exists():
        return ref.read_text()[:4000]
    # fallback — look for any scanner
    for p in Path(".").rglob("*.py"):
        text = p.read_text()
        if "httpx" in text and "asyncio" in text:
            return text[:4000]
    return ""


# ── Claude API call ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a professional security researcher building a public library of CVE scanners
for authorized bug bounty and red team use. You write production-quality, well-documented
async Python tools. Your code is thorough, safe, and matches the style shown."""

USER_PROMPT_TEMPLATE = """\
Today's date: {today}

## Existing tools in the repo (do NOT duplicate these):
{existing_tools}

## Style reference — match this structure and quality exactly:
```python
{style_ref}
```

---

Create a NEW security scanner for a **high-impact, currently relevant CVE or vulnerability
class** that is useful for bug bounty / red team. Requirements:

**Target categories** (pick one):
- Popular dev/ops tools (CI/CD, workflow engines, container orchestration, cloud CLIs)
- Web frameworks and runtime environments
- Authentication/SSO systems
- APIs and management panels

**Vulnerability classes** (pick one):
- Remote code execution (RCE)
- Authentication bypass
- Server-side request forgery (SSRF)
- Path/directory traversal
- Insecure deserialization
- SQL injection or command injection

**Technical requirements:**
- Async Python 3.10+ using `httpx` and `asyncio`
- Fingerprinting logic to detect the target software
- Version extraction and comparison against patched version
- Active probing (with `--safe` flag to skip probes and do detection-only)
- CLI flags: `--target`, `--list`, `--output`, `--safe`, `--concurrency`, `--no-verify`
- ANSI color terminal output: CRITICAL=red, HIGH=yellow, INFO=green, RESET
- JSON output with `--output file.json`
- Detailed module docstring with CVE info, usage examples, and references
- 350–550 lines total

**Format your response EXACTLY like this — nothing before TOOL_NAME, nothing after the README block:**

TOOL_NAME: <snake_case_name_no_extension>
CVE: <CVE-YYYY-NNNNN or MULTI or N/A>
DESCRIPTION: <concise one-line description for the README log>
PYTHON_CODE:
```python
<complete scanner code>
```
README_CONTENT:
```markdown
<complete README.md for this tool>
```
"""


def call_claude(today: str, existing_tools: str, style_ref: str) -> dict:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    prompt = USER_PROMPT_TEMPLATE.format(
        today=today,
        existing_tools=existing_tools,
        style_ref=style_ref,
    )

    print("[*] Calling Claude API...")
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=8192,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    response = message.content[0].text

    # ── Parse ──────────────────────────────────────────────────────────────────
    tool_name_m  = re.search(r"TOOL_NAME:\s*(.+)", response)
    description_m = re.search(r"DESCRIPTION:\s*(.+)", response)
    python_m     = re.search(r"PYTHON_CODE:\s*```python\n(.*?)```", response, re.DOTALL)
    readme_m     = re.search(r"README_CONTENT:\s*```markdown\n(.*?)```", response, re.DOTALL)

    missing = []
    if not tool_name_m:  missing.append("TOOL_NAME")
    if not python_m:     missing.append("PYTHON_CODE")
    if not readme_m:     missing.append("README_CONTENT")

    if missing:
        print(f"[!] Claude response missing: {', '.join(missing)}")
        print("--- Response preview ---")
        print(response[:1000])
        sys.exit(1)

    return {
        "tool_name":   tool_name_m.group(1).strip().replace(" ", "_").lower(),
        "description": description_m.group(1).strip() if description_m else "Security scanner",
        "python_code": python_m.group(1),
        "readme":      readme_m.group(1),
    }


# ── File writing & git ────────────────────────────────────────────────────────

def update_root_readme(today: str, tool_name: str, description: str):
    readme = Path("README.md")
    content = readme.read_text()
    new_entry = f"- **{today}**: [{description}]({today}/{tool_name}.py)"

    if new_entry in content:
        print("[*] README.md already has this entry, skipping.")
        return

    content = content.rstrip() + f"\n{new_entry}\n"
    readme.write_text(content)
    print("[*] Updated README.md")


def git_commit_and_push(today: str, tool_name: str):
    run(["git", "config", "user.name", "github-actions[bot]"])
    run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])
    run(["git", "add", today, "README.md"])
    run(["git", "commit", "-m", f"feat: add {tool_name} ({today})"])
    run(["git", "push"])
    print(f"[+] Pushed {tool_name} to origin")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    today = date.today().isoformat()

    # Skip if today's tool already exists
    today_dir = Path(today)
    if today_dir.exists() and list(today_dir.glob("*.py")):
        print(f"[*] Tool for {today} already exists — nothing to do.")
        sys.exit(0)

    existing_tools = get_existing_tools()
    style_ref = get_style_reference()

    result = call_claude(today, existing_tools, style_ref)
    tool_name = result["tool_name"]

    print(f"[*] Generated tool: {tool_name}")

    # Write files
    today_dir.mkdir(exist_ok=True)

    py_path = today_dir / f"{tool_name}.py"
    py_path.write_text(result["python_code"])
    print(f"[*] Written: {py_path}")

    readme_path = today_dir / "README.md"
    readme_path.write_text(result["readme"])
    print(f"[*] Written: {readme_path}")

    update_root_readme(today, tool_name, result["description"])
    git_commit_and_push(today, tool_name)

    print(f"\n[+] Done! Tool published: {today}/{tool_name}.py")


if __name__ == "__main__":
    main()
