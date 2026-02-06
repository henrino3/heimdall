# Heimdall 🔐

The Watchman of Asgard — Security Scanner for AI Agent Skills.

Scans AI agent skill packages for vulnerabilities, malware, prompt injection, and data exfiltration patterns before they touch your agent.

## Why

- 26% of 31,000+ community skills contain at least one vulnerability (Cisco AI Defense)
- 230+ malicious skills identified on community marketplaces
- One-click RCE bugs have been found in agent frameworks
- Your agent has access to your entire digital life. Every skill you install is a potential attack vector.

## What It Scans For

- 🔴 **Remote code execution** — curl/wget to external URLs, eval(), exec()
- 🔴 **Credential theft** — Access to .env, secrets/, API keys
- 🔴 **Data exfiltration** — Outbound HTTP with sensitive data patterns
- 🟡 **Obfuscated code** — Base64 encoded commands, encoded payloads
- 🟡 **Prompt injection** — Hidden instructions in skill descriptions
- 🟡 **Excessive permissions** — Skills requesting more access than needed

## Usage

```bash
# Scan a skill directory
python3 skill-scan.py /path/to/skill/

# Scan before installing from marketplace
python3 skill-scan.py --url https://clawdhub.com/skills/some-skill
```

## Output

```
🔍 Scanning: my-skill/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  CRITICAL: External URL in install script (line 12)
⚠️  HIGH: Reads from ~/.env (line 34)
✅ SAFE: No obfuscated code detected
✅ SAFE: No prompt injection patterns

Risk Score: 7/10 — REVIEW BEFORE INSTALLING
```

## Built By

Henry Mascot — after watching the OpenClaw security storm unfold in real-time and deciding to build the tool the community needed.

## License

MIT
