#!/usr/bin/env python3
"""
Skill Scanner v5.0 - Context-Aware Security Scanner for OpenClaw Skills
with Multi-Provider AI Support and CI/CD Integration

NEW in v5.0:
- Multi-provider model support (OpenRouter, Anthropic, OpenAI, Z.ai)
- Auto-detection from environment variables
- CLI flags: --model and --provider
- SARIF output for GitHub Security integration
- Risk scoring system (0-100)
- Config file support for custom rules
- Enhanced CI/CD integration with proper exit codes
- Dependency vulnerability scanning patterns
- Interactive review mode
- Performance optimizations (parallel processing, caching)

v4.0 Features:
- --analyze flag: AI-powered narrative security analysis
- Explains WHY each finding is dangerous
- Provides attack scenarios and impact assessment
- Gives actionable recommendations

v3.0 Features:
- Remote fetch detection (skill.md/heartbeat.md from internet)
- Heartbeat injection patterns
- MCP tool abuse (no_human_approval, auto_approve)
- Unicode tag injection (hidden U+E0001-U+E007F)
- Auto-approve exploits (curl | bash)
- Crypto wallet extraction patterns
- Agent impersonation patterns
- Data pre-fill exfiltration (Google Forms)

Usage:
    skill-scan <path-to-skill>
    skill-scan --analyze <path>              # AI-powered narrative analysis
    skill-scan --model gpt-4 --provider openai <path>  # Use specific provider
    skill-scan --json <path>                 # JSON output
    skill-scan --sarif <path>                # SARIF output for GitHub
    skill-scan --interactive <path>          # Interactive review mode
    skill-scan --config custom-rules.yaml <path>  # Custom rules
    skill-scan --ci <path>                   # CI mode (exit codes)
    skill-scan -v <path>                     # Verbose
    skill-scan --strict <path>               # Ignore context, flag everything
"""

import os
import re
import sys
import json
import subprocess
import hashlib
import time
import concurrent.futures
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional, Set, Any
from enum import IntEnum
from functools import lru_cache


class Severity(IntEnum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Context(IntEnum):
    CODE = 3        # Actual executable code - full severity
    CONFIG = 2      # Config files - reduced severity
    DOCS = 1        # Documentation - heavily reduced
    STRING = 0      # Inside a string literal - likely a pattern/blocklist


# =============================================================================
# MULTI-PROVIDER MODEL CONFIGURATION
# =============================================================================

class ModelProvider:
    """Configuration for AI model providers."""
    
    PROVIDERS = {
        'openrouter': {
            'env_key': 'OPENROUTER_API_KEY',
            'api_url': 'https://openrouter.ai/api/v1/chat/completions',
            'default_model': 'anthropic/claude-3.5-sonnet',
            'models': [
                'anthropic/claude-3.5-sonnet',
                'anthropic/claude-3.5-haiku',
                'openai/gpt-4o',
                'openai/gpt-4o-mini',
                'google/gemini-flash-1.5',
                'meta-llama/llama-3.2-70b-instruct',
            ]
        },
        'anthropic': {
            'env_key': 'ANTHROPIC_API_KEY',
            'api_url': 'https://api.anthropic.com/v1/messages',
            'default_model': 'claude-3-5-sonnet-20241022',
            'models': [
                'claude-3-5-sonnet-20241022',
                'claude-3-5-haiku-20241022',
                'claude-3-opus-20240229',
            ]
        },
        'openai': {
            'env_key': 'OPENAI_API_KEY',
            'api_url': 'https://api.openai.com/v1/chat/completions',
            'default_model': 'gpt-4o',
            'models': [
                'gpt-4o',
                'gpt-4o-mini',
                'gpt-4-turbo',
            ]
        },
        'zai': {
            'env_key': 'ZAI_API_KEY',
            'api_url': 'https://api.z.ai/v1/chat/completions',
            'default_model': 'glm-5',
            'models': [
                'glm-5',
                'glm-4.7',
            ]
        }
    }
    
    @classmethod
    def detect_available(cls) -> List[str]:
        """Auto-detect available providers from environment."""
        available = []
        for provider, config in cls.PROVIDERS.items():
            env_key = config['env_key']
            if os.environ.get(env_key):
                available.append(provider)
            # Also check file-based keys
            key_path = os.path.expanduser(f'~/clawd/secrets/{provider}.key')
            if os.path.exists(key_path):
                available.append(provider)
        # Fallback order priority
        priority = ['anthropic', 'openai', 'openrouter', 'zai']
        return sorted(list(set(available)), 
                     key=lambda x: priority.index(x) if x in priority else 999)
    
    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for provider."""
        config = cls.PROVIDERS.get(provider)
        if not config:
            return None
        
        # Check environment first
        env_key = config['env_key']
        key = os.environ.get(env_key)
        if key:
            return key
        
        # Check file-based keys
        key_paths = [
            os.path.expanduser(f'~/clawd/secrets/{provider}.key'),
            os.path.expanduser(f'~/.config/{provider}/key'),
        ]
        for kp in key_paths:
            if os.path.exists(kp):
                with open(kp) as f:
                    return f.read().strip()
        
        return None
    
    @classmethod
    def get_default_model(cls, provider: str) -> str:
        """Get default model for provider."""
        config = cls.PROVIDERS.get(provider, {})
        return config.get('default_model', 'gpt-4o')


@dataclass
class Finding:
    severity: Severity
    original_severity: Severity
    category: str
    pattern: str
    file: str
    line: int
    match: str
    description: str
    context: Context
    suppressed: bool = False
    suppression_reason: str = ""
    risk_score: int = 0  # 0-100 risk score


@dataclass
class ScanResult:
    path: str
    files_scanned: int
    findings: List[Finding] = field(default_factory=list)
    suppressed_count: int = 0
    scan_duration: float = 0.0
    cache_hits: int = 0
    
    @property
    def active_findings(self) -> List[Finding]:
        return [f for f in self.findings if not f.suppressed]
    
    @property
    def max_severity(self) -> Severity:
        active = self.active_findings
        if not active:
            return Severity.SAFE
        return max(f.severity for f in active)
    
    @property
    def risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        active = self.active_findings
        if not active:
            return 0
        
        score = 0
        for f in active:
            if f.severity == Severity.CRITICAL:
                score += 25
            elif f.severity == Severity.HIGH:
                score += 15
            elif f.severity == Severity.MEDIUM:
                score += 5
            elif f.severity == Severity.LOW:
                score += 1
        
        # Cap at 100
        return min(100, score)
    
    @property
    def risk_level(self) -> str:
        """Get risk level based on score."""
        score = self.risk_score
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        return "SAFE"
    
    @property
    def action(self) -> str:
        sev = self.max_severity
        if sev == Severity.SAFE:
            return "✅ SAFE - OK to install"
        elif sev == Severity.LOW:
            return "📝 LOW - Review recommended"
        elif sev == Severity.MEDIUM:
            return "⚠️ MEDIUM - Manual review required"
        elif sev == Severity.HIGH:
            return "🔴 HIGH - Do NOT install without audit"
        else:
            return "🚨 CRITICAL - BLOCKED - Likely malicious"
    
    @property
    def exit_code(self) -> int:
        """Return appropriate exit code for CI/CD."""
        sev = self.max_severity
        if sev == Severity.CRITICAL:
            return 2  # Critical issues - fail pipeline
        elif sev == Severity.HIGH:
            return 1  # High issues - fail pipeline
        elif sev == Severity.MEDIUM:
            return 0  # Warning but pass
        else:
            return 0  # Pass


# =============================================================================
# CONTEXT DETECTION
# =============================================================================

FILE_CONTEXTS = {
    '.md': Context.DOCS, '.txt': Context.DOCS, '.rst': Context.DOCS, '.adoc': Context.DOCS,
    '.yaml': Context.CONFIG, '.yml': Context.CONFIG, '.json': Context.CONFIG, 
    '.toml': Context.CONFIG, '.ini': Context.CONFIG,
    '.py': Context.CODE, '.js': Context.CODE, '.ts': Context.CODE, '.sh': Context.CODE, 
    '.bash': Context.CODE, '.mjs': Context.CODE, '.cjs': Context.CODE,
}

BLOCKLIST_INDICATORS = [
    r'patterns?\s*[=:]', r'blocklist\s*[=:]', r'blacklist\s*[=:]',
    r'detect(ion)?_patterns?', r'malicious_patterns?', r'attack_patterns?',
    r'PATTERNS\s*[=:\[]', r'regex(es)?\s*[=:]', r'r["\'].*["\'],?\s*#',
    r'description["\']?\s*:',
]

SECURITY_TOOL_INDICATORS = [
    'prompt-guard', 'prompt_guard', 'security-scan', 'detect.py',
    'patterns.py', 'blocklist', 'firewall', 'waf', 'filter',
]


def get_file_context(filepath: Path) -> Context:
    suffix = filepath.suffix.lower()
    name = filepath.name.lower()
    for indicator in SECURITY_TOOL_INDICATORS:
        if indicator in str(filepath).lower():
            return Context.DOCS
    if any(doc in name for doc in ['readme', 'changelog', 'license', 'contributing', 'history']):
        return Context.DOCS
    return FILE_CONTEXTS.get(suffix, Context.CODE)


def is_in_string_literal(line: str, match_start: int) -> bool:
    before = line[:match_start]
    single_quotes = len(re.findall(r"(?<!\\)'", before))
    double_quotes = len(re.findall(r'(?<!\\)"', before))
    raw_double = len(re.findall(r'r"', before))
    raw_single = len(re.findall(r"r'", before))
    return (single_quotes - raw_single) % 2 == 1 or (double_quotes - raw_double) % 2 == 1


def is_blocklist_definition(line: str, prev_lines: List[str]) -> bool:
    context_lines = prev_lines[-5:] + [line]
    context = '\n'.join(context_lines)
    return any(re.search(ind, context, re.IGNORECASE) for ind in BLOCKLIST_INDICATORS)


def adjust_severity_for_context(severity: Severity, context: Context, 
                                 is_string: bool, is_blocklist: bool,
                                 filepath: str = "") -> Tuple[Severity, str]:
    is_security_tool = any(ind in filepath.lower() for ind in SECURITY_TOOL_INDICATORS)
    
    if is_blocklist:
        return Severity.SAFE, "Pattern in blocklist definition"
    if is_security_tool:
        if context in (Context.DOCS, Context.STRING) or is_string:
            return Severity.SAFE, "Security tool - pattern example"
        new_val = max(0, severity.value - 2)
        return Severity(max(1, new_val)), "Security tool - detection pattern"
    if is_string:
        new_val = max(0, severity.value - 3)
        return Severity(new_val), "Pattern in string literal"
    if context == Context.DOCS:
        new_val = max(0, severity.value - 3)
        return Severity(new_val), "Pattern in documentation"
    if context == Context.CONFIG:
        new_val = max(0, severity.value - 1)
        return Severity(max(1, new_val)), "Pattern in config file"
    return severity, ""


def calculate_risk_score(severity: Severity, context: Context, category: str) -> int:
    """Calculate individual finding risk score (0-100)."""
    base_scores = {
        Severity.CRITICAL: 90,
        Severity.HIGH: 70,
        Severity.MEDIUM: 40,
        Severity.LOW: 10,
        Severity.SAFE: 0
    }
    
    score = base_scores.get(severity, 0)
    
    # Adjust for context
    if context == Context.STRING:
        score = int(score * 0.3)
    elif context == Context.DOCS:
        score = int(score * 0.2)
    elif context == Context.CONFIG:
        score = int(score * 0.8)
    
    # Category multipliers for critical categories
    critical_cats = ['credential_access', 'network_exfil', 'data_exfil', 'crypto_wallet', 
                     'remote_fetch', 'heartbeat_injection', 'mcp_abuse']
    if category in critical_cats and score > 0:
        score = min(100, int(score * 1.2))
    
    return score


# =============================================================================
# PATTERN DEFINITIONS (Enhanced)
# =============================================================================

PATTERNS: List[Tuple[str, Severity, str, str]] = [
    # Credential Access
    (r"cat\s+.*\.env\b", Severity.CRITICAL, "credential_access", "Reading .env file"),
    (r"source\s+.*\.env\b", Severity.HIGH, "credential_access", "Sourcing .env file"),
    (r"open\([^)]*\.env[^)]*\)", Severity.HIGH, "credential_access", "Opening .env file"),
    (r"secrets?/[a-zA-Z]", Severity.HIGH, "credential_access", "Accessing secrets directory"),
    (r"password\s*=\s*['\"][^'\"]+['\"]", Severity.CRITICAL, "credential_access", "Hardcoded password"),
    (r"api[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]", Severity.CRITICAL, "credential_access", "Hardcoded API key"),
    (r"token\s*=\s*['\"][^'\"]{20,}['\"]", Severity.CRITICAL, "credential_access", "Hardcoded token"),
    (r"BEGIN\s+(RSA|PRIVATE|OPENSSH)\s+PRIVATE\s+KEY", Severity.CRITICAL, "credential_access", "Embedded private key"),
    (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "credential_access", "AWS Access Key ID"),
    (r"gh[pousr]_[A-Za-z0-9_]{36}", Severity.CRITICAL, "credential_access", "GitHub token"),
    (r"ghp_[A-Za-z0-9_]{36}", Severity.CRITICAL, "credential_access", "GitHub Personal Access Token"),
    (r"sk-[a-zA-Z0-9]{48}", Severity.CRITICAL, "credential_access", "OpenAI API Key"),
    (r"sk_live_[a-zA-Z0-9]{24,}", Severity.CRITICAL, "credential_access", "Stripe Live Key"),
    (r"sk_test_[a-zA-Z0-9]{24,}", Severity.HIGH, "credential_access", "Stripe Test Key"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", Severity.CRITICAL, "credential_access", "Slack Token"),
    (r"\b[0-9a-f]{32}\b", Severity.HIGH, "credential_access", "Possible MD5 hash/API key"),
    (r"private[_-]?key\s*[=:]\s*['\"][^'\"]{20,}", Severity.CRITICAL, "credential_access", "Private key value"),
    (r"client[_-]?secret\s*[=:]\s*['\"][^'\"]{10,}", Severity.CRITICAL, "credential_access", "OAuth client secret"),
    (r"database[_-]?url\s*[=:]\s*['\"][^'\"]+['\"]", Severity.HIGH, "credential_access", "Database connection string"),
    
    # Network Exfiltration
    (r"curl\s+-[^s]*\s+(http|https)://(?!localhost|127\.0\.0\.1)", Severity.HIGH, "network_exfil", "Curl to external URL"),
    (r"wget\s+(http|https)://(?!localhost|127\.0\.0\.1)", Severity.HIGH, "network_exfil", "Wget to external URL"),
    (r"requests\.(get|post|put|delete)\s*\(['\"]https?://(?!localhost)", Severity.MEDIUM, "network_exfil", "HTTP request to external"),
    (r"fetch\s*\(\s*['\"]https?://(?!localhost)", Severity.MEDIUM, "network_exfil", "Fetch to external URL"),
    (r"webhook\.site", Severity.CRITICAL, "network_exfil", "Known exfil domain"),
    (r"ngrok\.io", Severity.HIGH, "network_exfil", "Ngrok tunnel"),
    (r"requestbin\.(com|net)", Severity.CRITICAL, "network_exfil", "Known exfil service"),
    (r"burpcollaborator", Severity.CRITICAL, "network_exfil", "Burp collaborator"),
    (r"pipedream\.net", Severity.HIGH, "network_exfil", "Pipedream webhook"),
    (r"hooks\.zapier\.com", Severity.HIGH, "network_exfil", "Zapier webhook"),
    (r"discord\.com/api/webhooks", Severity.HIGH, "network_exfil", "Discord webhook"),
    (r"slack\.com/api/chat\.postMessage", Severity.MEDIUM, "network_exfil", "Slack message API"),
    
    # Shell Execution
    (r"subprocess\.(?:run|call|Popen)\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "Subprocess with string command"),
    (r"subprocess\.(?:run|call|Popen)\s*\(\s*\[", Severity.MEDIUM, "shell_exec", "Subprocess with list command"),
    (r"os\.system\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "OS system call"),
    (r"os\.popen\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "OS popen"),
    (r"exec\s*\(\s*(?:compile|open)", Severity.CRITICAL, "shell_exec", "Exec with dynamic code"),
    (r"eval\s*\(\s*(?:input|request|argv)", Severity.CRITICAL, "shell_exec", "Eval with user input"),
    (r"\|\s*bash\s*$", Severity.CRITICAL, "shell_exec", "Pipe to bash"),
    (r"\|\s*sh\s*$", Severity.CRITICAL, "shell_exec", "Pipe to shell"),
    (r"bash\s+-c\s+['\"]", Severity.HIGH, "shell_exec", "Bash -c execution"),
    
    # Filesystem
    (r"shutil\.rmtree\s*\(\s*['\"]?/", Severity.CRITICAL, "filesystem", "Recursive delete from root"),
    (r"os\.remove\s*\(\s*['\"]?~", Severity.HIGH, "filesystem", "Delete in home directory"),
    (r"/etc/passwd", Severity.CRITICAL, "filesystem", "System file access"),
    (r"/etc/shadow", Severity.CRITICAL, "filesystem", "Password file access"),
    (r"~/.ssh/(?:id_|authorized)", Severity.CRITICAL, "filesystem", "SSH key access"),
    
    # Obfuscation
    (r"exec\s*\(\s*base64\.b64decode", Severity.CRITICAL, "obfuscation", "Exec base64 payload"),
    (r"eval\s*\(\s*base64\.b64decode", Severity.CRITICAL, "obfuscation", "Eval base64 payload"),
    (r"exec\s*\(\s*codecs\.decode", Severity.CRITICAL, "obfuscation", "Exec encoded payload"),
    (r"exec\s*\(\s*['\"]\\x", Severity.CRITICAL, "obfuscation", "Exec hex-encoded payload"),
    (r"getattr\s*\([^,]+,\s*['\"]__(?:import|builtins|globals)", Severity.CRITICAL, "obfuscation", "Dynamic dunder access"),
    
    # Data Exfiltration
    (r"(post|put|send)\s*\([^)]*\b(password|token|api_?key|secret)\b", Severity.CRITICAL, "data_exfil", "Sending credentials"),
    (r"json\.dumps\s*\([^)]*\benv\b", Severity.HIGH, "data_exfil", "Serializing env"),
    (r"\.env\s*\+\s*['\"]", Severity.HIGH, "data_exfil", "Concatenating env data"),
    
    # Privilege Escalation
    (r"sudo\s+-S", Severity.CRITICAL, "privilege", "Sudo with stdin password"),
    (r"chmod\s+[47]77", Severity.HIGH, "privilege", "World-writable permissions"),
    (r"setuid\s*\(", Severity.CRITICAL, "privilege", "Setuid call"),
    
    # Persistence
    (r"crontab\s+-[el]", Severity.MEDIUM, "persistence", "Cron listing"),
    (r"crontab\s+<<", Severity.CRITICAL, "persistence", "Cron injection"),
    (r"echo\s+.*>>\s*~/\.(bashrc|zshrc|profile)", Severity.HIGH, "persistence", "Shell config injection"),
    (r"/etc/rc\.local", Severity.HIGH, "persistence", "Startup script modification"),
    
    # Crypto/Mining
    (r"xmrig", Severity.CRITICAL, "crypto", "Crypto miner detected"),
    (r"stratum\+tcp://", Severity.CRITICAL, "crypto", "Mining pool protocol"),
    (r"monero.*wallet|wallet.*monero", Severity.CRITICAL, "crypto", "Monero wallet"),
    
    # v3.0 Patterns
    (r"curl\s+.*skill\.md", Severity.CRITICAL, "remote_fetch", "Fetching skill from internet"),
    (r"curl\s+.*SKILL\.md", Severity.CRITICAL, "remote_fetch", "Fetching skill from internet"),
    (r"curl\s+.*heartbeat\.md", Severity.CRITICAL, "remote_fetch", "Fetching heartbeat from internet"),
    (r"curl\s+.*HEARTBEAT\.md", Severity.CRITICAL, "remote_fetch", "Fetching heartbeat from internet"),
    (r"wget\s+.*skill\.md", Severity.CRITICAL, "remote_fetch", "Fetching skill from internet"),
    (r"fetch\s+.*heartbeat", Severity.HIGH, "remote_fetch", "Fetching heartbeat instructions"),
    (r"https?://.*\.md\s*>\s*~/", Severity.CRITICAL, "remote_fetch", "Downloading MD to home dir"),
    (r"https?://.*\.md\s*>\s*~/.*(moltbot|openclaw|clawdbot)", Severity.CRITICAL, "remote_fetch", "Downloading to agent skills dir"),
    
    (r">>\s*.*HEARTBEAT\.md", Severity.CRITICAL, "heartbeat_injection", "Appending to heartbeat file"),
    (r">\s*.*HEARTBEAT\.md", Severity.HIGH, "heartbeat_injection", "Overwriting heartbeat file"),
    (r"echo\s+.*>.*heartbeat", Severity.HIGH, "heartbeat_injection", "Writing to heartbeat"),
    (r"(every|periodic|interval).*fetch.*https?://", Severity.HIGH, "heartbeat_injection", "Periodic remote fetch pattern"),
    
    (r"mcp[_-]?tool", Severity.MEDIUM, "mcp_abuse", "MCP tool reference"),
    (r"no[_-]?human[_-]?(approval|review|confirm)", Severity.CRITICAL, "mcp_abuse", "Bypassing human approval"),
    (r"auto[_-]?approve", Severity.CRITICAL, "mcp_abuse", "Auto-approve pattern"),
    (r"skip[_-]?(confirm|approval|review)", Severity.HIGH, "mcp_abuse", "Skipping confirmation"),
    (r"PreToolUse.*override", Severity.CRITICAL, "mcp_abuse", "Hook override attempt"),
    (r"PromptSubmit.*bypass", Severity.CRITICAL, "mcp_abuse", "Prompt submission bypass"),
    
    (r"[\U000E0001-\U000E007F]", Severity.CRITICAL, "unicode_injection", "Hidden Unicode tag character"),
    (r"\\u[Ee]00[0-7][0-9a-fA-F]", Severity.HIGH, "unicode_injection", "Unicode tag escape sequence"),
    (r"&#x[Ee]00[0-7][0-9a-fA-F];", Severity.HIGH, "unicode_injection", "HTML entity Unicode tag"),
    
    (r"always\s+allow", Severity.HIGH, "auto_approve", "Always allow pattern"),
    (r"allow\s+all", Severity.HIGH, "auto_approve", "Allow all pattern"),
    (r"\$\([^)]+\)", Severity.MEDIUM, "auto_approve", "Process substitution"),
    (r"`[^`]+`", Severity.MEDIUM, "auto_approve", "Backtick command substitution"),
    (r"curl\s+[^|]*\|\s*bash", Severity.CRITICAL, "auto_approve", "Curl pipe to bash"),
    (r"curl\s+[^|]*\|\s*sh", Severity.CRITICAL, "auto_approve", "Curl pipe to shell"),
    
    (r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", Severity.HIGH, "crypto_wallet", "Bitcoin address pattern"),
    (r"0x[a-fA-F0-9]{40}", Severity.HIGH, "crypto_wallet", "Ethereum address pattern"),
    (r"wallet\s*[=:]\s*['\"][^'\"]{25,}", Severity.HIGH, "crypto_wallet", "Wallet assignment"),
    (r"(seed|mnemonic)\s*(phrase|words?)", Severity.CRITICAL, "crypto_wallet", "Seed phrase reference"),
    (r"private[_-]?key\s*[=:]", Severity.CRITICAL, "crypto_wallet", "Private key assignment"),
    
    (r"(i\s+am|i'm)\s+(the\s+)?(admin|owner|developer|creator)", Severity.HIGH, "impersonation", "Authority claim"),
    (r"system\s*:\s*you\s+are", Severity.HIGH, "impersonation", "System prompt injection"),
    (r"\[SYSTEM\]", Severity.HIGH, "impersonation", "Fake system tag"),
    (r"ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)", Severity.CRITICAL, "impersonation", "Instruction override"),
    
    (r"docs\.google\.com/forms.*entry\.", Severity.HIGH, "prefill_exfil", "Google Forms pre-fill"),
    (r"forms\.gle.*\?", Severity.MEDIUM, "prefill_exfil", "Google Forms with params"),
    (r"GET.*[?&](secret|token|key|password)=", Severity.CRITICAL, "prefill_exfil", "Secrets in GET params"),
    
    # Supply chain patterns
    (r"git\s+clone\s+https?://(?!github\.com/(openclaw|henrino3)/)", Severity.HIGH, "supply_chain", "Git clone from external repo"),
    (r"npm\s+install\s+(?!-[gD])", Severity.MEDIUM, "supply_chain", "npm install (supply chain risk)"),
    (r"pip\s+install\s+(?!-r)", Severity.MEDIUM, "supply_chain", "pip install (supply chain risk)"),
    
    # Telemetry patterns
    (r"opentelemetry|otel", Severity.MEDIUM, "telemetry", "OpenTelemetry (sends data externally)"),
    (r"signoz|uptrace|jaeger|zipkin", Severity.HIGH, "telemetry", "Telemetry backend"),
    (r"analytics\.(track|send|log)", Severity.MEDIUM, "telemetry", "Analytics tracking"),
    
    # NEW v5.0: Dependency vulnerability patterns
    (r"pip\s+install\s+.*==.*--force-reinstall", Severity.MEDIUM, "dependency_vuln", "Force reinstall pattern"),
    (r"npm\s+install\s+.*--legacy-peer-deps", Severity.LOW, "dependency_vuln", "Legacy peer deps (may install vulnerable versions)"),
    (r"requirements.*\.txt.*--index-url", Severity.MEDIUM, "dependency_vuln", "Custom package index"),
    (r"npm\s+install\s+.*git\+https?://", Severity.HIGH, "dependency_vuln", "Install from git URL (unverified)"),
    (r"pip\s+install\s+.*git\+https?://", Severity.HIGH, "dependency_vuln", "Install from git URL (unverified)"),
    (r"@([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)@\^?\d+\.\d+\.\d+.*\bmalicious|\bhack|\bbackdoor|\btrojan", Severity.CRITICAL, "dependency_vuln", "Suspicious dependency naming"),
]

SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.sh', '.bash', '.mjs', '.cjs', '.md', '.yaml', '.yml', '.json', '.toml', '.ini', '.txt'}


# =============================================================================
# CONFIG FILE SUPPORT
# =============================================================================

def load_custom_rules(config_path: str) -> List[Tuple[str, Severity, str, str]]:
    """Load custom rules from YAML or JSON config file."""
    import yaml
    
    path = Path(config_path)
    if not path.exists():
        return []
    
    try:
        with open(path) as f:
            if path.suffix == '.json':
                config = json.load(f)
            else:
                config = yaml.safe_load(f)
        
        custom_patterns = []
        if 'patterns' in config:
            for p in config['patterns']:
                severity = getattr(Severity, p.get('severity', 'MEDIUM').upper(), Severity.MEDIUM)
                custom_patterns.append((
                    p['regex'],
                    severity,
                    p.get('category', 'custom'),
                    p.get('description', 'Custom pattern')
                ))
        return custom_patterns
    except Exception as e:
        print(f"⚠️ Warning: Could not load config file: {e}", file=sys.stderr)
        return []


# =============================================================================
# CACHING SYSTEM
# =============================================================================

SCAN_CACHE: Dict[str, Tuple[float, List[Finding]]] = {}

def get_file_hash(filepath: Path) -> str:
    """Get hash of file for caching."""
    try:
        content = filepath.read_bytes()
        return hashlib.md5(content).hexdigest()
    except:
        return ""

def cache_key(filepath: Path, strict: bool) -> str:
    """Generate cache key for file."""
    return f"{filepath}:{get_file_hash(filepath)}:{strict}"

@lru_cache(maxsize=1000)
def scan_file_cached(filepath_str: str, strict: bool = False, mtime: float = 0) -> List[Finding]:
    """Cached version of scan_file."""
    return scan_file(Path(filepath_str), strict)


def scan_file(filepath: Path, strict: bool = False) -> List[Finding]:
    """Scan a single file for security patterns."""
    findings = []
    file_context = get_file_context(filepath)
    
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return findings
    
    lines = content.split('\n')
    
    for pattern, severity, category, description in PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        
        for line_num, line in enumerate(lines, 1):
            matches = list(regex.finditer(line))
            for match in matches:
                is_string = is_in_string_literal(line, match.start())
                is_blocklist = is_blocklist_definition(line, lines[max(0, line_num-6):line_num-1])
                
                if is_blocklist:
                    context = Context.STRING
                elif is_string:
                    context = Context.STRING
                else:
                    context = file_context
                
                if strict:
                    adjusted_severity = severity
                    suppressed = False
                    suppression_reason = ""
                else:
                    adjusted_severity, suppression_reason = adjust_severity_for_context(
                        severity, context, is_string, is_blocklist, str(filepath)
                    )
                    suppressed = adjusted_severity == Severity.SAFE and severity != Severity.SAFE
                
                # Calculate risk score
                risk_score = calculate_risk_score(adjusted_severity, context, category)
                
                findings.append(Finding(
                    severity=adjusted_severity,
                    original_severity=severity,
                    category=category,
                    pattern=pattern,
                    file=str(filepath),
                    line=line_num,
                    match=match.group()[:80],
                    description=description,
                    context=context,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason,
                    risk_score=risk_score
                ))
    
    return findings


def scan_file_worker(args: Tuple[Path, bool]) -> Tuple[Path, List[Finding]]:
    """Worker function for parallel scanning."""
    filepath, strict = args
    findings = scan_file(filepath, strict)
    return filepath, findings


def scan_skill(skill_path: str, strict: bool = False, parallel: bool = True, 
               custom_patterns: Optional[List] = None) -> ScanResult:
    """Scan a skill directory or file."""
    path = Path(skill_path).expanduser().resolve()
    start_time = time.time()
    
    if not path.exists():
        print(f"❌ Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    
    result = ScanResult(path=str(path), files_scanned=0)
    
    if path.is_file():
        files = [path]
    else:
        files = [f for f in path.rglob('*') if f.is_file() and f.suffix.lower() in SCAN_EXTENSIONS]
    
    # Parallel scanning for performance
    if parallel and len(files) > 10:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            args = [(f, strict) for f in files]
            for filepath, findings in executor.map(scan_file_worker, args):
                result.files_scanned += 1
                result.findings.extend(findings)
    else:
        for filepath in files:
            result.files_scanned += 1
            findings = scan_file(filepath, strict)
            result.findings.extend(findings)
    
    result.suppressed_count = len([f for f in result.findings if f.suppressed])
    result.scan_duration = time.time() - start_time
    
    return result


# =============================================================================
# AI ANALYSIS WITH MULTI-PROVIDER SUPPORT
# =============================================================================

def get_skill_content(path: str, max_chars: int = 50000) -> str:
    """Get skill content for AI analysis."""
    p = Path(path)
    content_parts = []
    total_chars = 0
    
    for filepath in sorted(p.rglob('*')):
        if filepath.is_file() and filepath.suffix.lower() in SCAN_EXTENSIONS:
            try:
                text = filepath.read_text(encoding='utf-8', errors='ignore')
                rel_path = str(filepath.relative_to(p))
                chunk = f"\n--- {rel_path} ---\n{text[:10000]}\n"
                if total_chars + len(chunk) > max_chars:
                    break
                content_parts.append(chunk)
                total_chars += len(chunk)
            except:
                pass
    
    return ''.join(content_parts)


def call_ai_provider(provider: str, model: Optional[str], prompt: str) -> Optional[str]:
    """Call AI provider with the given model and prompt."""
    api_key = ModelProvider.get_api_key(provider)
    if not api_key:
        return None
    
    config = ModelProvider.PROVIDERS.get(provider, {})
    api_url = config.get('api_url', '')
    default_model = config.get('default_model', 'gpt-4o')
    model = model or default_model
    
    try:
        import urllib.request
        import urllib.error
        
        if provider == 'anthropic':
            # Anthropic uses different API format
            data = json.dumps({
                "model": model,
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}]
            }).encode('utf-8')
            
            req = urllib.request.Request(
                api_url,
                data=data,
                headers={
                    'x-api-key': api_key,
                    'Content-Type': 'application/json',
                    'anthropic-version': '2023-06-01'
                }
            )
        else:
            # Standard OpenAI-compatible format
            data = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4000
            }).encode('utf-8')
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
            }
            
            if provider == 'openrouter':
                headers['HTTP-Referer'] = 'https://github.com/henrino3/heimdall'
            
            req = urllib.request.Request(api_url, data=data, headers=headers)
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            result_json = json.loads(resp.read().decode('utf-8'))
            
            if provider == 'anthropic':
                return result_json.get('content', [{}])[0].get('text', '')
            else:
                return result_json['choices'][0]['message']['content']
                
    except Exception as e:
        return None


def generate_ai_analysis(result: ScanResult, skill_content: str, 
                         provider: Optional[str] = None, 
                         model: Optional[str] = None) -> str:
    """Generate AI-powered narrative analysis with multi-provider support."""
    
    # Build findings summary for the prompt
    findings_text = []
    for f in result.active_findings:
        if f.severity >= Severity.MEDIUM:
            findings_text.append(f"- [{f.severity.name}] {f.category}: {f.description} (Match: {f.match})")
    
    findings_summary = '\n'.join(findings_text[:30])  # Limit to top 30
    
    prompt = f"""You are a security analyst reviewing an AI agent skill for potential risks.

SKILL PATH: {result.path}
FILES SCANNED: {result.files_scanned}
MAX SEVERITY: {result.max_severity.name}
ACTIVE ISSUES: {len(result.active_findings)}

DETECTED PATTERNS:
{findings_summary}

SKILL CONTENT (truncated):
{skill_content[:30000]}

Write a security analysis report in this EXACT format:

============================================================
🔍 HEIMDALL SECURITY ANALYSIS
============================================================

📁 Skill: [skill name]
⚡ Verdict: [emoji + verdict based on severity]

## Summary
[2-3 sentence overview of what this skill does and the main security concerns]

## Key Risks

### 1. [Risk Category]
[Explain what the pattern does, why it's dangerous, and what an attacker could achieve]

### 2. [Risk Category]
[Same format - be specific about the attack scenario]

[Add more risks as needed, focus on CRITICAL and HIGH severity only]

## What You're Agreeing To
[Numbered list of what the user accepts by installing this skill]

## Recommendation
🔴/🟡/🟢 [Clear actionable recommendation]
✅ Safe conditions (if any)

## References
- [Relevant security sources if applicable]
============================================================

Be direct, specific, and alarming where appropriate. Focus on real risks, not theoretical ones.
If the skill appears safe, say so clearly."""

    # Try specified provider first
    if provider:
        response = call_ai_provider(provider, model, prompt)
        if response:
            return response
    
    # Auto-detect and try available providers in priority order
    available = ModelProvider.detect_available()
    for p in available:
        response = call_ai_provider(p, model, prompt)
        if response:
            return f"<!-- Analysis powered by {p} -->\n{response}"
    
    # Try oracle CLI as fallback
    try:
        proc = subprocess.run(
            ['oracle', '-m', 'anthropic/claude-sonnet-4-20250514', '-p', prompt],
            capture_output=True,
            text=True,
            timeout=120
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    
    # Final fallback: generate basic report without AI
    return generate_basic_report(result)


def generate_basic_report(result: ScanResult) -> str:
    """Generate a basic report without AI when API is unavailable."""
    skill_name = Path(result.path).name
    
    critical = [f for f in result.active_findings if f.severity == Severity.CRITICAL]
    high = [f for f in result.active_findings if f.severity == Severity.HIGH]
    
    report = f"""
============================================================
🔍 HEIMDALL SECURITY ANALYSIS (Basic Mode)
============================================================

📁 Skill: {skill_name}
⚡ Verdict: {result.action}

## Summary
Automated scan detected {len(result.active_findings)} potential security issues.
AI analysis unavailable - showing pattern-based findings only.

## Critical Issues ({len(critical)})
"""
    
    for f in critical[:5]:
        report += f"\n### {f.category}\n- **Pattern:** {f.description}\n- **Match:** `{f.match}`\n- **Location:** {f.file}:{f.line}\n"
    
    report += f"\n## High Severity Issues ({len(high)})\n"
    
    for f in high[:5]:
        report += f"\n### {f.category}\n- **Pattern:** {f.description}\n- **Match:** `{f.match}`\n"
    
    report += """
## Recommendation
Review the flagged patterns manually before installing.
Run with --analyze and ensure an AI provider API key is set for full analysis.

============================================================
"""
    return report


# =============================================================================
# OUTPUT FORMATS
# =============================================================================

def generate_sarif(result: ScanResult) -> Dict:
    """Generate SARIF output for GitHub Security integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Heimdall Skill Scanner",
                    "version": "5.0",
                    "informationUri": "https://github.com/henrino3/heimdall"
                }
            },
            "results": []
        }]
    }
    
    for f in result.active_findings:
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.SAFE: "none"
        }
        
        result_entry = {
            "ruleId": f.category,
            "message": {
                "text": f.description
            },
            "level": severity_map.get(f.severity, "warning"),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file.replace(result.path + '/', '')
                    },
                    "region": {
                        "startLine": f.line
                    }
                }
            }],
            "properties": {
                "riskScore": f.risk_score,
                "context": f.context.name
            }
        }
        sarif["runs"][0]["results"].append(result_entry)
    
    return sarif


def generate_markdown_report(result: ScanResult) -> str:
    """Generate Markdown report."""
    md = f"""# Heimdall Security Scan Report

**Skill:** `{result.path}`  
**Files Scanned:** {result.files_scanned}  
**Scan Duration:** {result.scan_duration:.2f}s  
**Risk Score:** {result.risk_score}/100 ({result.risk_level})  

## Summary

| Metric | Value |
|--------|-------|
| Active Findings | {len(result.active_findings)} |
| Suppressed Findings | {result.suppressed_count} |
| Max Severity | {result.max_severity.name} |
| Action | {result.action} |

## Findings by Severity

"""
    
    active = result.active_findings
    if active:
        by_severity: Dict[Severity, List[Finding]] = {}
        for f in active:
            by_severity.setdefault(f.severity, []).append(f)
        
        for sev in sorted(by_severity.keys(), reverse=True):
            findings = by_severity[sev]
            emoji = "🚨" if sev >= Severity.HIGH else "⚠️" if sev >= Severity.MEDIUM else "📝"
            md += f"### {emoji} {sev.name} ({len(findings)} issues)\n\n"
            
            by_cat: Dict[str, List[Finding]] = {}
            for f in findings:
                by_cat.setdefault(f.category, []).append(f)
            
            for cat, cat_findings in by_cat.items():
                md += f"**{cat}** ({len(cat_findings)})\n\n"
                for f in cat_findings[:5]:
                    rel_path = f.file.replace(result.path + '/', '')
                    md += f"- `{rel_path}:{f.line}` - {f.description} (Risk: {f.risk_score})\n"
                if len(cat_findings) > 5:
                    md += f"- ... and {len(cat_findings) - 5} more\n"
                md += "\n"
    
    md += f"""
## Recommendation

{result.action}

---
*Generated by Heimdall v5.0*
"""
    return md


# =============================================================================
# INTERACTIVE MODE
# =============================================================================

def interactive_review(result: ScanResult):
    """Interactive review mode for findings."""
    active = result.active_findings
    if not active:
        print("✅ No issues found! Nothing to review.")
        return
    
    print("\n" + "="*60)
    print("🔍 INTERACTIVE REVIEW MODE")
    print("="*60)
    print(f"Found {len(active)} issues to review.\n")
    
    reviewed = []
    for i, f in enumerate(active, 1):
        print(f"\n[{i}/{len(active)}] {f.severity.name}: {f.category}")
        print(f"  File: {f.file}:{f.line}")
        print(f"  Match: {f.match}")
        print(f"  Description: {f.description}")
        print(f"  Risk Score: {f.risk_score}/100")
        print()
        
        while True:
            choice = input("Action: [a]pprove, [s]uppress, [d]etails, [q]uit: ").lower().strip()
            if choice == 'a':
                reviewed.append(('approved', f))
                print("  ✅ Approved")
                break
            elif choice == 's':
                reviewed.append(('suppressed', f))
                print("  🔇 Suppressed")
                break
            elif choice == 'd':
                print(f"  Pattern: {f.pattern}")
                print(f"  Context: {f.context.name}")
            elif choice == 'q':
                print("\nReview session saved.")
                return
            else:
                print("  Invalid choice")
    
    # Summary
    approved = len([r for r in reviewed if r[0] == 'approved'])
    suppressed = len([r for r in reviewed if r[0] == 'suppressed'])
    print(f"\n\nReview complete: {approved} approved, {suppressed} suppressed")


# =============================================================================
# REPORTING
# =============================================================================

def print_report(result: ScanResult, verbose: bool = False, show_suppressed: bool = False,
                 show_risk_score: bool = True):
    """Print scan report."""
    print("\n" + "="*60)
    print("🔍 SKILL SECURITY SCAN REPORT v5.0")
    print("="*60)
    print(f"📁 Path: {result.path}")
    print(f"📄 Files scanned: {result.files_scanned}")
    print(f"⏱️  Scan duration: {result.scan_duration:.2f}s")
    if show_risk_score:
        print(f"🎯 Risk Score: {result.risk_score}/100 ({result.risk_level})")
    print(f"🔢 Active issues: {len(result.active_findings)}")
    if result.suppressed_count > 0:
        print(f"🔇 Suppressed (context-aware): {result.suppressed_count}")
    print(f"⚡ Max severity: {result.max_severity.name}")
    print(f"📋 Action: {result.action}")
    print("="*60)
    
    active = result.active_findings
    if active:
        by_severity: Dict[Severity, List[Finding]] = {}
        for f in active:
            by_severity.setdefault(f.severity, []).append(f)
        
        for sev in sorted(by_severity.keys(), reverse=True):
            findings = by_severity[sev]
            print(f"\n{'🚨' if sev >= Severity.HIGH else '⚠️'} {sev.name} ({len(findings)} issues):")
            
            by_cat: Dict[str, List[Finding]] = {}
            for f in findings:
                by_cat.setdefault(f.category, []).append(f)
            
            for cat, cat_findings in by_cat.items():
                print(f"  [{cat}]")
                shown = 0
                for f in cat_findings:
                    if verbose or shown < 3:
                        rel_path = f.file.replace(result.path + '/', '')
                        ctx = f"[{f.context.name}]" if f.context != Context.CODE else ""
                        risk = f"[Risk: {f.risk_score}]" if show_risk_score else ""
                        print(f"    • {rel_path}:{f.line} {ctx} {risk}")
                        print(f"      Match: {f.match}")
                        shown += 1
                if not verbose and len(cat_findings) > 3:
                    print(f"    ... and {len(cat_findings) - 3} more")
    
    if show_suppressed and result.suppressed_count > 0:
        print(f"\n🔇 SUPPRESSED FINDINGS ({result.suppressed_count}):")
        suppressed = [f for f in result.findings if f.suppressed]
        for f in suppressed[:10]:
            rel_path = f.file.replace(result.path + '/', '')
            print(f"  • {rel_path}:{f.line} - {f.description}")
            print(f"    Reason: {f.suppression_reason}")
        if len(suppressed) > 10:
            print(f"  ... and {len(suppressed) - 10} more")
    
    print("\n" + "="*60)
    
    if result.max_severity >= Severity.HIGH:
        print("❌ RECOMMENDATION: Do NOT install this skill without thorough review")
        return 1
    elif result.max_severity >= Severity.MEDIUM:
        print("⚠️ RECOMMENDATION: Review flagged items before installing")
        return 0
    else:
        print("✅ RECOMMENDATION: Skill appears safe to install")
        return 0


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scan OpenClaw skills for security issues (v5.0 - Multi-Provider AI)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('path', help='Path to skill directory or file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all findings')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--sarif', action='store_true', help='Output as SARIF for GitHub Security')
    parser.add_argument('--markdown', '--md', action='store_true', help='Output as Markdown report')
    parser.add_argument('--strict', action='store_true', help='Ignore context, flag everything')
    parser.add_argument('--show-suppressed', action='store_true', help='Show suppressed findings')
    parser.add_argument('--analyze', action='store_true', help='AI-powered narrative analysis')
    parser.add_argument('--provider', choices=['openrouter', 'anthropic', 'openai', 'zai'],
                       help='AI provider to use (auto-detect if not specified)')
    parser.add_argument('--model', help='Specific model to use (provider default if not specified)')
    parser.add_argument('--interactive', action='store_true', help='Interactive review mode')
    parser.add_argument('--config', help='Path to custom rules config file (YAML or JSON)')
    parser.add_argument('--ci', action='store_true', help='CI mode (returns exit code 1 for HIGH/CRITICAL)')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel scanning')
    
    args = parser.parse_args()
    
    # Load custom rules if specified
    custom_patterns = None
    if args.config:
        custom_patterns = load_custom_rules(args.config)
        if custom_patterns:
            PATTERNS.extend(custom_patterns)
            print(f"📋 Loaded {len(custom_patterns)} custom patterns from {args.config}")
    
    # Run scan
    result = scan_skill(args.path, strict=args.strict, parallel=not args.no_parallel)
    
    # Interactive mode
    if args.interactive:
        interactive_review(result)
        sys.exit(0)
    
    # AI Analysis
    if args.analyze:
        print("\n🔍 Running AI-powered security analysis...")
        available = ModelProvider.detect_available()
        if available:
            print(f"   Available providers: {', '.join(available)}")
            if args.provider:
                print(f"   Using: {args.provider}" + (f" ({args.model})" if args.model else ""))
        print()
        skill_content = get_skill_content(args.path)
        analysis = generate_ai_analysis(result, skill_content, args.provider, args.model)
        print(analysis)
        sys.exit(result.exit_code if args.ci else 0)
    
    # JSON Output
    if args.json:
        output = {
            'version': '5.0',
            'path': result.path,
            'files_scanned': result.files_scanned,
            'scan_duration': result.scan_duration,
            'risk_score': result.risk_score,
            'risk_level': result.risk_level,
            'max_severity': result.max_severity.name,
            'action': result.action,
            'active_findings': len(result.active_findings),
            'suppressed_findings': result.suppressed_count,
            'findings': [
                {
                    'severity': f.severity.name,
                    'original_severity': f.original_severity.name,
                    'category': f.category,
                    'file': f.file,
                    'line': f.line,
                    'match': f.match,
                    'description': f.description,
                    'context': f.context.name,
                    'suppressed': f.suppressed,
                    'suppression_reason': f.suppression_reason,
                    'risk_score': f.risk_score
                }
                for f in result.findings if not f.suppressed or args.show_suppressed
            ]
        }
        print(json.dumps(output, indent=2))
        sys.exit(result.exit_code if args.ci else 0)
    
    # SARIF Output
    if args.sarif:
        sarif_output = generate_sarif(result)
        print(json.dumps(sarif_output, indent=2))
        sys.exit(result.exit_code if args.ci else 0)
    
    # Markdown Output
    if args.markdown:
        md_output = generate_markdown_report(result)
        print(md_output)
        sys.exit(result.exit_code if args.ci else 0)
    
    # Default report
    exit_code = print_report(result, args.verbose, args.show_suppressed)
    sys.exit(result.exit_code if args.ci else exit_code)


if __name__ == '__main__':
    main()
