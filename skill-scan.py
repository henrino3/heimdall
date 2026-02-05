#!/usr/bin/env python3
"""
Skill Scanner v2.0 - Context-Aware Security Scanner for OpenClaw Skills
Scans skill code for malicious patterns before installation.

v2.0 Improvements:
- Context-aware scanning (documentation vs execution)
- String literal detection (patterns in blocklists don't trigger)
- File type awareness (*.md treated as docs, *.py as code)
- Reduced false positives for security tools
- Whitelist support for known-good skills

Usage:
    skill-scan <path-to-skill>
    skill-scan --json <path>     # JSON output
    skill-scan -v <path>         # Verbose
    skill-scan --strict <path>   # Ignore context, flag everything

Severity Levels:
    SAFE (0)     - No issues found
    LOW (1)      - Minor concerns, probably fine
    MEDIUM (2)   - Review recommended
    HIGH (3)     - Likely malicious, do not install
    CRITICAL (4) - Definitely malicious, block immediately
"""

import os
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from enum import IntEnum


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


@dataclass
class Finding:
    severity: Severity
    original_severity: Severity  # Before context adjustment
    category: str
    pattern: str
    file: str
    line: int
    match: str
    description: str
    context: Context
    suppressed: bool = False
    suppression_reason: str = ""


@dataclass
class ScanResult:
    path: str
    files_scanned: int
    findings: List[Finding] = field(default_factory=list)
    suppressed_count: int = 0
    
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


# =============================================================================
# CONTEXT DETECTION
# =============================================================================

# File extensions and their context
FILE_CONTEXTS = {
    # Documentation
    '.md': Context.DOCS,
    '.txt': Context.DOCS,
    '.rst': Context.DOCS,
    '.adoc': Context.DOCS,
    
    # Config
    '.yaml': Context.CONFIG,
    '.yml': Context.CONFIG,
    '.json': Context.CONFIG,
    '.toml': Context.CONFIG,
    '.ini': Context.CONFIG,
    
    # Code (default)
    '.py': Context.CODE,
    '.js': Context.CODE,
    '.ts': Context.CODE,
    '.sh': Context.CODE,
    '.bash': Context.CODE,
    '.mjs': Context.CODE,
    '.cjs': Context.CODE,
}

# Patterns that indicate a line is defining a blocklist/pattern list
BLOCKLIST_INDICATORS = [
    r'patterns?\s*[=:]',
    r'blocklist\s*[=:]',
    r'blacklist\s*[=:]',
    r'detect(ion)?_patterns?',
    r'malicious_patterns?',
    r'attack_patterns?',
    r'PATTERNS\s*[=:\[]',
    r'regex(es)?\s*[=:]',
    r'r["\'].*["\'],?\s*#',  # Python raw string with comment (pattern definition)
    r'description["\']?\s*:',  # Description field in pattern def
]

# Known security tools that legitimately contain attack patterns
SECURITY_TOOL_INDICATORS = [
    'prompt-guard',
    'prompt_guard',
    'security-scan',
    'detect.py',
    'patterns.py',
    'blocklist',
    'firewall',
    'waf',
    'filter',
]


def get_file_context(filepath: Path) -> Context:
    """Determine context based on file type and name."""
    suffix = filepath.suffix.lower()
    name = filepath.name.lower()
    
    # Check for security tool files
    for indicator in SECURITY_TOOL_INDICATORS:
        if indicator in str(filepath).lower():
            return Context.DOCS  # Treat security tools as docs (patterns are examples)
    
    # Changelog, readme, etc. are docs regardless of extension
    if any(doc in name for doc in ['readme', 'changelog', 'license', 'contributing', 'history']):
        return Context.DOCS
    
    return FILE_CONTEXTS.get(suffix, Context.CODE)


def is_in_string_literal(line: str, match_start: int) -> bool:
    """Check if a match position is inside a string literal."""
    # Count quotes before the match
    before = line[:match_start]
    
    # Simple heuristic: odd number of unescaped quotes means we're in a string
    single_quotes = len(re.findall(r"(?<!\\)'", before))
    double_quotes = len(re.findall(r'(?<!\\)"', before))
    
    # Also check for raw strings (r"..." or r'...')
    raw_double = len(re.findall(r'r"', before))
    raw_single = len(re.findall(r"r'", before))
    
    in_single = (single_quotes - raw_single) % 2 == 1
    in_double = (double_quotes - raw_double) % 2 == 1
    
    return in_single or in_double


def is_blocklist_definition(line: str, prev_lines: List[str]) -> bool:
    """Check if this line is defining a blocklist/pattern list."""
    context_lines = prev_lines[-5:] + [line]  # Check last 5 lines + current
    context = '\n'.join(context_lines)
    
    for indicator in BLOCKLIST_INDICATORS:
        if re.search(indicator, context, re.IGNORECASE):
            return True
    
    return False


def adjust_severity_for_context(severity: Severity, context: Context, 
                                 is_string: bool, is_blocklist: bool,
                                 filepath: str = "") -> Tuple[Severity, str]:
    """Adjust severity based on context, return new severity and reason."""
    # Check if this is a known security tool
    is_security_tool = any(ind in filepath.lower() for ind in SECURITY_TOOL_INDICATORS)
    
    if is_blocklist:
        # Pattern definitions in blocklists are expected
        return Severity.SAFE, "Pattern in blocklist definition"
    
    if is_security_tool:
        # Security tools legitimately contain attack patterns
        if context in (Context.DOCS, Context.STRING) or is_string:
            return Severity.SAFE, "Security tool - pattern example"
        # Even in code, reduce severity for security tools
        new_sev = max(Severity.LOW, Severity(severity.value - 2))
        return new_sev, "Security tool - detection pattern"
    
    if is_string:
        # String literals often contain examples, patterns to match
        new_sev = max(Severity.SAFE, Severity(severity.value - 3))
        return new_sev, "Pattern in string literal"
    
    if context == Context.DOCS:
        # Documentation examples
        new_sev = max(Severity.SAFE, Severity(severity.value - 3))
        return new_sev, "Pattern in documentation"
    
    if context == Context.CONFIG:
        # Config files - slightly reduced
        new_sev = max(Severity.LOW, Severity(severity.value - 1))
        return new_sev, "Pattern in config file"
    
    return severity, ""


# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

PATTERNS: List[Tuple[str, Severity, str, str]] = [
    # Category: Credential Access (HIGH-CRITICAL)
    (r"cat\s+.*\.env\b", Severity.CRITICAL, "credential_access", "Reading .env file"),
    (r"source\s+.*\.env\b", Severity.HIGH, "credential_access", "Sourcing .env file"),
    (r"open\([^)]*\.env[^)]*\)", Severity.HIGH, "credential_access", "Opening .env file"),
    (r"secrets?/[a-zA-Z]", Severity.HIGH, "credential_access", "Accessing secrets directory"),
    (r"password\s*=\s*['\"][^'\"]+['\"]", Severity.CRITICAL, "credential_access", "Hardcoded password"),
    (r"api[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]", Severity.CRITICAL, "credential_access", "Hardcoded API key"),
    (r"token\s*=\s*['\"][^'\"]{20,}['\"]", Severity.CRITICAL, "credential_access", "Hardcoded token"),
    (r"BEGIN\s+(RSA|PRIVATE|OPENSSH)\s+PRIVATE\s+KEY", Severity.CRITICAL, "credential_access", "Embedded private key"),
    
    # Category: External Network - Actual Requests (HIGH-CRITICAL)
    (r"curl\s+-[^s]*\s+(http|https)://(?!localhost|127\.0\.0\.1)", Severity.HIGH, "network_exfil", "Curl to external URL"),
    (r"wget\s+(http|https)://(?!localhost|127\.0\.0\.1)", Severity.HIGH, "network_exfil", "Wget to external URL"),
    (r"requests\.(get|post|put|delete)\s*\(['\"]https?://(?!localhost)", Severity.MEDIUM, "network_exfil", "HTTP request to external"),
    (r"fetch\s*\(\s*['\"]https?://(?!localhost)", Severity.MEDIUM, "network_exfil", "Fetch to external URL"),
    (r"webhook\.site", Severity.CRITICAL, "network_exfil", "Known exfil domain"),
    (r"ngrok\.io", Severity.HIGH, "network_exfil", "Ngrok tunnel"),
    (r"requestbin\.(com|net)", Severity.CRITICAL, "network_exfil", "Known exfil service"),
    (r"burpcollaborator", Severity.CRITICAL, "network_exfil", "Burp collaborator"),
    
    # Category: Shell Execution (HIGH) - More specific patterns
    (r"subprocess\.(?:run|call|Popen)\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "Subprocess with string command"),
    (r"subprocess\.(?:run|call|Popen)\s*\(\s*\[", Severity.MEDIUM, "shell_exec", "Subprocess with list command"),
    (r"os\.system\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "OS system call"),
    (r"os\.popen\s*\(\s*['\"]", Severity.HIGH, "shell_exec", "OS popen"),
    (r"exec\s*\(\s*(?:compile|open)", Severity.CRITICAL, "shell_exec", "Exec with dynamic code"),
    (r"eval\s*\(\s*(?:input|request|argv)", Severity.CRITICAL, "shell_exec", "Eval with user input"),
    (r"\|\s*bash\s*$", Severity.CRITICAL, "shell_exec", "Pipe to bash"),
    (r"\|\s*sh\s*$", Severity.CRITICAL, "shell_exec", "Pipe to shell"),
    (r"bash\s+-c\s+['\"]", Severity.HIGH, "shell_exec", "Bash -c execution"),
    
    # Category: File System - Dangerous Operations
    (r"shutil\.rmtree\s*\(\s*['\"]?/", Severity.CRITICAL, "filesystem", "Recursive delete from root"),
    (r"os\.remove\s*\(\s*['\"]?~", Severity.HIGH, "filesystem", "Delete in home directory"),
    (r"/etc/passwd", Severity.CRITICAL, "filesystem", "System file access"),
    (r"/etc/shadow", Severity.CRITICAL, "filesystem", "Password file access"),
    (r"~/.ssh/(?:id_|authorized)", Severity.CRITICAL, "filesystem", "SSH key access"),
    
    # Category: Obfuscation - Execution of encoded content
    (r"exec\s*\(\s*base64\.b64decode", Severity.CRITICAL, "obfuscation", "Exec base64 payload"),
    (r"eval\s*\(\s*base64\.b64decode", Severity.CRITICAL, "obfuscation", "Eval base64 payload"),
    (r"exec\s*\(\s*codecs\.decode", Severity.CRITICAL, "obfuscation", "Exec encoded payload"),
    (r"exec\s*\(\s*['\"]\\x", Severity.CRITICAL, "obfuscation", "Exec hex-encoded payload"),
    (r"getattr\s*\([^,]+,\s*['\"]__(?:import|builtins|globals)", Severity.CRITICAL, "obfuscation", "Dynamic dunder access"),
    
    # Category: Data Exfiltration - Sending credentials
    (r"(post|put|send)\s*\([^)]*\b(password|token|api_?key|secret)\b", Severity.CRITICAL, "data_exfil", "Sending credentials"),
    (r"json\.dumps\s*\([^)]*\benv\b", Severity.HIGH, "data_exfil", "Serializing env"),
    
    # Category: Privilege Escalation
    (r"sudo\s+-S", Severity.CRITICAL, "privilege", "Sudo with stdin password"),
    (r"chmod\s+[47]77", Severity.HIGH, "privilege", "World-writable permissions"),
    (r"setuid\s*\(", Severity.CRITICAL, "privilege", "Setuid call"),
    
    # Category: Persistence
    (r"crontab\s+-[el]", Severity.MEDIUM, "persistence", "Cron listing"),
    (r"crontab\s+<<", Severity.CRITICAL, "persistence", "Cron injection"),
    (r"echo\s+.*>>\s*~/\.(bashrc|zshrc|profile)", Severity.HIGH, "persistence", "Shell config injection"),
    (r"/etc/rc\.local", Severity.HIGH, "persistence", "Startup script modification"),
    
    # Category: Crypto/Mining
    (r"xmrig", Severity.CRITICAL, "crypto", "Crypto miner detected"),
    (r"stratum\+tcp://", Severity.CRITICAL, "crypto", "Mining pool protocol"),
    (r"monero.*wallet|wallet.*monero", Severity.CRITICAL, "crypto", "Monero wallet"),
]

# File extensions to scan
SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.sh', '.bash', '.mjs', '.cjs', '.md', '.yaml', '.yml', '.json'}


def scan_file(filepath: Path, strict: bool = False) -> List[Finding]:
    """Scan a single file for malicious patterns with context awareness."""
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
                # Context detection
                is_string = is_in_string_literal(line, match.start())
                is_blocklist = is_blocklist_definition(line, lines[max(0, line_num-6):line_num-1])
                
                # Determine context
                if is_blocklist:
                    context = Context.STRING
                elif is_string:
                    context = Context.STRING
                else:
                    context = file_context
                
                # Adjust severity
                if strict:
                    adjusted_severity = severity
                    suppressed = False
                    suppression_reason = ""
                else:
                    adjusted_severity, suppression_reason = adjust_severity_for_context(
                        severity, context, is_string, is_blocklist, str(filepath)
                    )
                    suppressed = adjusted_severity == Severity.SAFE and severity != Severity.SAFE
                
                findings.append(Finding(
                    severity=adjusted_severity,
                    original_severity=severity,
                    category=category,
                    pattern=pattern,
                    file=str(filepath),
                    line=line_num,
                    match=match.group()[:60],
                    description=description,
                    context=context,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason
                ))
    
    return findings


def scan_skill(skill_path: str, strict: bool = False) -> ScanResult:
    """Scan all files in a skill directory."""
    path = Path(skill_path).expanduser().resolve()
    
    if not path.exists():
        print(f"❌ Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    
    result = ScanResult(path=str(path), files_scanned=0)
    
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob('*'))
    
    for filepath in files:
        if filepath.is_file() and filepath.suffix.lower() in SCAN_EXTENSIONS:
            result.files_scanned += 1
            findings = scan_file(filepath, strict)
            result.findings.extend(findings)
    
    result.suppressed_count = len([f for f in result.findings if f.suppressed])
    
    return result


def print_report(result: ScanResult, verbose: bool = False, show_suppressed: bool = False):
    """Print scan report."""
    print("\n" + "="*60)
    print("🔍 SKILL SECURITY SCAN REPORT v2.0")
    print("="*60)
    print(f"📁 Path: {result.path}")
    print(f"📄 Files scanned: {result.files_scanned}")
    print(f"🔢 Active issues: {len(result.active_findings)}")
    if result.suppressed_count > 0:
        print(f"🔇 Suppressed (context-aware): {result.suppressed_count}")
    print(f"⚡ Max severity: {result.max_severity.name}")
    print(f"📋 Action: {result.action}")
    print("="*60)
    
    active = result.active_findings
    if active:
        # Group by severity
        by_severity: Dict[Severity, List[Finding]] = {}
        for f in active:
            by_severity.setdefault(f.severity, []).append(f)
        
        for sev in sorted(by_severity.keys(), reverse=True):
            findings = by_severity[sev]
            print(f"\n{'🚨' if sev >= Severity.HIGH else '⚠️'} {sev.name} ({len(findings)} issues):")
            
            # Group by category
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
                        print(f"    • {rel_path}:{f.line} {ctx} - {f.description}")
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
    
    # Exit code based on severity
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
        description='Scan OpenClaw skills for security issues (v2.0 - Context-Aware)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('path', help='Path to skill directory or file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all findings')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--strict', action='store_true', help='Ignore context, flag everything')
    parser.add_argument('--show-suppressed', action='store_true', help='Show suppressed findings')
    
    args = parser.parse_args()
    
    result = scan_skill(args.path, strict=args.strict)
    
    if args.json:
        output = {
            'version': '2.0',
            'path': result.path,
            'files_scanned': result.files_scanned,
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
                    'suppression_reason': f.suppression_reason
                }
                for f in result.findings if not f.suppressed or args.show_suppressed
            ]
        }
        print(json.dumps(output, indent=2))
        sys.exit(1 if result.max_severity >= Severity.HIGH else 0)
    else:
        sys.exit(print_report(result, args.verbose, args.show_suppressed))


if __name__ == '__main__':
    main()
