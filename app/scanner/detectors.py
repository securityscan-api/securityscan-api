import re
from dataclasses import dataclass, asdict
from typing import List, Optional
from sqlalchemy.orm import Session


@dataclass
class Issue:
    type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    line: int
    description: str
    snippet: str

    def to_dict(self):
        return asdict(self)


def find_line_number(code: str, match_start: int) -> int:
    return code[:match_start].count('\n') + 1


# === Skill Security Detectors ===

def detect_hardcoded_credentials(code: str, filename: str) -> List[Issue]:
    """Detect hardcoded API keys, passwords, tokens."""
    issues = []

    patterns = [
        (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "API key (sk-...)"),
        (r'["\']pk-[a-zA-Z0-9]{20,}["\']', "API key (pk-...)"),
        (r'["\']ghp_[a-zA-Z0-9]{36,}["\']', "GitHub token"),
        (r'["\']xox[baprs]-[a-zA-Z0-9-]{10,}["\']', "Slack token"),
        (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
        (r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
        (r'["\']AKIA[A-Z0-9]{16}["\']', "AWS Access Key"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            line_num = find_line_number(code, match.start())
            snippet = match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
            issues.append(Issue(
                type="hardcoded_credentials",
                severity="HIGH",
                line=line_num,
                description=f"{desc} found in {filename}",
                snippet=snippet
            ))

    return issues


def detect_exfiltration(code: str, filename: str) -> List[Issue]:
    """Detect attempts to send data to external servers."""
    issues = []

    patterns = [
        (r'fetch\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)[^"\']+["\'].*?(memory|credential|secret|token|key|password)', "fetch() with sensitive data"),
        (r'axios\.(post|put)\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)[^"\']+["\'].*?(memory|credential|secret)', "axios POST with sensitive data"),
        (r'requests\.(post|put)\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)[^"\']+["\'].*?(memory|credential|secret)', "requests POST with sensitive data"),
        (r'(agent|bot)\.(memory|credentials|secrets).*?(fetch|axios|requests|http)', "Agent data sent externally"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
            line_num = find_line_number(code, match.start())
            snippet = code[match.start():match.start()+80].replace('\n', ' ')
            issues.append(Issue(
                type="exfiltration",
                severity="CRITICAL",
                line=line_num,
                description=f"Potential data exfiltration: {desc}",
                snippet=snippet
            ))

    return issues


def detect_remote_code_execution(code: str, filename: str) -> List[Issue]:
    """Detect dynamic code evaluation with external input."""
    issues = []

    patterns = [
        (r'\beval\s*\([^)]*\b(input|request|body|query|params|user)', "eval() with user input"),
        (r'\beval\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', "eval() with variable"),
        (r'Function\s*\([^)]*\)\s*\(', "Function constructor"),
        (r'subprocess\.(run|call|Popen)\s*\([^)]*\b(input|request|user)', "subprocess with user input"),
        (r'os\.system\s*\(', "os.system call"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            line_num = find_line_number(code, match.start())
            snippet = code[match.start():match.start()+60].replace('\n', ' ')
            issues.append(Issue(
                type="remote_code_execution",
                severity="MEDIUM",
                line=line_num,
                description=f"Potential RCE: {desc}",
                snippet=snippet
            ))

    return issues


def detect_privilege_escalation(code: str, filename: str) -> List[Issue]:
    """Detect access to system resources outside normal scope."""
    issues = []

    patterns = [
        (r'os\.(system|popen|spawn)', "OS command execution"),
        (r'fs\.(readFile|writeFile|unlink|rmdir)\s*\(\s*["\']/', "Filesystem access to root"),
        (r'open\s*\(\s*["\']/(etc|var|usr|root)', "Access to system directories"),
        (r'process\.env\b', "Environment variable access"),
        (r'__import__\s*\(', "Dynamic import"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            line_num = find_line_number(code, match.start())
            snippet = code[match.start():match.start()+50].replace('\n', ' ')
            issues.append(Issue(
                type="privilege_escalation",
                severity="MEDIUM",
                line=line_num,
                description=f"Potential privilege escalation: {desc}",
                snippet=snippet
            ))

    return issues


# === PentAGI Configuration Detectors ===

def detect_env_secrets(content: str, filename: str) -> List[Issue]:
    """Detect exposed secrets in .env files."""
    issues = []

    # Only run on .env files
    if not filename.endswith('.env') and '.env' not in filename:
        return issues

    patterns = [
        (r'(?:OPENAI|ANTHROPIC|DEEPSEEK)_API_KEY\s*=\s*["\']?([^"\'\s]+)', "LLM API Key exposed"),
        (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']?([^"\'\s]+)', "AWS Secret Key exposed"),
        (r'(?:DB|DATABASE)_PASSWORD\s*=\s*["\']?([^"\'\s]+)', "Database password exposed"),
        (r'(?:POSTGRES|MYSQL|MONGO).*PASSWORD\s*=\s*["\']?([^"\'\s]+)', "Database password exposed"),
        (r'SECRET_KEY\s*=\s*["\']?([^"\'\s]+)', "Secret key exposed"),
        (r'PRIVATE_KEY\s*=\s*["\']?([^"\'\s]+)', "Private key exposed"),
        (r'://[^:]+:([^@]+)@', "Password in connection string"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = find_line_number(content, match.start())
            # Don't include actual secret in snippet
            snippet = content[match.start():match.start()+30].split('=')[0] + "=***"
            issues.append(Issue(
                type="exposed_secret",
                severity="CRITICAL",
                line=line_num,
                description=desc,
                snippet=snippet
            ))

    return issues


def detect_docker_misconfig(content: str, filename: str) -> List[Issue]:
    """Detect insecure Docker configurations."""
    issues = []

    # Only run on docker-compose files
    if 'docker-compose' not in filename and 'dockerfile' not in filename.lower():
        return issues

    checks = [
        (r'privileged\s*:\s*true', "CRITICAL", "Container running in privileged mode"),
        (r'network_mode\s*:\s*["\']?host', "HIGH", "Container using host network mode"),
        (r'pid\s*:\s*["\']?host', "HIGH", "Container sharing host PID namespace"),
        (r'0\.0\.0\.0:\d+:\d+', "MEDIUM", "Port exposed on all interfaces"),
        (r'cap_add\s*:.*SYS_ADMIN', "CRITICAL", "Container has SYS_ADMIN capability"),
        (r'security_opt\s*:.*seccomp:unconfined', "HIGH", "Seccomp disabled"),
        (r'volumes\s*:.*\/var\/run\/docker\.sock', "CRITICAL", "Docker socket mounted in container"),
    ]

    for pattern, severity, desc in checks:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = find_line_number(content, match.start())
            snippet = match.group(0)
            issues.append(Issue(
                type="docker_misconfiguration",
                severity=severity,
                line=line_num,
                description=desc,
                snippet=snippet
            ))

    return issues


def run_dynamic_rules(code: str, filename: str, db: Optional[Session] = None) -> List[Issue]:
    """Run approved dynamic rules from the database."""
    issues = []

    if db is None:
        return issues

    try:
        from app.db.models import ApprovedRule

        active_rules = db.query(ApprovedRule).filter(ApprovedRule.is_active == True).all()

        for rule in active_rules:
            if not rule.pattern:
                continue

            try:
                for match in re.finditer(rule.pattern, code, re.IGNORECASE):
                    line_num = find_line_number(code, match.start())
                    snippet = code[match.start():match.start()+60].replace('\n', ' ')
                    issues.append(Issue(
                        type=rule.detector_type,
                        severity=rule.severity,
                        line=line_num,
                        description=f"{rule.description} (dynamic rule)",
                        snippet=snippet
                    ))
            except re.error:
                # Invalid regex pattern, skip this rule
                continue

    except Exception:
        # If we can't load rules, continue without them
        pass

    return issues


def run_all_static_detectors(code: str, filename: str, db: Optional[Session] = None) -> List[Issue]:
    """Run all static analysis detectors on code."""
    issues = []

    # OpenClaw detectors (for code files)
    issues.extend(detect_hardcoded_credentials(code, filename))
    issues.extend(detect_exfiltration(code, filename))
    issues.extend(detect_remote_code_execution(code, filename))
    issues.extend(detect_privilege_escalation(code, filename))

    # PentAGI detectors (for config files)
    issues.extend(detect_env_secrets(code, filename))
    issues.extend(detect_docker_misconfig(code, filename))

    # Dynamic rules from database
    issues.extend(run_dynamic_rules(code, filename, db))

    return issues
