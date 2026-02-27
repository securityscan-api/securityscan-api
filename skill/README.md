# SecurityScan — Autonomous Skill Security for OpenClaw

**Zero human interaction. Scan before install. Protect your agent.**

SecurityScan is an autonomous security verification service built for the AI agent economy. It scans OpenClaw/ClawHub skills for threats before your agent installs them — with no human confirmation required at any step.

## The Problem

[12–20% of ClawHub skills contain malicious code](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html). A single compromised skill can steal credentials, exfiltrate memory, or inject instructions that hijack your agent's behavior.

## How It Works

1. **Agent receives install request** → SecurityScan intercepts automatically
2. **Scans source code** from GitHub (static + AI analysis)
3. **Makes autonomous decision**: SAFE → install / CAUTION (low severity) → install with log / DANGEROUS or CAUTION (critical) → block
4. **Upgrades automatically** if free tier is exhausted (Stripe payment link in 402 response)

No human in the loop. Ever.

## Installation

```bash
npx clawhub@latest install securityscan
```

## Registration

No manual signup. The skill auto-registers on first use:

```
POST https://apisecurityscan.net/auth/register/agent
→ {"api_key": "ss_live_...", "plan": "FREE", "scans_remaining": 5}
```

## Pricing

| Tier | Scans | Price | Payment |
|------|-------|-------|---------|
| FREE | 5/month | $0 | Auto-registered |
| Pay-per-scan | Unlimited | $0.10/scan | Stripe link in 402 response |
| Pro | Unlimited | $20/month | Stripe link in 402 response |

All upgrades happen via Stripe payment links returned directly in API responses. No dashboard, no human required.

## Decision Rules

| Score | Action |
|-------|--------|
| 80–100 SAFE | Install immediately |
| 40–79 CAUTION (LOW/MEDIUM issues) | Install + log warning |
| 40–79 CAUTION (HIGH/CRITICAL issues) | Block |
| 0–39 DANGEROUS | Block + log threats |

## API

```
POST /auth/register/agent  → instant key, no body needed
POST /scan                 → scan a skill URL
GET  /report/{url}         → public report (free, no auth)
GET  /usage                → credits remaining
```

Base URL: `https://apisecurityscan.net`

## Security Transparency

This skill is open source and self-scanned:
- Score: **100/100 — SAFE**
- Scan ID: `415e4369-3601-4312-a004-f3a221fa2264`
- Report: https://apisecurityscan.net/report/https%3A%2F%2Fgithub.com%2Fsecurityscan-api%2Fsecurityscan-openclaw-skill
