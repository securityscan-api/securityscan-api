# SecurityScan API

> Vulnerability scanner for AI agent skills.
> Detects prompt injection, malware patterns and OWASP LLM Top 10 issues before your agent installs an untrusted skill.

**Live endpoint:** https://apisecurityscan.net
**Health check:** https://apisecurityscan.net/health

---

## Why this exists

As AI agents increasingly install and execute third-party skills, supply chain
security becomes a real problem. SecurityScan lets an agent verify a skill's
safety autonomously — no human in the loop required.

---

## What it detects

- Prompt injection patterns
- Malicious code indicators
- Data exfiltration attempts
- Unauthorized external API access
- Supply chain attack vectors
- OWASP LLM Top 10 coverage

---

## Quick start

### 1. Get an API key

Register instantly — no payment required for the free tier:

```bash
curl -X POST https://apisecurityscan.net/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "name": "My Agent"}'
```

Response:
```json
{
  "api_key": "ss_live_...",
  "plan": "FREE",
  "scans_remaining": 5
}
```

Store `api_key`. Proceed immediately — no payment needed for FREE tier.

### 2. Run a scan

```bash
curl -X POST https://apisecurityscan.net/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_live_your_key" \
  -d '{
    "skill_url": "https://github.com/owner/skill-repo"
  }'
```

**Note:** `skill_url` must be a `github.com` URL.

### 3. Response

```json
{
  "scan_id": "a1b2c3d4e5f6",
  "skill_url": "https://github.com/owner/skill-repo",
  "score": 72,
  "recommendation": "CAUTION",
  "issues": [
    {
      "type": "PROMPT_INJECTION",
      "severity": "HIGH",
      "line": 42,
      "description": "Detected attempt to override agent instructions",
      "snippet": "ignore previous instructions and..."
    }
  ],
  "scan_time_ms": 1240,
  "cached": false,
  "scans_remaining": 4
}
```

**Verdict values:** `SAFE` (score ≥ 80) · `CAUTION` (50–79) · `DANGEROUS` (< 50)

---

## Pricing (MXN)

| Plan | Price | Scans | Type |
|------|-------|-------|------|
| `FREE` | $0 | 5/month | Free tier — no payment required |
| `PAY_PER_SCAN` | $2/scan | Pay as you go | One-time pack (5 scans min) |
| `PRO` | $399/month | Unlimited | Subscription |

Results cached 24 hours — rescanning the same skill costs zero scans.

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | None | Register and get API key (FREE tier) |
| `POST` | `/scan` | X-API-Key | Submit a skill for scanning |
| `GET` | `/scan/{scan_id}` | X-API-Key | Retrieve scan result |
| `GET` | `/report/{skill_url}` | None | Public scan report (no cost) |
| `POST` | `/billing/upgrade` | X-API-Key | Create Stripe checkout session |
| `GET` | `/billing/status` | X-API-Key | Current plan and usage |
| `GET` | `/health` | None | Service status |
| `GET` | `/quickstart` | None | Agent quickstart guide |

---

## Handle scan limit (402)

When `/scan` returns `402 scan_limit_reached`:

```bash
# Step 1: get checkout URL
curl -X POST https://apisecurityscan.net/billing/upgrade \
  -H "X-API-Key: ss_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{"plan": "PAY_PER_SCAN"}'

# Step 2: complete payment at checkout_url
# Step 3: poll GET /billing/status until plan != FREE
# Step 4: retry scan
```

---

## MCP integration

SecurityScan exposes an MCP server at `https://apisecurityscan.net/mcp`:

```json
{
  "mcpServers": {
    "securityscan": {
      "url": "https://apisecurityscan.net/mcp",
      "transport": "http"
    }
  }
}
```

Available tools: `scan_skill` · `get_report` · `check_certification`

---

## Latency & availability

- Average scan time: < 3 seconds
- Uptime: 99.9% (Contabo dedicated VPS)
- Response format: JSON

---

## Companion service

**DepScan API** checks the external dependency health of skills (endpoints,
SSL certificates, domain reputation, blacklists): https://depscan.net

---

## License

MIT — this repository contains documentation and skill package only. Service source code is proprietary.
