import json
import httpx
from typing import List
from app.config import get_settings
from app.scanner.detectors import Issue


ANALYSIS_PROMPT = '''Analyze this code/configuration for security vulnerabilities.

Context: This is from an AI agent skill or pentesting tool configuration.

Look specifically for:
1. PROMPT INJECTION: Hidden instructions in comments or strings that manipulate AI agents (e.g., "ignore previous instructions", "SYSTEM:", "you are now")
2. DATA EXFILTRATION: Code that sends sensitive data (memory, credentials, tokens) to external servers
3. MALICIOUS DEPENDENCIES: Suspicious package imports or obfuscated code
4. INSECURE CONFIGURATIONS: For Docker/configs - privileged mode, exposed ports, mounted secrets

Respond ONLY with valid JSON in this exact format:
{{
    "issues": [
        {{
            "type": "prompt_injection|exfiltration|malicious_dependency|insecure_config",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "line": <line_number_or_0>,
            "description": "<what the issue is and why it's dangerous>"
        }}
    ]
}}

If no security issues found, respond with: {{"issues": []}}

File being analyzed: {filename}

Code/Config:
```
{code}
```'''


class DeepSeekAnalyzer:
    API_URL = "https://api.deepseek.com/v1/chat/completions"

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.deepseek_api_key
        self.client = httpx.AsyncClient(timeout=60.0)

    async def analyze(self, code: str, filename: str) -> List[Issue]:
        """Analyze code using DeepSeek for semantic security issues."""
        # Limit code size to avoid token limits
        code_truncated = code[:8000] if len(code) > 8000 else code
        prompt = ANALYSIS_PROMPT.format(code=code_truncated, filename=filename)

        try:
            response = await self.client.post(
                self.API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "You are a security analyst. Respond only with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 1000
                }
            )
            response.raise_for_status()

            data = response.json()
            content = data["choices"][0]["message"]["content"]

            # Clean up response (remove markdown code blocks if present)
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            # Parse JSON response
            result = json.loads(content)
            issues = []

            for item in result.get("issues", []):
                issues.append(Issue(
                    type=item.get("type", "unknown"),
                    severity=item.get("severity", "MEDIUM"),
                    line=item.get("line", 0),
                    description=item.get("description", "Issue detected by semantic analysis"),
                    snippet=""
                ))

            return issues

        except json.JSONDecodeError as e:
            # If DeepSeek doesn't return valid JSON, return empty
            print(f"DeepSeek JSON parse error: {e}")
            return []
        except httpx.HTTPStatusError as e:
            print(f"DeepSeek HTTP error: {e}")
            return []
        except Exception as e:
            # Log error but don't fail scan
            print(f"DeepSeek analysis error: {e}")
            return []

    async def close(self):
        await self.client.aclose()
