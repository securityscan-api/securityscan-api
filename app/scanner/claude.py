"""Claude API fallback analyzer for when DeepSeek is unavailable."""

import json
import logging
from typing import List

import anthropic

from app.config import get_settings
from app.scanner.deepseek import ANALYSIS_PROMPT, MAX_CODE_SIZE
from app.scanner.detectors import Issue

logger = logging.getLogger(__name__)

CLAUDE_MODEL = "claude-haiku-4-5-20251001"


class ClaudeAnalyzer:
    """Uses Claude Haiku as fallback when DeepSeek is unavailable."""

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.anthropic_api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def analyze(self, code: str, filename: str) -> List[Issue]:
        """Analyze code using Claude Haiku for semantic security issues."""
        issues = []
        was_truncated = False

        if len(code) > MAX_CODE_SIZE:
            was_truncated = True
            code = code[:MAX_CODE_SIZE]
            logger.warning(f"Code truncated to {MAX_CODE_SIZE} chars for {filename}")

        prompt = ANALYSIS_PROMPT.format(code=code, filename=filename)

        try:
            message = await self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=1024,
                system="You are a security analyst. Respond only with valid JSON.",
                messages=[{"role": "user", "content": prompt}],
            )

            content = message.content[0].text.strip()

            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            result = json.loads(content)

            for item in result.get("issues", []):
                issues.append(Issue(
                    type=item.get("type", "unknown"),
                    severity=item.get("severity", "MEDIUM"),
                    line=item.get("line", 0),
                    description=item.get("description", "Issue detected by semantic analysis"),
                    snippet=""
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Claude JSON parse error for {filename}: {e}")
        except anthropic.APIError as e:
            logger.error(f"Claude API error for {filename}: {e}")
        except Exception as e:
            logger.error(f"Claude analysis error for {filename}: {e}")

        if was_truncated:
            issues.append(Issue(
                type="partial_analysis",
                severity="LOW",
                line=0,
                description=f"⚠️ Analysis partial: file exceeded {MAX_CODE_SIZE} characters.",
                snippet=""
            ))

        return issues

    async def close(self):
        if self._client is not None:
            await self._client.close()
