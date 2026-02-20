import time
import logging
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)
from typing import List, Optional
from sqlalchemy.orm import Session
from app.scanner.github import GitHubFetcher
from app.scanner.deepseek import DeepSeekAnalyzer
from app.scanner.claude import ClaudeAnalyzer
from app.scanner.detectors import Issue, run_all_static_detectors


SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5
}


@dataclass
class ScanResult:
    skill_url: str
    score: int
    recommendation: str
    issues: List[dict]
    scan_time_ms: int
    cached: bool = False

    def to_dict(self):
        return asdict(self)


class SkillScanner:
    def __init__(self):
        self.github = GitHubFetcher()
        self.deepseek = DeepSeekAnalyzer()
        self.claude = ClaudeAnalyzer()

    def calculate_score(self, issues: List[Issue]) -> int:
        """Calculate security score based on issues found."""
        score = 100
        for issue in issues:
            weight = SEVERITY_WEIGHTS.get(issue.severity, 5)
            score -= weight
        return max(0, score)

    def get_recommendation(self, score: int) -> str:
        """Get recommendation based on score."""
        if score >= 80:
            return "SAFE"
        elif score >= 40:
            return "CAUTION"
        else:
            return "DANGEROUS"

    async def scan(self, skill_url: str, db: Optional[Session] = None) -> ScanResult:
        """Perform full security scan on a skill/repo."""
        start_time = time.time()
        all_issues: List[Issue] = []

        try:
            # Fetch files from GitHub
            files = await self.github.fetch_skill_files(skill_url)

            # Run analysis on each file
            for filepath, content in files.items():
                # Static analysis (regex-based detectors + dynamic rules)
                static_issues = run_all_static_detectors(content, filepath, db)
                all_issues.extend(static_issues)

                # Semantic analysis: DeepSeek primary, Claude Haiku fallback
                semantic_issues = await self._semantic_analyze(content, filepath)
                all_issues.extend(semantic_issues)

        except Exception as e:
            # If we can't fetch the skill, add an error issue
            all_issues.append(Issue(
                type="fetch_error",
                severity="HIGH",
                line=0,
                description=f"Could not fetch skill: {str(e)}",
                snippet=""
            ))

        # Deduplicate issues (same type + line)
        seen = set()
        unique_issues = []
        for issue in all_issues:
            key = (issue.type, issue.line, issue.description[:50])
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)

        score = self.calculate_score(unique_issues)
        recommendation = self.get_recommendation(score)
        scan_time_ms = int((time.time() - start_time) * 1000)

        return ScanResult(
            skill_url=skill_url,
            score=score,
            recommendation=recommendation,
            issues=[i.to_dict() for i in unique_issues],
            scan_time_ms=scan_time_ms
        )

    async def _semantic_analyze(self, code: str, filename: str) -> List[Issue]:
        """Try DeepSeek first, fall back to Claude Haiku on failure."""
        try:
            issues = await self.deepseek.analyze(code, filename)
            # If DeepSeek returned results (even empty), use them
            return issues
        except Exception as e:
            logger.warning(f"DeepSeek failed for {filename}, trying Claude fallback: {e}")

        if self.claude.is_available():
            try:
                return await self.claude.analyze(code, filename)
            except Exception as e:
                logger.error(f"Claude fallback also failed for {filename}: {e}")

        return []

    async def close(self):
        await self.github.close()
        await self.deepseek.close()
        await self.claude.close()
