import pytest
from app.scanner.engine import SkillScanner, ScanResult
from app.scanner.detectors import Issue


def test_score_calculation():
    scanner = SkillScanner()

    # Test scoring with known issues
    issues = [
        Issue("test", "CRITICAL", 1, "test", "test"),
        Issue("test", "HIGH", 2, "test", "test"),
    ]
    score = scanner.calculate_score(issues)
    # 100 - 40 (CRITICAL) - 25 (HIGH) = 35
    assert score == 35


def test_score_minimum_is_zero():
    scanner = SkillScanner()

    # Many critical issues should floor at 0
    issues = [
        Issue("test", "CRITICAL", 1, "test", "test"),
        Issue("test", "CRITICAL", 2, "test", "test"),
        Issue("test", "CRITICAL", 3, "test", "test"),
    ]
    score = scanner.calculate_score(issues)
    assert score == 0


def test_recommendation_safe():
    scanner = SkillScanner()
    assert scanner.get_recommendation(85) == "SAFE"
    assert scanner.get_recommendation(80) == "SAFE"


def test_recommendation_caution():
    scanner = SkillScanner()
    assert scanner.get_recommendation(79) == "CAUTION"
    assert scanner.get_recommendation(40) == "CAUTION"


def test_recommendation_dangerous():
    scanner = SkillScanner()
    assert scanner.get_recommendation(39) == "DANGEROUS"
    assert scanner.get_recommendation(0) == "DANGEROUS"


@pytest.mark.asyncio
async def test_scan_returns_result():
    scanner = SkillScanner()
    result = await scanner.scan("https://github.com/octocat/Hello-World")

    assert isinstance(result, ScanResult)
    assert 0 <= result.score <= 100
    assert result.recommendation in ["SAFE", "CAUTION", "DANGEROUS"]
    assert isinstance(result.issues, list)
    assert result.scan_time_ms > 0
    assert result.skill_url == "https://github.com/octocat/Hello-World"

    await scanner.close()
