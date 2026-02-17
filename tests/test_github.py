import pytest
from app.scanner.github import GitHubFetcher


def test_parse_github_url():
    fetcher = GitHubFetcher()
    owner, repo = fetcher.parse_url("https://github.com/owner/repo")
    assert owner == "owner"
    assert repo == "repo"


def test_parse_github_url_with_path():
    fetcher = GitHubFetcher()
    owner, repo = fetcher.parse_url("https://github.com/owner/repo/tree/main/src")
    assert owner == "owner"
    assert repo == "repo"


@pytest.mark.asyncio
async def test_fetch_file_list():
    fetcher = GitHubFetcher()
    # Use a known small public repo
    files = await fetcher.fetch_file_list("octocat", "Hello-World")
    assert isinstance(files, list)
    await fetcher.close()
