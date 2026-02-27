import re
import httpx
from typing import Tuple


class GitHubFetcher:
    BASE_URL = "https://api.github.com"
    RAW_URL = "https://raw.githubusercontent.com"

    def __init__(self):
        from app.config import get_settings
        settings = get_settings()
        headers = {"Accept": "application/vnd.github.v3+json"}
        if settings.github_token:
            headers["Authorization"] = f"token {settings.github_token}"
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=30.0,
            follow_redirects=True
        )

    def parse_url(self, url: str) -> Tuple[str, str]:
        """Extract owner and repo from GitHub URL. Only github.com is allowed."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http") or parsed.netloc.lower() != "github.com":
            raise ValueError(f"Only github.com URLs are supported, got: {url}")
        pattern = r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
        match = re.match(pattern, parsed.path)
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {url}")
        return match.group(1), match.group(2)

    async def fetch_file_list(self, owner: str, repo: str, path: str = "") -> list:
        """Get list of files in repository."""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        response = await self.client.get(url)
        response.raise_for_status()
        return response.json()

    async def fetch_file_content(self, owner: str, repo: str, path: str, branch: str = "main") -> str:
        """Download raw file content."""
        url = f"{self.RAW_URL}/{owner}/{repo}/{branch}/{path}"
        response = await self.client.get(url)
        if response.status_code == 404:
            # Try master branch
            url = f"{self.RAW_URL}/{owner}/{repo}/master/{path}"
            response = await self.client.get(url)
        response.raise_for_status()
        return response.text

    async def fetch_skill_files(self, skill_url: str) -> dict[str, str]:
        """Fetch all relevant files from a skill repository."""
        owner, repo = self.parse_url(skill_url)
        files = await self.fetch_file_list(owner, repo)

        result = {}
        relevant_extensions = {".js", ".ts", ".py", ".json"}

        for item in files:
            if item["type"] == "file":
                ext = "." + item["name"].split(".")[-1] if "." in item["name"] else ""
                if ext in relevant_extensions or item["name"] in ["package.json", "requirements.txt"]:
                    try:
                        content = await self.fetch_file_content(owner, repo, item["path"])
                        result[item["path"]] = content
                    except Exception:
                        pass  # Skip files we can't fetch

        return result

    async def close(self):
        await self.client.aclose()
