"""A small, same-domain crawler that discovers pages, links and forms."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

from bs4 import BeautifulSoup

from .http_client import HttpClient


@dataclass
class Form:
    """A discovered HTML form."""

    action: str                       # absolute URL the form submits to
    method: str                       # "get" or "post"
    inputs: dict = field(default_factory=dict)  # name -> default value


@dataclass
class Page:
    """A crawled page with the injectable surface we extracted from it."""

    url: str
    params: dict = field(default_factory=dict)  # query params: name -> value
    forms: list = field(default_factory=list)   # list[Form]


# Third-party / admin apps that are common on shared hosts (esp. XAMPP) but are
# never the target application. Crawling into them is slow and pure noise, so we
# don't follow links into them by default (the seed URL is always honored, and
# the directory/admin modules still flag their existence).
DEFAULT_SKIP_PATTERNS = (
    "phpmyadmin", "/pma/", "adminer", "webalizer", "/server-status",
    "/server-info", "/dashboard/docs/",
)


class Crawler:
    def __init__(self, client: HttpClient, max_pages: int = 50, same_domain: bool = True,
                 skip_patterns: tuple = DEFAULT_SKIP_PATTERNS):
        self.client = client
        self.max_pages = max_pages
        self.same_domain = same_domain
        self.skip_patterns = tuple(p.lower() for p in skip_patterns)

    def _in_scope(self, base_netloc: str, url: str) -> bool:
        if not self.same_domain:
            return True
        return urlparse(url).netloc == base_netloc

    def _is_skipped(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(pat in path for pat in self.skip_patterns)

    @staticmethod
    def _normalize(url: str) -> str:
        # Drop fragments so #anchors don't create duplicate pages.
        return urldefrag(url)[0]

    def _parse_forms(self, page_url: str, soup: BeautifulSoup) -> list:
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            method = (form.get("method") or "get").lower()
            inputs: dict = {}
            for field_el in form.find_all(["input", "textarea", "select"]):
                name = field_el.get("name")
                if not name:
                    continue
                inputs[name] = field_el.get("value", "")
            forms.append(
                Form(action=urljoin(page_url, action), method=method, inputs=inputs)
            )
        return forms

    def crawl(self, start_url: str) -> list:
        """BFS crawl from start_url, returning a list of Page objects.

        Each BFS level's frontier is fetched concurrently (via the client's
        worker pool), which is much faster than one request at a time while
        preserving breadth-first ordering and the page limit.
        """
        base_netloc = urlparse(start_url).netloc
        start = self._normalize(start_url)
        seen: set = {start}
        pages: list = []
        frontier: list = [start]

        while frontier and len(pages) < self.max_pages:
            # Never fetch more than the remaining page budget.
            capacity = self.max_pages - len(pages)
            batch, frontier = frontier[:capacity], frontier[capacity:]
            responses = self.client.get_many(batch)
            next_frontier: list = []

            for url, resp in zip(batch, responses):
                if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                    # Still record query params for non-HTML so they can be probed.
                    params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
                    if params:
                        pages.append(Page(url=url, params=params))
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
                forms = self._parse_forms(url, soup)
                pages.append(Page(url=url, params=params, forms=forms))

                for a in soup.find_all("a", href=True):
                    link = self._normalize(urljoin(url, a["href"]))
                    if not link.startswith(("http://", "https://")):
                        continue
                    if (link not in seen and self._in_scope(base_netloc, link)
                            and not self._is_skipped(link)):
                        seen.add(link)
                        next_frontier.append(link)

            frontier.extend(next_frontier)

        return pages
