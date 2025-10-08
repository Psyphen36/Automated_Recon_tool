"""AdvancedFuzzer: async-friendly fuzzer that uses run_in_executor for blocking requests."""

from typing import List, Set
import asyncio
from recon.utils import make_request
import logging

log = logging.getLogger(__name__)


class AdvancedFuzzer:
    def __init__(self, base_urls: List[str], concurrency: int = 20):
        self.base_urls = base_urls
        self.concurrency = concurrency
        self.found_endpoints: Set[str] = set()

    async def fuzz_common_paths(self, wordlist: List[str], extensions: List[str] = None):
        if extensions is None:
            extensions = ["", ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".html"]

        sem = asyncio.Semaphore(self.concurrency)

        async def _check(url: str):
            async with sem:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(None, make_request, url)
                if resp and getattr(resp, "status_code", 0) in (200, 301, 302, 403, 401, 500):
                    self.found_endpoints.add(url)
                    log.info("Found %s -> %s", url, resp.status_code)

        tasks = []
        for base in self.base_urls:
            for p in wordlist:
                for ext in extensions:
                    url = base.rstrip("/") + "/" + p.lstrip("/") + ext
                    tasks.append(_check(url))

        await asyncio.gather(*tasks, return_exceptions=True)

    def fuzz_headers(self, base_url: str):
        headers_variations = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"Referer": base_url},
            {"Origin": base_url},
        ]

        for headers in headers_variations:
            try:
                resp = make_request(base_url, headers=headers)
                if resp and getattr(resp, "status_code", 0) in (200, 301, 302, 403):
                    log.info("Header bypass: %s with %s -> %s", base_url, headers, resp.status_code)
            except Exception:
                continue
