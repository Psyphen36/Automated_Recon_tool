"""Base Recon class providing state, standard files and simple orchestration."""

from pathlib import Path
from typing import Dict, Any
import logging
from .utils import ensure_dir, which
from .config import DEFAULT_CONCURRENCY

log = logging.getLogger(__name__)


class Recon:
    def __init__(self, target: str, outdir: Path, concurrency: int = DEFAULT_CONCURRENCY, wordlist: Path = None, api_keys: Dict[str, str] = None):
        self.target = target.rstrip('/')
        self.outdir = Path(outdir)
        self.concurrency = concurrency
        self.wordlist = wordlist
        self.api_keys = api_keys or {}

        ensure_dir(self.outdir)

        # tools map will be populated by AdvancedRecon (it knows full REQUIRES)
        self.tools = {}

        base = self.outdir / self.target.replace('/', '_')
        self.files = {
            'allsubs': base.with_suffix('.allsubs.txt'),
            'resolved_hosts': base.with_suffix('.resolved.txt'),
            'alive': base.with_suffix('.alive.txt'),
            'endpoints_raw': base.with_suffix('.endpoints.txt'),
        }

        self.state: Dict[str, Any] = {
            'subdomains': [],
            'resolved_hosts': [],
            'alive': [],
            'endpoints_raw': [],
            'juicy': [],
        }

        log.info("Initialized Recon for %s -> %s", self.target, self.outdir)

    # Stubs to be overridden or extended
    def passive_enum(self):
        log.info("passive_enum: stub - no-op")

    def resolve_subs(self):
        log.info("resolve_subs: stub - no-op")

    def probe_hosts(self):
        log.info("probe_hosts: stub - no-op")

    def historical_endpoints(self):
        log.info("historical_endpoints: stub - no-op")

    def probe_endpoints(self):
        log.info("probe_endpoints: stub - no-op")

    def filter_juicy(self):
        log.info("filter_juicy: stub - no-op")

    def origin_ip_discovery(self):
        log.info("origin_ip_discovery: stub - no-op")

    def port_scan(self):
        log.info("port_scan: stub - no-op")

    def screenshots(self):
        log.info("screenshots: stub - no-op")

    def run_all(self, do_fuzz: bool = False, do_screens: bool = False):
        self.passive_enum()
        self.resolve_subs()
        self.probe_hosts()
        self.historical_endpoints()
        self.probe_endpoints()
        self.filter_juicy()
        if do_screens:
            self.screenshots()
