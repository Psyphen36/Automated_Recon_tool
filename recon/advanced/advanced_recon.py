"""AdvancedRecon implements the advanced pipeline and uses all tools listed in config.REQUIRES."""

from ..recon_base import Recon
from ..utils import make_request, run, which, ensure_dir
from ..config import FUZZING_WORDLISTS, REQUIRES, DATE, SUBPROCESS_TIMEOUT
from .fuzzer import AdvancedFuzzer
from pathlib import Path
import asyncio
import logging
import tldextract
import json
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# For fallback DNS resolution
import concurrent.futures
import dns.resolver
import socket

log = logging.getLogger(__name__)


class AdvancedRecon(Recon):
    def __init__(self, target: str, outdir: Path, concurrency: int = 50, wordlist: Path = None, api_keys: dict = None):
        super().__init__(target, outdir, concurrency, wordlist, api_keys)

        # Detect all required tools and store their paths
        self.tools = {name: which(cmd) for name, cmd in REQUIRES.items()}

        base = self.outdir / self.target.replace("/", "_")
        self.advanced_files = {
            "permutations": base.with_suffix(".permutations.txt"),
            "cloud_assets": base.with_suffix(".cloud_assets.txt"),
            "js_endpoints": base.with_suffix(".js_endpoints.txt"),
            "hidden_params": base.with_suffix(".hidden_params.txt"),
            "cors_misconfig": base.with_suffix(".cors.txt"),
            "takeovers": base.with_suffix(".takeovers.txt"),
            "nuclei_results": base.with_suffix(".nuclei.txt"),
            "graphql": base.with_suffix(".graphql.txt"),
            "websockets": base.with_suffix(".websockets.txt"),
        }

        # Merge into main files dict
        self.files.update(self.advanced_files)

        # Ensure outdir exists
        ensure_dir(self.outdir)

    # ------------------ Permutations & Subdomain ----------------------------
    def generate_permutations(self) -> set:
        ext = tldextract.extract(self.target)
        if not ext.suffix:
            base = self.target
        else:
            base = f"{ext.domain}.{ext.suffix}"

        prefixes = [
            "api", "admin", "beta", "staging", "dev", "test", "internal", "secure",
            "vpn", "mail", "webmail", "ftp", "cpanel", "whm", "webdisk", "ns1", "ns2",
            "mx", "imap", "pop", "smtp", "autodiscover", "owa", "exchange", "lync",
            "sharepoint", "portal", "apps", "app", "mobile", "m", "cdn", "media",
            "static", "assets", "img", "images", "js", "css", "upload", "download",
            "backup", "old", "new", "temp", "tmp", "demo", "sandbox", "lab",
            "aws", "azure", "gcp", "cloud", "s3", "storage", "bucket", "blob",
            "k8s", "kubernetes", "docker", "registry", "git", "svn", "jenkins",
            "us", "eu", "uk", "de", "fr", "jp", "sg", "au", "ca", "in", "br",
            "01", "02", "1", "2", "3", "a", "b", "c", "www1", "www2"
        ]

        permutations = set()
        for p in prefixes:
            permutations.update({
                f"{p}.{base}",
                f"{p}-{base}",
                f"{base}-{p}",
                f"{p}{base}",
                f"{base}{p}",
            })

        self.advanced_files["permutations"].write_text("\n".join(sorted(permutations)))
        return permutations
    
    def advanced_subdomain_enum(self):
        log.info("[*] Starting advanced subdomain enumeration")
        permutations = self.generate_permutations()

        all_targets = set(permutations)
        if self.files["allsubs"].exists():
            all_targets.update(self.files["allsubs"].read_text().splitlines())

        # Use shuffledns if available
        if self.tools.get("shuffledns") and self.wordlist and self.wordlist.exists():
            log.info("  - Performing DNS brute force with shuffledns")
            tmp_input = self.outdir / f"dns_brute_input_{DATE}.txt"
            tmp_input.write_text("\n".join(sorted(all_targets)))

            cmd = [
                self.tools["shuffledns"],
                "-d", self.target,
                "-list", str(tmp_input),
                "-r", "/usr/share/seclists/Discovery/DNS/resolvers.txt",
                "-o", str(self.advanced_files["permutations"]) + ".resolved"
            ]
            result = run(cmd, timeout=SUBPROCESS_TIMEOUT)
            if result and getattr(result, "stdout", None):
                outpath = Path(str(self.advanced_files["permutations"]) + ".resolved")
                if outpath.exists():
                    new_subs = set(outpath.read_text().splitlines())
                    all_targets.update(new_subs)
                else:
                    all_targets.update(result.stdout.splitlines())

        sorted_subs = sorted(all_targets)
        self.files["allsubs"].write_text("\n".join(sorted_subs))
        log.info("[*] Advanced enumeration found %d total subdomains", len(sorted_subs))
    
        # ------------------ Cloud Asset Discovery --------------------------------
    def cloud_asset_discovery(self):
        log.info("[*] Discovering cloud assets")
        cloud_assets = set()

        ext = tldextract.extract(self.target)
        domain = ext.domain if ext.domain else self.target.replace(".", "-")
        possible_buckets = [
            f"{domain}",
            f"{domain}-assets",
            f"{domain}-media",
            f"{domain}-storage",
            f"{domain}-backup",
            f"{domain}-prod",
            f"{domain}-staging",
            self.target.replace(".", "-"),
        ]

        cloud_patterns = [
            "https://{bucket}.s3.amazonaws.com",
            "https://s3.amazonaws.com/{bucket}",
            "https://{bucket}.s3.{region}.amazonaws.com",
            "https://storage.googleapis.com/{bucket}",
            "https://{bucket}.storage.googleapis.com",
            "https://{bucket}.blob.core.windows.net",
        ]

        regions = ["us-east-1", "eu-west-1", "ap-southeast-1"]
        for bucket in possible_buckets:
            for pattern in cloud_patterns:
                if "{region}" in pattern:
                    for region in regions:
                        test_url = pattern.format(bucket=bucket, region=region)
                        resp = make_request(test_url, method="HEAD")
                        if resp and resp.status_code in (200, 403, 301):
                            cloud_assets.add(test_url)
                            log.info("[+] Cloud asset found: %s [%s]", test_url, resp.status_code)
                else:
                    test_url = pattern.format(bucket=bucket)
                    resp = make_request(test_url, method="HEAD")
                    if resp and resp.status_code in (200, 403, 301):
                        cloud_assets.add(test_url)
                        log.info("[+] Cloud asset found: %s [%s]", test_url, resp.status_code)

        if cloud_assets:
            self.advanced_files["cloud_assets"].write_text("\n".join(sorted(cloud_assets)))
            log.info("[*] Found %d cloud assets", len(cloud_assets))

    # ------------------ Passive enumeration (subfinder / assetfinder / amass)
    def passive_enum(self):
        """
        Run passive enumeration tools (subfinder, assetfinder, amass).
        Results are merged, deduplicated, written to files['allsubs'] and state['subdomains'].
        """
        log.info("[*] Running passive enumeration (subfinder / assetfinder / amass)")

        discovered = set()

        # subfinder - prefers JSON or silent stdout; many installs support -silent
        if self.tools.get("subfinder"):
            cmd = [self.tools["subfinder"], "-d", self.target, "-silent"]
            log.info("  - Running subfinder: %s", " ".join(cmd))
            res = run(cmd, timeout=180)
            if res and getattr(res, "stdout", None):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line:
                        discovered.add(line)

        # assetfinder - many versions support -subs-only or just print domains
        if self.tools.get("assetfinder"):
            cmd = [self.tools["assetfinder"], "--subs-only", self.target] if shutil_works(self.tools["assetfinder"]) else [self.tools["assetfinder"], self.target]
            # assetfinder usage varies; attempt common flags but fallback to plain invocation
            try:
                log.info("  - Running assetfinder: %s", " ".join(cmd))
                res = run(cmd, timeout=120)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if line:
                            discovered.add(line)
            except Exception:
                # fallback plain
                cmd = [self.tools["assetfinder"], self.target]
                res = run(cmd, timeout=120)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if line:
                            discovered.add(line)

        # amass - passive enumeration with -passive flag; if JSON output supported we could parse it.
        if self.tools.get("amass"):
            cmd = [self.tools["amass"], "enum", "-passive", "-d", self.target, "-norecursive"]
            # Some amass builds require -o or -src; many print to stdout when -passive used
            log.info("  - Running amass: %s", " ".join(cmd))
            res = run(cmd, timeout=300)
            if res and getattr(res, "stdout", None):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # amass sometimes prints "FOUND:" or json; try to capture plain hostnames
                        parts = re.findall(r"([A-Za-z0-9\-\_\.]+\.[A-Za-z]{2,})", line)
                        for p in parts:
                            discovered.add(p)

        # Also include existing allsubs file if present
        if self.files["allsubs"].exists():
            existing = {l.strip() for l in self.files["allsubs"].read_text().splitlines() if l.strip()}
            discovered.update(existing)

        # Normalize and sort
        discovered = {d.rstrip(".") for d in discovered if d}
        sorted_subs = sorted(discovered)

        # Persist
        self.files["allsubs"].write_text("\n".join(sorted_subs))
        self.state["subdomains"] = sorted_subs

        log.info("[*] passive_enum: discovered %d unique subdomains", len(sorted_subs))

    # ------------------ Resolve subdomains (dnsx or python fallback) -----------
    def resolve_subs(self):
        """
        Resolve subdomains to IPs. Prefer dnsx if available (fast), otherwise use concurrent dnspython lookups.
        Writes resolved hosts to files['resolved_hosts'] and state['resolved_hosts'].
        """
        log.info("[*] Resolving subdomains to IPs")

        subs = []
        if self.files["allsubs"].exists():
            subs = [l.strip() for l in self.files["allsubs"].read_text().splitlines() if l.strip()]
        else:
            subs = list(self.state.get("subdomains", []))

        subs = sorted(set(subs))
        resolved = {}  # domain -> set(ips)

        # Use dnsx if available
        if self.tools.get("dnsx"):
            log.info("  - Using dnsx for bulk resolution")
            tmp_in = self.outdir / f"dnsx_in_{DATE}.txt"
            tmp_out = self.outdir / f"dnsx_out_{DATE}.txt"
            tmp_in.write_text("\n".join(subs))
            cmd = [self.tools["dnsx"], "-l", str(tmp_in), "-a", "-resp", "-silent", "-o", str(tmp_out)]
            res = run(cmd, timeout=SUBPROCESS_TIMEOUT)
            # dnsx outputs lines like: host A ip (format may vary)
            if tmp_out.exists():
                for line in tmp_out.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # best-effort parsing: extract domain and IP(s)
                    parts = line.split()
                    # try replace trailing punctuation
                    domain = parts[0].strip()
                    ips = [p for p in parts if _looks_like_ip(p)]
                    if ips:
                        resolved.setdefault(domain, set()).update(ips)
            elif res and getattr(res, "stdout", None):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    domain = parts[0].strip()
                    ips = [p for p in parts if _looks_like_ip(p)]
                    if ips:
                        resolved.setdefault(domain, set()).update(ips)

        # Fallback: concurrent dnspython A lookups
        if not resolved:
            log.info("  - No dnsx results or dnsx unavailable; falling back to dnspython lookups")
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5.0
            resolver.timeout = 3.0

            def _resolve(name):
                ips = set()
                try:
                    answers = resolver.resolve(name, "A")
                    for r in answers:
                        ips.add(r.to_text())
                except Exception:
                    # try CNAME/AAAA or ignore
                    try:
                        answers6 = resolver.resolve(name, "AAAA")
                        for r in answers6:
                            ips.add(r.to_text())
                    except Exception:
                        pass
                return name, ips

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(subs) or 1)) as ex:
                futures = {ex.submit(_resolve, s): s for s in subs}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        name, ips = fut.result()
                        if ips:
                            resolved.setdefault(name, set()).update(ips)
                    except Exception:
                        continue

        # Build resolved_hosts list (host -> ip) and persist
        resolved_lines = []
        for host, ips in resolved.items():
            for ip in ips:
                resolved_lines.append(f"{host} {ip}")

        # Also write list of just hosts for tools that expect a file with hosts
        resolved_host_only = sorted({host for host in resolved.keys()})
        if resolved_lines:
            self.files["resolved_hosts"].write_text("\n".join(sorted(resolved_lines)))
            log.info("[*] Resolved %d hosts", len(resolved_lines))

        # Update state
        self.state["resolved_hosts"] = resolved_host_only

    # ------------------ Probe hosts (httpx preferred, fallback to requests) ----
    def probe_hosts(self):
        """
        Probe resolved hosts for alive HTTP endpoints. Uses httpx if present (fast), otherwise
        does threaded requests to try http/https on each host. Writes alive hosts to files['alive'] and state['alive'].
        """
        log.info("[*] Probing hosts for HTTP(S) responsiveness")

        hosts = []
        if self.files["resolved_hosts"].exists():
            # file contains lines like "host ip" or just "host"
            raw = [l.strip() for l in self.files["resolved_hosts"].read_text().splitlines() if l.strip()]
            for line in raw:
                host = line.split()[0]
                hosts.append(host)
        else:
            hosts = list(self.state.get("resolved_hosts", []))

        hosts = sorted(set(hosts))
        alive = set()

        # If httpx tool is available, use it in bulk
        if self.tools.get("httpx"):
            log.info("  - Using httpx for probing")
            tmp_in = self.outdir / f"httpx_in_{DATE}.txt"
            tmp_out = self.outdir / f"httpx_out_{DATE}.txt"
            tmp_in.write_text("\n".join(hosts))
            cmd = [self.tools["httpx"], "-l", str(tmp_in), "-silent", "-status-code", "-o", str(tmp_out)]
            res = run(cmd, timeout=300)
            # httpx output may need parsing; check outfile
            if tmp_out.exists():
                for line in tmp_out.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    # lines often: <url> <status> ...
                    url = parts[0]
                    alive.add(url.rstrip("/"))
            elif res and getattr(res, "stdout", None):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if parts:
                        alive.add(parts[0].rstrip("/"))

        # Fallback: threaded requests checks (try https then http)
        if not alive:
            log.info("  - httpx not available or returned nothing; using threaded HTTP checks")
            def _check(host):
                tried = []
                for scheme in ("https://", "http://"):
                    url = scheme + host
                    try:
                        r = make_request(url, timeout=8, method="GET")
                        if r and getattr(r, "status_code", 0) in (200, 301, 302, 403, 401):
                            return url.rstrip("/")
                    except Exception:
                        continue
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(40, len(hosts) or 1)) as ex:
                futures = {ex.submit(_check, h): h for h in hosts}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        url = fut.result()
                        if url:
                            alive.add(url)
                    except Exception:
                        continue

        if alive:
            sorted_alive = sorted(alive)
            self.files["alive"].write_text("\n".join(sorted_alive))
            self.state["alive"] = sorted_alive
            log.info("[*] Probing complete: %d alive hosts", len(sorted_alive))
        else:
            log.info("[*] Probing complete: no alive hosts discovered")

    # ------------------ JavaScript Analysis --------------------------------
    def javascript_analysis(self):
        log.info("[*] Analyzing JavaScript files for hidden endpoints")
        js_endpoints = set()
        alive_hosts = self.state.get("alive", [])

        for host in alive_hosts:
            try:
                response = make_request(host)
                if not response:
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                js_links = []

                for script in soup.find_all("script", src=True):
                    js_url = urljoin(host, script["src"])
                    js_links.append(js_url)

                # check common JS directory listings
                common_js_paths = ["/static/js/", "/js/", "/assets/js/", "/scripts/"]
                for path in common_js_paths:
                    test_url = urljoin(host, path)
                    response_dir = make_request(test_url)
                    if response_dir and response_dir.status_code == 200:
                        js_files = re.findall(r'href="([^"]+\.js)"', response_dir.text)
                        for js_file in js_files:
                            js_links.append(urljoin(test_url, js_file))

                # analyze js files
                for js_url in set(js_links):
                    js_response = make_request(js_url)
                    if js_response and js_response.text:
                        endpoints_in_js = self._extract_from_js(js_response.text, host)
                        js_endpoints.update(endpoints_in_js)
                        secrets = self._find_secrets_in_js(js_response.text)
                        if secrets:
                            log.warning("Potential secrets found in %s:", js_url)
                            for secret in secrets:
                                log.warning("    %s", secret)
            except Exception as e:
                log.debug("    Error analyzing %s: %s", host, e)

        if js_endpoints:
            self.advanced_files["js_endpoints"].write_text("\n".join(sorted(js_endpoints)))
            log.info("[*] Found %d endpoints in JavaScript files", len(js_endpoints))

    # ------------------ Advanced Endpoint Discovery -------------------------
    def advanced_endpoint_discovery(self):
        log.info("[*] Starting advanced endpoint discovery")
        all_endpoints = set()
        alive_hosts = self.state.get("alive", [])

        # katana
        if self.tools.get("katana"):
            log.info("  - Crawling with katana")
            for host in alive_hosts:
                cmd = [self.tools["katana"], "-u", host, "-silent"]
                result = run(cmd, timeout=300)
                if result and getattr(result, "stdout", None):
                    all_endpoints.update(result.stdout.splitlines())

        # gospider
        if self.tools.get("gospider"):
            log.info("  - Crawling with gospider")
            for host in alive_hosts:
                cmd = [self.tools["gospider"], "-s", host, "-t", str(self.concurrency), "-d", "3", "--json"]
                result = run(cmd, timeout=300)
                if result and result.stdout:
                    for line in result.stdout.splitlines():
                        try:
                            data = json.loads(line)
                            if "url" in data:
                                all_endpoints.add(data["url"])
                        except Exception:
                            continue

        # gau & waybackurls
        if self.tools.get("gau"):
            log.info("  - Gathering with gau")
            for host in alive_hosts:
                cmd = [self.tools["gau"], host]
                result = run(cmd, timeout=120)
                if result and result.stdout:
                    all_endpoints.update(result.stdout.splitlines())

        if self.tools.get("waybackurls"):
            log.info("  - Gathering with waybackurls")
            for host in alive_hosts:
                cmd = [self.tools["waybackurls"], host]
                result = run(cmd, timeout=120)
                if result and result.stdout:
                    all_endpoints.update(result.stdout.splitlines())

        # parameter discovery (simple)
        self._parameter_discovery(alive_hosts)

        if all_endpoints:
            current_endpoints = set(self.state.get("endpoints_raw", []))
            current_endpoints.update(all_endpoints)
            sorted_endpoints = sorted(current_endpoints)
            self.files["endpoints_raw"].write_text("\n".join(sorted_endpoints))
            log.info("[*] Advanced discovery found %d new endpoints", len(all_endpoints))

    def _parameter_discovery(self, hosts):
        log.info("  - Discovering hidden parameters")
        common_params = [
            "debug", "test", "admin", "api", "token", "key", "auth", "password",
            "callback", "jsonp", "redirect", "url", "return", "next", "ref",
            "id", "user", "account", "email", "phone", "code", "verify"
        ]
        found_params = set()
        for host in hosts:
            for param in common_params:
                test_url = f"{host}?{param}=test"
                response = make_request(test_url)
                if response and response.status_code == 200:
                    baseline = make_request(host)
                    if baseline and baseline.text != response.text:
                        found_params.add(f"{host}?{param}=*")
                        log.info("[+] Parameter found: %s", test_url)
        if found_params:
            self.advanced_files["hidden_params"].write_text("\n".join(sorted(found_params)))

    # ------------------ Security Vulnerability Scanning ---------------------
    def security_scanning(self):
        log.info("[*] Starting security vulnerability scanning")
        # nuclei
        if self.tools.get("nuclei"):
            log.info("  - Running nuclei vulnerability scanner")
            cmd = [
                self.tools["nuclei"],
                "-list", str(self.files["alive"]),
                "-t", "/home/user/nuclei-templates/",  # adjust path
                "-o", str(self.advanced_files["nuclei_results"]),
                "-severity", "low,medium,high,critical",
                "-rate-limit", "50"
            ]
            run(cmd, timeout=900)
        # cors testing
        self._cors_testing()
        # takeover check
        self._subdomain_takeover_check()

    def _cors_testing(self):
        log.info("  - Testing for CORS misconfigurations")
        cors_vulnerable = []
        origins_to_test = [
            "https://evil.com",
            "http://localhost",
            "null",
            "https://attacker.com",
            "https://" + self.target
        ]
        for endpoint in self.state.get("endpoints_alive", []):
            for origin in origins_to_test:
                try:
                    headers = {"Origin": origin}
                    response = make_request(endpoint, method="OPTIONS", headers=headers)
                    if response:
                        cors_headers = response.headers.get("Access-Control-Allow-Origin", "")
                        if origin in cors_headers or cors_headers == "*":
                            cors_vulnerable.append(f"{endpoint} - {origin}")
                            log.warning("[!] CORS misconfiguration: %s allows %s", endpoint, origin)
                except Exception:
                    continue
        if cors_vulnerable:
            self.advanced_files["cors_misconfig"].write_text("\n".join(cors_vulnerable))

    def _subdomain_takeover_check(self):
        log.info("  - Checking for subdomain takeovers")
        if not self.tools.get("subjack"):
            log.debug("subjack not available; skipping takeover checks")
            return
        cmd = [
            self.tools["subjack"],
            "-w", str(self.files["resolved_hosts"]),
            "-t", "100",
            "-o", str(self.advanced_files["takeovers"])
        ]
        run(cmd, timeout=300)

    # ------------------ GraphQL and WebSocket Discovery ---------------------
    def advanced_protocol_discovery(self):
        log.info("[*] Discovering advanced protocol endpoints")
        graphql_endpoints = set()
        websocket_endpoints = set()
        common_graphql_paths = [
            "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
            "/query", "/gql", "/graph", "/graphql-api", "/graphql/console"
        ]
        common_ws_paths = [
            "/ws", "/websocket", "/socket.io", "/wss", "/websockets",
            "/live", "/realtime", "/events", "/notifications"
        ]
        for host in self.state.get("alive", []):
            # GraphQL discovery
            for path in common_graphql_paths:
                test_url = urljoin(host, path)
                response = make_request(test_url, method="POST", json={"query": "{__schema{types{name}}}"})
                if response and response.status_code == 200:
                    if "application/json" in response.headers.get("content-type", "").lower():
                        try:
                            data = response.json()
                            if "data" in data and "__schema" in str(data):
                                graphql_endpoints.add(test_url)
                                log.info("[+] GraphQL endpoint: %s", test_url)
                        except Exception:
                            pass

            # WebSocket discovery (heuristic)
            for path in common_ws_paths:
                test_url = urljoin(host, path)
                if test_url.startswith("http:"):
                    ws_url = test_url.replace("http:", "ws:")
                else:
                    ws_url = test_url.replace("https:", "wss:")
                websocket_endpoints.add(ws_url)

        if graphql_endpoints:
            self.advanced_files["graphql"].write_text("\n".join(sorted(graphql_endpoints)))
        if websocket_endpoints:
            self.advanced_files["websockets"].write_text("\n".join(sorted(websocket_endpoints)))

    # ------------------ Advanced Fuzzing ------------------------------------
    def advanced_fuzzing(self):
        if not self.wordlist or not Path(self.wordlist).exists():
            log.warning("[!] No wordlist provided for advanced fuzzing")
            return

        log.info("[*] Starting advanced fuzzing")
        fuzzer = AdvancedFuzzer(self.state.get("alive", []), self.concurrency)

        all_wordlists = []
        for category, words in FUZZING_WORDLISTS.items():
            all_wordlists.extend(words)
        # run async fuzzing
        asyncio.run(fuzzer.fuzz_common_paths(all_wordlists))
        # header fuzzing
        for host in self.state.get("alive", []):
            fuzzer.fuzz_headers(host)

        if fuzzer.found_endpoints:
            current = set(self.state.get("endpoints_raw", []))
            current.update(fuzzer.found_endpoints)
            sorted_endpoints = sorted(current)
            self.files["endpoints_raw"].write_text("\n".join(sorted_endpoints))
            log.info("[*] Advanced fuzzing found %d new endpoints", len(fuzzer.found_endpoints))

    def historical_endpoints(self):
        """
        Collect historical/archived endpoints using gau, waybackurls and optionally katana/gospider.
        Results are merged into self.files['endpoints_raw'] and self.state['endpoints_raw'].
        """
        import os
        from urllib.parse import urlparse, urljoin

        log.info("[*] Gathering historical endpoints (gau, waybackurls, katana/gospider)")

        endpoints = set(self.state.get("endpoints_raw", []))

        # Use alive hosts as targets if available, otherwise fallback to main target
        targets = self.state.get("alive") or [self.target]

        def _norm(u, base=None):
            if not u:
                return None
            u = u.strip()
            # skip data:, javascript:, mailto:
            if u.startswith("data:") or u.startswith("javascript:") or u.startswith("mailto:"):
                return None
            if u.startswith("//"):
                u = "https:" + u
            p = urlparse(u)
            if p.scheme:
                return u
            # if path-only, join with base
            if u.startswith("/") and base:
                return urljoin(base, u)
            # if just host/path without scheme, assume https
            return "https://" + u if not p.scheme else u

        # gau
        if self.tools.get("gau"):
            log.info("  - running gau")
            for t in targets:
                cmd = [self.tools["gau"], t]
                res = run(cmd, timeout=120)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        n = _norm(line, base=t)
                        if n:
                            endpoints.add(n)

        # waybackurls
        if self.tools.get("waybackurls"):
            log.info("  - running waybackurls")
            for t in targets:
                cmd = [self.tools["waybackurls"], t]
                res = run(cmd, timeout=120)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        n = _norm(line, base=t)
                        if n:
                            endpoints.add(n)

        # katana/gospider (crawl) - they may produce duplicates but are useful
        if self.tools.get("katana"):
            log.info("  - crawling with katana (historical)")
            for t in targets:
                cmd = [self.tools["katana"], "-u", t, "-silent"]
                res = run(cmd, timeout=180)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        n = _norm(line, base=t)
                        if n:
                            endpoints.add(n)

        if self.tools.get("gospider"):
            log.info("  - crawling with gospider (historical)")
            for t in targets:
                cmd = [self.tools["gospider"], "-s", t, "-t", str(self.concurrency), "-d", "2", "--json"]
                res = run(cmd, timeout=240)
                if res and getattr(res, "stdout", None):
                    for line in res.stdout.splitlines():
                        try:
                            obj = json.loads(line)
                            url = obj.get("url") or obj.get("start_url")
                            n = _norm(url, base=t)
                            if n:
                                endpoints.add(n)
                        except Exception:
                            continue

        # persist merged endpoints
        if endpoints:
            merged = sorted(endpoints)
            self.files["endpoints_raw"].write_text("\n".join(merged))
            self.state["endpoints_raw"] = merged
            log.info("[*] historical_endpoints: collected %d endpoints", len(merged))
        else:
            log.info("[*] historical_endpoints: no endpoints discovered")

    def probe_endpoints(self):
        """
        Probe endpoints (from endpoints_raw) to find alive endpoints.
        Prefer httpx if available for bulk probing; otherwise use threaded make_request fallback.
        Writes alive endpoints to a per-target file and updates state['endpoints_alive'].
        """
        import concurrent.futures
        from urllib.parse import urlparse

        log.info("[*] Probing collected endpoints for liveness")

        # read endpoints
        endpoints = []
        if self.files.get("endpoints_raw") and self.files["endpoints_raw"].exists():
            endpoints = [l.strip() for l in self.files["endpoints_raw"].read_text().splitlines() if l.strip()]
        else:
            endpoints = list(self.state.get("endpoints_raw", []))

        endpoints = sorted(set(endpoints))
        if not endpoints:
            log.info("  - No endpoints to probe")
            self.state["endpoints_alive"] = []
            return

        alive = set()

        # Preferred: httpx
        if self.tools.get("httpx"):
            log.info("  - Probing with httpx")
            tmp_in = self.outdir / f"endpoints_httpx_in_{DATE}.txt"
            tmp_out = self.outdir / f"endpoints_httpx_out_{DATE}.txt"
            tmp_in.write_text("\n".join(endpoints))
            cmd = [self.tools["httpx"], "-l", str(tmp_in), "-silent", "-status-code", "-o", str(tmp_out)]
            res = run(cmd, timeout=300)
            if tmp_out.exists():
                for line in tmp_out.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # httpx often prints: <url> <status> ...
                    parts = line.split()
                    alive.add(parts[0].rstrip("/"))
            elif res and getattr(res, "stdout", None):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    alive.add(parts[0].rstrip("/"))

        # Fallback threaded checks using make_request
        if not alive:
            log.info("  - httpx not available or returned nothing; using threaded requests")
            def _check(url):
                try:
                    # First try HEAD (less bandwidth); fall back to GET
                    r = make_request(url, method="HEAD", timeout=8, allow_redirects=True)
                    status = getattr(r, "status_code", 0) if r else 0
                    if r and status in (200, 301, 302, 403, 401):
                        return url.rstrip("/")
                    # fallback GET
                    r2 = make_request(url, method="GET", timeout=10)
                    if r2 and getattr(r2, "status_code", 0) in (200, 301, 302, 403, 401):
                        return url.rstrip("/")
                except Exception:
                    return None
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(60, len(endpoints) or 1)) as ex:
                futures = {ex.submit(_check, e): e for e in endpoints}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        v = fut.result()
                        if v:
                            alive.add(v)
                    except Exception:
                        continue

        # persist results
        alive_sorted = sorted(alive)
        endpoints_alive_file = self.outdir / f"{self.target.replace('/', '_')}.endpoints_alive.txt"
        if alive_sorted:
            endpoints_alive_file.write_text("\n".join(alive_sorted))
            self.state["endpoints_alive"] = alive_sorted
            log.info("[*] probe_endpoints: %d alive endpoints", len(alive_sorted))
        else:
            self.state["endpoints_alive"] = []
            log.info("[*] probe_endpoints: no alive endpoints found")

    def filter_juicy(self):
        """
        Filter endpoints for 'juicy' indicators (admin pages, API endpoints, sensitive params, file extensions).
        Uses JUICY_PATTERNS from config and writes juicy endpoints to a file + updates self.state['juicy'].
        """
        import re
        from ..config import JUICY_PATTERNS

        log.info("[*] Filtering juicy endpoints using patterns")

        # read candidates: prefer endpoints_alive; else endpoints_raw
        candidates = []
        if self.state.get("endpoints_alive"):
            candidates = list(self.state["endpoints_alive"])
        elif self.files.get("endpoints_raw") and self.files["endpoints_raw"].exists():
            candidates = [l.strip() for l in self.files["endpoints_raw"].read_text().splitlines() if l.strip()]

        juicy = set()
        sens_param_re = re.compile(r"([?&](?:api[_-]?key|token|auth|password|pwd|secret|key|cred|access)=)", re.I)

        for url in set(candidates):
            try:
                # direct keyword/extension matches
                if JUICY_PATTERNS.get("keywords") and JUICY_PATTERNS["keywords"].search(url):
                    juicy.add(url)
                    continue
                if JUICY_PATTERNS.get("extensions") and JUICY_PATTERNS["extensions"].search(url):
                    juicy.add(url)
                    continue
                # sensitive params in querystring
                if sens_param_re.search(url):
                    juicy.add(url)
                    continue
                # api-like patterns
                if "/api/" in url or "/graphql" in url or "/v1/" in url:
                    juicy.add(url)
                    continue
                # admin paths
                if "/admin" in url or "/login" in url or "/wp-admin" in url or "/wp-login" in url:
                    juicy.add(url)
                    continue
            except Exception:
                continue

        # Persist juicy list and update state; also add to files dict if needed
        juicy_file = self.outdir / f"{self.target.replace('/', '_')}.juicy.txt"
        if juicy:
            juicy_file.write_text("\n".join(sorted(juicy)))
            self.state["juicy"] = sorted(juicy)
            # register in files mapping for other methods to find
            self.files["juicy"] = juicy_file
            log.info("[*] filter_juicy: found %d juicy endpoints", len(juicy))
        else:
            self.state["juicy"] = []
            log.info("[*] filter_juicy: no juicy endpoints identified")

    def origin_ip_discovery(self):
        """
        Attempt to find origin IP addresses behind CDN by:
          - parsing resolved_hosts file (host -> IP)
          - probing IPs directly with Host header and comparing content to canonical host response
        Results are written to <target>.origin_ips.txt and state['origin_ips'] (dict host->ips).
        """
        import concurrent.futures
        import socket
        from urllib.parse import urlparse

        log.info("[*] Discovering origin IPs by direct probing")

        # Build host->ips mapping from resolved_hosts file if available
        host_map = {}
        if self.files.get("resolved_hosts") and self.files["resolved_hosts"].exists():
            for line in self.files["resolved_hosts"].read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                host = parts[0]
                ips = parts[1:] if len(parts) > 1 else []
                if ips:
                    host_map.setdefault(host, set()).update(ips)
        else:
            # fallback: try resolving via dns resolver for hosts in state.subdomains
            for host in self.state.get("subdomains", []):
                try:
                    answers = dns.resolver.resolve(host, "A", lifetime=3)
                    for a in answers:
                        host_map.setdefault(host, set()).add(a.to_text())
                except Exception:
                    continue

        results = {}  # host -> set(origin_ips)

        # helper to compare baseline host response vs direct-ip-with-host header
        def _is_origin(host_url, ip, scheme):
            """
            Request host_url normally (baseline) and then request scheme+ip with Host header = host
            If response similarity is high (status matches and body lengths similar) mark as origin.
            """
            try:
                baseline = make_request(host_url, timeout=8, method="GET")
                if not baseline:
                    return False
                base_text = getattr(baseline, "text", "") or ""
                # direct IP URL
                ip_url = f"{scheme}{ip}"
                headers = {"Host": urlparse(host_url).hostname}
                # for HTTPS via IP we must ignore cert verify
                direct = make_request(ip_url, timeout=8, method="GET", headers=headers, verify=False)
                if not direct:
                    return False
                direct_text = getattr(direct, "text", "") or ""
                # compare status and length similarity
                if getattr(baseline, "status_code", 0) == getattr(direct, "status_code", -1):
                    if base_text and direct_text:
                        len_diff = abs(len(base_text) - len(direct_text))
                        ratio = len_diff / max(1, max(len(base_text), len(direct_text)))
                        # if lengths are within 25% consider similar OR if same title tag exists
                        if ratio < 0.25:
                            return True
                        if "<title>" in base_text and "<title>" in direct_text:
                            t1 = re.search(r"<title>(.*?)</title>", base_text, re.I | re.S)
                            t2 = re.search(r"<title>(.*?)</title>", direct_text, re.I | re.S)
                            if t1 and t2 and t1.group(1).strip() == t2.group(1).strip():
                                return True
                return False
            except Exception:
                return False

        # Use alive host URLs if possible (they include scheme), else try to add scheme
        host_to_url = {}
        for alive in self.state.get("alive", []):
            parsed = urlparse(alive)
            host_to_url[parsed.hostname] = alive

        # For hosts without alive record, create a https:// host entry
        for host in host_map.keys():
            if host not in host_to_url:
                host_to_url[host] = "https://" + host

        # Probe candidates concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(40, sum(len(v) for v in host_map.values()) + 1 or 1)) as ex:
            future_map = {}
            for host, ips in host_map.items():
                host_url = host_to_url.get(host, "https://" + host)
                for ip in ips:
                    # try HTTPS first then HTTP
                    future = ex.submit(_is_origin, host_url, ip, "https://")
                    future_map[future] = (host, ip, "https")
                    future2 = ex.submit(_is_origin, host_url, ip, "http://")
                    future_map[future2] = (host, ip, "http")

            for fut in concurrent.futures.as_completed(future_map):
                try:
                    ok = fut.result()
                    host, ip, scheme = future_map[fut]
                    if ok:
                        results.setdefault(host, set()).add(ip)
                except Exception:
                    continue

        # Persist results
        origin_file = self.outdir / f"{self.target.replace('/', '_')}.origin_ips.txt"
        lines = []
        for host, ips in results.items():
            for ip in sorted(ips):
                lines.append(f"{host} {ip}")
        if lines:
            origin_file.write_text("\n".join(sorted(lines)))
            self.state["origin_ips"] = {k: sorted(v) for k, v in results.items()}
            log.info("[*] origin_ip_discovery: found %d origin IP mappings", sum(len(v) for v in results.values()))
        else:
            self.state["origin_ips"] = {}
            log.info("[*] origin_ip_discovery: no origin IPs identified")

    def port_scan(self, ports: list = None):
        """
        Port-scan a list of IPs (origin IPs preferred, otherwise resolved hosts).
        Uses naabu if available, otherwise falls back to a threaded socket scanner for a
        list of common ports. Results are written to <target>.ports.json and state['ports'].
        """
        import concurrent.futures
        import socket
        import json

        log.info("[*] Running port scan")

        # Prepare targets (IPs): prefer discovered origin IPs, else parse resolved_hosts file
        ips = set()
        if self.state.get("origin_ips"):
            for iplist in self.state["origin_ips"].values():
                ips.update(iplist)
        elif self.files.get("resolved_hosts") and self.files["resolved_hosts"].exists():
            for line in self.files["resolved_hosts"].read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                # parts[1] is ip if file contains 'host ip' pairs
                if len(parts) > 1:
                    ips.add(parts[1])
                else:
                    # if file contains only hosts, attempt resolve
                    try:
                        resolved = socket.gethostbyname(parts[0])
                        ips.add(resolved)
                    except Exception:
                        continue
        else:
            # last resort attempt to resolve hosts in state
            for host in self.state.get("resolved_hosts", []):
                try:
                    resolved = socket.gethostbyname(host)
                    ips.add(resolved)
                except Exception:
                    continue

        ips = sorted(ips)
        if not ips:
            log.info("  - No IPs to scan")
            self.state["ports"] = {}
            return

        # default ports if not provided
        if not ports:
            ports = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379, 27017, 9200]

        results = {}  # ip -> [open ports]

        # Try naabu if present
        if self.tools.get("naabu"):
            log.info("  - Using naabu for scanning")
            tmp_in = self.outdir / f"naabu_in_{DATE}.txt"
            tmp_out = self.outdir / f"naabu_out_{DATE}.txt"
            tmp_in.write_text("\n".join(ips))
            # attempt a conservative command; naabu flags vary by version
            cmd = [self.tools["naabu"], "-list", str(tmp_in), "-o", str(tmp_out)]
            res = run(cmd, timeout=900)
            # parse output if available
            combined = ""
            if res and getattr(res, "stdout", None):
                combined += res.stdout + "\n"
            if tmp_out.exists():
                combined += tmp_out.read_text()
            # Extract ip:port occurrences
            for m in re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", combined):
                ip, port = m
                results.setdefault(ip, set()).add(int(port))

        # Fallback: threaded socket connect
        if not results:
            log.info("  - naabu not available or returned no results; using socket scanner")
            def _scan_ip_port(ip, port, timeout=1.2):
                try:
                    with socket.create_connection((ip, port), timeout=timeout):
                        return True
                except Exception:
                    return False

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(200, len(ips) * len(ports) or 1)) as ex:
                future_map = {}
                for ip in ips:
                    for p in ports:
                        fut = ex.submit(_scan_ip_port, ip, p)
                        future_map[fut] = (ip, p)
                for fut in concurrent.futures.as_completed(future_map):
                    try:
                        ok = fut.result()
                        ip, p = future_map[fut]
                        if ok:
                            results.setdefault(ip, set()).add(p)
                    except Exception:
                        continue

        # Normalize and store results
        normalized = {ip: sorted(list(ports)) for ip, ports in results.items()}
        out_json = self.outdir / f"{self.target.replace('/', '_')}.ports.json"
        out_json.write_text(json.dumps(normalized, indent=2))
        self.state["ports"] = normalized
        log.info("[*] port_scan: scanned %d IPs, found open ports for %d IPs", len(ips), len(normalized))


    # ------------------ Enhanced Orchestrator -------------------------------
    def run_advanced(self, do_fuzz=False, do_screens=False, do_security=True):
        log.info("[*] Starting advanced reconnaissance pipeline")
        # Reuse Recon stubs and advanced steps
        self.passive_enum()
        self.advanced_subdomain_enum()
        self.resolve_subs()
        self.probe_hosts()
        self.cloud_asset_discovery()
        self.historical_endpoints()
        self.advanced_endpoint_discovery()
        self.javascript_analysis()
        self.advanced_protocol_discovery()
        self.probe_endpoints()
        self.filter_juicy()
        self.origin_ip_discovery()
        self.port_scan()
        if do_security:
            self.security_scanning()
        if do_fuzz:
            self.advanced_fuzzing()
        if do_screens:
            self.screenshots()
        self.advanced_summary()

    def advanced_summary(self):
        print("\n" + "=" * 60)
        print("[*] ADVANCED RECON SUMMARY")
        print("=" * 60)
        print(f"  - Total subdomains: {len(self.state.get('subdomains', []))}")
        print(f"  - Resolved hosts: {len(self.state.get('resolved_hosts', []))}")
        print(f"  - Alive hosts: {len(self.state.get('alive', []))}")
        print(f"  - Endpoints collected: {len(self.state.get('endpoints_raw', []))}")
        print(f"  - Juicy endpoints: {len(self.state.get('juicy', []))}")
        advanced_stats = {
            "Cloud assets": self.advanced_files["cloud_assets"],
            "JS endpoints": self.advanced_files["js_endpoints"],
            "Hidden parameters": self.advanced_files["hidden_params"],
            "GraphQL endpoints": self.advanced_files["graphql"],
            "WebSocket endpoints": self.advanced_files["websockets"],
            "CORS misconfigurations": self.advanced_files["cors_misconfig"],
            "Takeover candidates": self.advanced_files["takeovers"],
            "Nuclei findings": self.advanced_files["nuclei_results"],
        }
        for name, filepath in advanced_stats.items():
            if filepath.exists():
                count = len(filepath.read_text().splitlines())
                print(f"  - {name}: {count}")
        print(f"\nOutputs written to: {self.outdir}")
        print("=" * 60)

# Helper utility inside module
def _looks_like_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        # try IPv6 naive check
        if ":" in s and len(s) > 2:
            return True
    return False


def shutil_works(tool_path: str) -> bool:
    """
    Quick helper to determine if assetfinder supports --subs-only.
    We use a cheap heuristic: if the binary name contains 'assetfinder' assume modern usage.
    This is a placeholder; we still attempt both command forms in passive_enum.
    """
    return "assetfinder" in (tool_path or "")
