#!/usr/bin/env python3
import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# ----------------------------- Configuration ---------------------------------
DEFAULT_CONCURRENCY = 40
DEFAULT_PARALLELISM = 40
USER_AGENT = "JuicyRecon/1.0 (+https://github.com/Psyphen)"
SUBPROCESS_TIMEOUT = 300  # seconds - adjust if you expect longer runs

# Tools to try to use (we detect presence automatically)
REQUIRES = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "amass": "amass",
    "shuffledns": "shuffledns",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "gau": "gau",
    "waybackurls": "waybackurls",
    "anew": "anew",
    "naabu": "naabu",
    "ffuf": "ffuf",
    "hakrawler": "hakrawler",
}

# Juicy keyword regex for endpoints
JUICY_KEYWORDS = re.compile(
    r"(admin|console|dashboard|beta|staging|dev|internal|login|auth|api|backup|manage|secret|config|upload|wp-login|wp-admin|signin)",
    re.I,
)

# Acceptable output filenames
DATE = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# ----------------------------- Utilities -----------------------------------


def which(tool: str) -> Optional[str]:
    """Return path to executable or None."""
    return shutil.which(tool)


def run(cmd: List[str], capture_output=True, check=False, timeout=None, input_text=None):
    """Convenience wrapper around subprocess.run"""
    try:
        res = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=check,
            timeout=timeout,
            input=input_text,
        )
        return res
    except subprocess.CalledProcessError as e:
        print(f"[!] command failed: {' '.join(cmd)}: {e}")
        return e
    except subprocess.TimeoutExpired:
        print(f"[!] command timed out: {' '.join(cmd)}")
        return None


async def run_async(cmd: List[str]) -> Tuple[int, str, str]:
    """Run subprocess asynchronously and collect stdout/stderr."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, (stdout.decode() if stdout else ""), (stderr.decode() if stderr else "")


def ensure_dir(d: Path):
    d.mkdir(parents=True, exist_ok=True)


# ----------------------------- Core Recon Steps -----------------------------


class Recon:
    def __init__(
        self,
        target: str,
        outdir: Path,
        concurrency: int = DEFAULT_CONCURRENCY,
        wordlist: Optional[Path] = None,
        api_keys: dict = None,
    ):
        self.target = target.strip()
        self.outdir = outdir
        ensure_dir(self.outdir)
        self.concurrency = concurrency
        self.wordlist = wordlist
        self.tools = {name: which(bin) for name, bin in REQUIRES.items()}
        self.api_keys = api_keys or {}
        self.files = {}
        self.state = defaultdict(list)
        self._init_files()

    def _init_files(self):
        base = f"{self.outdir}/{self.target.replace('/', '_')}"
        self.files = {
            "allsubs": Path(base + ".allsubs.txt"),
            "resolved_hosts": Path(base + ".resolved_hosts.txt"),
            "alive": Path(base + ".alive.txt"),
            "endpoints_raw": Path(base + ".endpoints_raw.txt"),
            "endpoints_alive": Path(base + ".endpoints_alive.txt"),
            "juicy": Path(base + ".juicy.txt"),
            "origin_ips": Path(base + ".origin_ips.json"),
            "ports": Path(base + ".ports.txt"),
        }

    # ------------------ Passive enumeration ---------------------------------
    def passive_enum(self):
        """Run a collection of passive enumerators and aggregate results into allsubs.txt"""
        print("[*] Passive enumeration started")
        subdomains = set()

        # subfinder
        if self.tools.get("subfinder"):
            print("  - running subfinder")
            res = run([self.tools["subfinder"], "-d", self.target, "-all"], capture_output=True)
            if res and getattr(res, "stdout", None):
                subdomains.update({l.strip() for l in res.stdout.splitlines() if l.strip()})

        # assetfinder
        if self.tools.get("assetfinder"):
            print("  - running assetfinder")
            res = run([self.tools["assetfinder"], self.target], capture_output=True)
            if res and getattr(res, "stdout", None):
                subdomains.update({l.strip() for l in res.stdout.splitlines() if l.strip()})

        # amass passive
        if self.tools.get("amass"):
            print("  - running amass (passive)")
            tmp = self.outdir / f"amass_passive_{DATE}.txt"
            run([self.tools["amass"], "enum", "-passive", "-d", self.target, "-o", str(tmp)], capture_output=False)
            if tmp.exists():
                subdomains.update({l.strip() for l in tmp.read_text().splitlines() if l.strip()})

        # crt.sh
        print("  - querying crt.sh (public certs)")
        try:
            import urllib.parse, urllib.request

            q = urllib.request.urlopen(
                f"https://crt.sh/?q=%25.{urllib.parse.quote(self.target)}&output=json", timeout=30
            )
            raw = q.read().decode()
            entries = json.loads(raw)
            for e in entries:
                name = e.get("name_value")
                if name:
                    for n in name.split("\n"):
                        subdomains.add(n.replace("*.", "").strip())
        except Exception as e:
            print(f"    crt.sh query failed: {e}")

        # save
        subs_sorted = sorted(subdomains)
        self.files["allsubs"].write_text("\n".join(subs_sorted) + ("\n" if subs_sorted else ""))
        print(f"[*] Passive enumeration found {len(subs_sorted)} subdomains -> {self.files['allsubs']}")
        self.state["subdomains"] = subs_sorted

    # ------------------ Resolve / Filter ----------------------------------
    def resolve_subs(self):
        """Resolve subdomains with dnsx (if available) or socket fallback."""
        print("[*] Resolving subdomains")
        subs = self.files["allsubs"].read_text().splitlines() if self.files["allsubs"].exists() else []
        resolved = set()

        if not subs:
            print("[!] No subdomains to resolve")
            return

        if self.tools.get("dnsx"):
            print("  - using dnsx for fast resolution and CNAME/A records (temp-file input)")
            tmpout = self.outdir / f"dnsx_out_{DATE}.txt"
            p = [self.tools["dnsx"], "-l", str(tmpout) + ".in", "-a", "-resp", "-cname"]
            # write subs to a temp file and call dnsx with -l <file>
            tf = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
                    tf_path = tf.name
                    tf.write("\n".join(subs) + "\n")
                p = [self.tools["dnsx"], "-l", tf_path, "-a", "-resp", "-cname"]
                proc = subprocess.Popen(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=SUBPROCESS_TIMEOUT)
                if proc.returncode != 0:
                    print(f"    dnsx returned code {proc.returncode}. stderr: {err.strip()}")
                if out:
                    for line in out.splitlines():
                        host = line.split()[0]
                        host = host.split(":")[0]
                        resolved.add(host)
                # also try to read dnsx output file if dnsx supports -o (not used here), but we captured stdout already
            except subprocess.TimeoutExpired:
                proc.kill()
                print("    dnsx timed out")
            except Exception as e:
                print(f"    dnsx invocation failed: {e}")
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
        else:
            print("  - dnsx not found, using socket.gethostbyname_ex fallback (slow)")
            for s in subs:
                try:
                    _ = socket.gethostbyname_ex(s)
                    resolved.add(s)
                except Exception:
                    continue

        resolved_list = sorted(resolved)
        self.files["resolved_hosts"].write_text("\n".join(resolved_list) + ("\n" if resolved_list else ""))
        print(f"[*] Resolved {len(resolved_list)} hosts -> {self.files['resolved_hosts']}")
        self.state["resolved_hosts"] = resolved_list

    # ------------------ HTTP probing --------------------------------------
    def probe_hosts(self):
        """Check which hosts have HTTP(S) service using httpx or httprobe fallback."""
        hosts = self.state.get("resolved_hosts", [])
        if not hosts:
            print("[!] No hosts to probe")
            return

        alive = []
        if self.tools.get("httpx"):
            print("[*] probing with httpx (temp-file input)")
            tmp_alive = str(self.files["alive"])
            tf = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
                    tf_path = tf.name
                    tf.write("\n".join(hosts) + "\n")
                p = [self.tools["httpx"], "-silent", "-status-code", "-title", "-content-length", "-o", tmp_alive, "-l", tf_path]
                proc = subprocess.Popen(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=SUBPROCESS_TIMEOUT)
                if proc.returncode != 0:
                    print(f"    httpx returned code {proc.returncode}. stderr: {err.strip()}")
                if self.files["alive"].exists():
                    alive = [l.split()[0] for l in self.files["alive"].read_text().splitlines() if l.strip()]
            except subprocess.TimeoutExpired:
                proc.kill()
                print("    httpx timed out")
            except Exception as e:
                print(f"    httpx invocation failed: {e}")
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
        else:
            # simple probe using requests via python
            print("[*] httpx not found, performing naive http(s) probes")
            import requests

            sess = requests.Session()
            sess.headers.update({"User-Agent": USER_AGENT})
            for h in hosts:
                for proto in ("https://", "http://"):
                    try:
                        url = proto + h
                        r = sess.head(url, timeout=6, allow_redirects=True)
                        if r.status_code < 600:
                            alive.append(url)
                            break
                    except Exception:
                        continue
            Path(self.files["alive"]).write_text("\n".join(alive) + ("\n" if alive else ""))

        print(f"[*] Found {len(alive)} alive hosts -> {self.files['alive']}")
        self.state["alive"] = alive

    # ------------------ Historical endpoints --------------------------------
    def historical_endpoints(self):
        """Collect endpoints via gau + waybackurls (per-host). Uses parallelism conservatively."""
        hosts = self.state.get("resolved_hosts", [])
        if not hosts:
            print("[!] No hosts for historical endpoints")
            return

        results = set()
        print("[*] Collecting historical endpoints (gau + waybackurls when available)")
        for h in hosts:
            if self.tools.get("gau"):
                rc = run([self.tools["gau"], h], capture_output=True, timeout=60)
                if rc and getattr(rc, "stdout", None):
                    results.update({l.strip() for l in rc.stdout.splitlines() if l.strip()})
            if self.tools.get("waybackurls"):
                # avoid shell; pass host on stdin
                try:
                    rc = run([self.tools["waybackurls"]], capture_output=True, timeout=60, input_text=h + "\n")
                    if rc and getattr(rc, "stdout", None):
                        results.update({l.strip() for l in rc.stdout.splitlines() if l.strip()})
                except Exception as e:
                    print(f"    waybackurls failed for {h}: {e}")

        # save
        results_sorted = sorted(results)
        self.files["endpoints_raw"].write_text("\n".join(results_sorted) + ("\n" if results_sorted else ""))
        print(f"[*] Collected {len(results_sorted)} historical endpoints -> {self.files['endpoints_raw']}")
        self.state["endpoints_raw"] = results_sorted

    # ------------------ Endpoint liveness ----------------------------------
    def probe_endpoints(self):
        print("[*] Probing endpoints for liveness and metadata")
        endpoints = self.state.get("endpoints_raw", [])
        if not endpoints:
            print("[!] No endpoints to probe")
            return

        alive = set()
        if self.tools.get("httpx"):
            tmpfile = self.outdir / f"httpx_endpoints_{DATE}.txt"
            tf = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
                    tf_path = tf.name
                    tf.write("\n".join(endpoints) + "\n")
                p = [
                    self.tools["httpx"],
                    "-silent",
                    "-title",
                    "-status-code",
                    "-content-length",
                    "-o",
                    str(tmpfile),
                    "-follow-redirects",
                    "-l",
                    tf_path,
                ]
                proc = subprocess.Popen(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=SUBPROCESS_TIMEOUT)
                if proc.returncode != 0:
                    print(f"    httpx (endpoints) returned code {proc.returncode}. stderr: {err.strip()}")
                if tmpfile.exists():
                    alive.update({l.strip() for l in tmpfile.read_text().splitlines() if l.strip()})
            except subprocess.TimeoutExpired:
                proc.kill()
                print("    httpx (endpoints) timed out")
            except Exception as e:
                print(f"    httpx endpoints invocation failed: {e}")
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
        else:
            import requests

            sess = requests.Session()
            sess.headers.update({"User-Agent": USER_AGENT})
            for e in endpoints:
                try:
                    r = sess.head(e, timeout=8, allow_redirects=True)
                    alive.add(e)
                except Exception:
                    continue

        alive_sorted = sorted(alive)
        self.files["endpoints_alive"].write_text("\n".join(alive_sorted) + ("\n" if alive_sorted else ""))
        print(f"[*] Endpoints alive: {len(alive_sorted)} -> {self.files['endpoints_alive']}")
        self.state["endpoints_alive"] = alive_sorted

    # ------------------ Juicy filtering ------------------------------------
    def filter_juicy(self):
        print("[*] Filtering juicy endpoints and patterns")
        alive = self.state.get("endpoints_alive", [])
        juicy = []
        for e in alive:
            if JUICY_KEYWORDS.search(e):
                juicy.append(e)
        # Also check raw endpoints for interesting file extensions (php, aspx, json, xml)
        for e in self.state.get("endpoints_raw", []):
            if re.search(r"\.(php|aspx|json|xml|jsp|action)(\b|\?)", e, re.I):
                juicy.append(e)

        juicy = sorted(set(juicy))
        self.files["juicy"].write_text("\n".join(juicy) + ("\n" if juicy else ""))
        print(f"[*] Juicy endpoints: {len(juicy)} -> {self.files['juicy']}")
        self.state["juicy"] = juicy

    # ------------------ Origin IP discovery --------------------------------
    def origin_ip_discovery(self):
        """Attempt to find origin IPs by resolving host A records and optionally using Shodan/Censys if API keys provided."""
        print("[*] Discovering origin IPs")
        hosts = self.state.get("resolved_hosts", [])
        ip_map = defaultdict(set)
        for h in hosts:
            try:
                answers = socket.getaddrinfo(h, None)
                for a in answers:
                    addr = a[4][0]
                    if re.match(r"\d+\.\d+\.\d+\.\d+", addr):
                        ip_map[addr].add(h)
            except Exception:
                continue

        # Optionally, check Shodan/Censys (if keys provided) to find historical IPs or hostnames
        if self.api_keys.get("shodan"):
            print("  - querying shodan for extra host->ip mappings (requires API key)")
            try:
                import requests

                shodan_key = self.api_keys["shodan"]
                for h in hosts:
                    q = requests.get(f"https://api.shodan.io/dns/resolve?hostnames={h}&key={shodan_key}")
                    if q.ok:
                        data = q.json()
                        for v in data.values():
                            if v:
                                ip_map[v].add(h)
            except Exception as e:
                print(f"    shodan query failed: {e}")

        # persist
        ip_data = {ip: sorted(list(hosts)) for ip, hosts in ip_map.items()}
        self.files["origin_ips"].write_text(json.dumps(ip_data, indent=2))
        print(f"[*] Discovered {len(ip_data)} IPs -> {self.files['origin_ips']}")
        self.state["origin_ips"] = ip_data

    # ------------------ Port scanning -------------------------------------
    def port_scan(self):
        print("[*] Port/Service discovery")
        ips = list(self.state.get("origin_ips", {}).keys())
        if not ips:
            print("[!] No IPs for port scanning")
            return

        results = []
        if self.tools.get("naabu"):
            print("  - using naabu for fast TCP scan (temp-file input)")
            tmp = self.outdir / f"naabu_{DATE}.txt"
            try:
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
                    tf_path = tf.name
                    tf.write("\n".join(ips) + "\n")
                p = [self.tools["naabu"], "-list", tf_path, "-o", str(tmp), "-rate", "500"]
                proc = subprocess.Popen(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=SUBPROCESS_TIMEOUT)
                if proc.returncode != 0:
                    print(f"    naabu returned code {proc.returncode}. stderr: {err.strip()}")
                if tmp.exists():
                    results = [l.strip() for l in tmp.read_text().splitlines() if l.strip()]
            except subprocess.TimeoutExpired:
                proc.kill()
                print("    naabu timed out")
            except Exception as e:
                print(f"    naabu invocation failed: {e}")
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
        else:
            # naive socket connect scan for common ports
            common = [80, 443, 8080, 8443, 22, 21, 25, 3306, 6379, 27017]
            for ip in ips:
                for port in common:
                    s = socket.socket()
                    s.settimeout(1.5)
                    try:
                        s.connect((ip, port))
                        results.append(f"{ip}:{port}")
                    except Exception:
                        pass
                    finally:
                        s.close()

        Path(self.files["ports"]).write_text("\n".join(results) + ("\n" if results else ""))
        print(f"[*] Port scan results -> {self.files['ports']} ({len(results)} entries)")
        self.state["ports"] = results

    # ------------------ Fuzz / Directory discovery -------------------------
    def fuzz_paths(self, targets: Optional[List[str]] = None):
        """Run ffuf (if installed) to find hidden directories on juicy hosts. Requires a wordlist.
        The user should provide a good wordlist (SecLists) via --wordlist flag.
        """
        targets = targets or self.state.get("alive", [])
        if not targets:
            print("[!] No live hosts to fuzz")
            return
        if not self.wordlist or not self.wordlist.exists():
            print("[!] No wordlist provided or file not found; skipping ffuf")
            return
        if not self.tools.get("ffuf"):
            print("[!] ffuf not found in PATH; skipping fuzzing")
            return

        print("[*] Starting path fuzzing with ffuf (conservative by default)")
        outdir = self.outdir / "ffuf"
        ensure_dir(outdir)
        for t in targets:
            host = t.replace("http://", "").replace("https://", "").split("/")[0]
            out = outdir / f"ffuf_{host}.json"
            cmd = [
                self.tools["ffuf"],
                "-u",
                f"{t.rstrip('/')}/FUZZ",
                "-w",
                str(self.wordlist),
                "-mc",
                "200,301,302,401,403,500",
                "-o",
                str(out),
                "-of",
                "json",
                "-t",
                "40",
            ]
            print(f"  - fuzzing {t} -> {out}")
            subprocess.run(cmd)

    # ------------------ Screenshots (optional) -----------------------------
    def screenshots(self):
        """If chromium is installed, use it headlessly to screenshot alive hosts (simple)."""
        chromium = shutil.which("chromium") or shutil.which("chrome") or shutil.which("chromium-browser")
        if not chromium:
            print("[!] Chromium/Chrome not found; skipping screenshots")
            return
        outdir = self.outdir / "screenshots"
        ensure_dir(outdir)
        for url in self.state.get("alive", []):
            host = re.sub(r"https?://", "", url).split("/")[0]
            outfile = outdir / f"{host}.png"
            cmd = [chromium, "--headless", "--disable-gpu", "--screenshot=" + str(outfile), "--window-size=1366,768", url]
            subprocess.run(cmd)
            print(f"  - screenshot {url} -> {outfile}")

    # ------------------ Summary / Output ----------------------------------
    def summary(self):
        print("\n[*] Recon summary")
        print(f"  - total subdomains: {len(self.state.get('subdomains', []))}")
        print(f"  - resolved hosts: {len(self.state.get('resolved_hosts', []))}")
        print(f"  - alive hosts: {len(self.state.get('alive', []))}")
        print(f"  - endpoints collected: {len(self.state.get('endpoints_raw', []))}")
        print(f"  - juicy endpoints: {len(self.state.get('juicy', []))}")
        print(f"  - origin IPs: {len(self.state.get('origin_ips', {}))}")
        print(f"  - port entries: {len(self.state.get('ports', []))}")
        print(f"\nOutputs written to: {self.outdir}\n")

    # ------------------ Orchestrator --------------------------------------
    def run_all(self, do_fuzz=False, do_screens=False):
        self.passive_enum()
        self.resolve_subs()
        self.probe_hosts()
        self.historical_endpoints()
        self.probe_endpoints()
        self.filter_juicy()
        self.origin_ip_discovery()
        self.port_scan()
        if do_fuzz:
            self.fuzz_paths()
        if do_screens:
            self.screenshots()
        self.summary()


# ----------------------------- CLI ---------------------------------------


def parse_args():
    p = argparse.ArgumentParser(description="Advanced Recon Toolkit - single-file")
    p.add_argument("-t", "--target", required=True, help="Target domain or host (e.g. example.com)")
    p.add_argument("-o", "--outdir", default="./juicy_recon_results", help="Output directory")
    p.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("-w", "--wordlist", type=Path, help="Path to wordlist for fuzzing (ffuf)")
    p.add_argument("--shodan", help="Shodan API key (optional)")
    p.add_argument("--fuzz", action="store_true", help="Run ffuf fuzzing step (requires ffuf + wordlist)")
    p.add_argument("--screenshots", action="store_true", help="Take screenshots of alive hosts (requires chromium)")
    return p.parse_args()


def main():
    args = parse_args()
    outdir = Path(args.outdir) / args.target.replace("/", "_")
    recon = Recon(
        args.target,
        outdir,
        concurrency=args.concurrency,
        wordlist=args.wordlist,
        api_keys={"shodan": args.shodan} if args.shodan else {},
    )
    recon.run_all(do_fuzz=args.fuzz, do_screens=args.screenshots)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)