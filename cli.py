#!/usr/bin/env python3
import argparse
from pathlib import Path
import logging
from recon.advanced.advanced_recon import AdvancedRecon
from recon.recon_base import Recon

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def parse_args():
    p = argparse.ArgumentParser(description="JuicyRecon - Modular Advanced Recon")
    p.add_argument("-t", "--target", required=True, help="Target domain or host (e.g. example.com)")
    p.add_argument("-o", "--outdir", default="./advanced_recon_results", help="Output directory")
    p.add_argument("-c", "--concurrency", type=int, default=50, help="Concurrency")
    p.add_argument("-w", "--wordlist", type=Path, help="Path to wordlist for fuzzing")
    p.add_argument("--fuzz", action="store_true", help="Run advanced fuzzing")
    p.add_argument("--screenshots", action="store_true", help="Take screenshots")
    p.add_argument("--no-security", action="store_true", help="Skip security scanning")
    p.add_argument("--advanced", action="store_true", help="Enable all advanced techniques")
    return p.parse_args()

def main():
    args = parse_args()
    outdir = Path(args.outdir) / args.target.replace("/", "_")
    if args.advanced:
        recon = AdvancedRecon(
            args.target,
            outdir,
            concurrency=args.concurrency,
            wordlist=args.wordlist
        )
        recon.run_advanced(do_fuzz=args.fuzz, do_screens=args.screenshots, do_security=not args.no_security)
    else:
        recon = Recon(args.target, outdir, concurrency=args.concurrency, wordlist=args.wordlist)
        recon.run_all(do_fuzz=args.fuzz, do_screens=args.screenshots)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        raise SystemExit(1)
