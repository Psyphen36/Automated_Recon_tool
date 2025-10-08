from pathlib import Path
from datetime import datetime, timezone

DEFAULT_CONCURRENCY = 50
DEFAULT_PARALLELISM = 40
USER_AGENT = "JuicyRecon/2.0 (+https://github.com/Psyphen)"
SUBPROCESS_TIMEOUT = 600
DATE = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# Full set of tools restored from your original script
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
    "nuclei": "nuclei",
    "katana": "katana",
    "gospider": "gospider",
    "subjack": "subjack",
    "aquatone": "aquatone",
    "dalfox": "dalfox",
}

# Juicy patterns (shortened for readability but kept representative)
import re
JUICY_PATTERNS = {
    "keywords": re.compile(r"(admin|console|dashboard|beta|staging|dev|login|auth|api|backup|secret|config|upload|wp-login|wp-admin|signin|debug|test|swagger|phpmyadmin|\.git|\.env)", re.I),
    "extensions": re.compile(r"\.(php|asp|aspx|jsp|jsf|do|action|pl|py|rb|json|xml|yml|yaml|conf|bak|old|save|sql|db|zip|7z|pem|key|crt)(\?|$|/)", re.I),
}

# Fuzzing wordlists (kept concise)
FUZZING_WORDLISTS = {
    "api": ["api","v1","graphql","rest","endpoint"],
    "admin": ["admin","dashboard","console"],
    "files": [".git",".env","backup.zip","dump.sql"],
}

ROOT = Path.cwd()
