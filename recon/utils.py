"""Utility helpers: subprocess wrappers, http requests with backoff, basic filesystem helpers."""

from pathlib import Path
import shutil
import subprocess
from typing import List, Optional
import requests
import backoff
import logging
from .config import USER_AGENT, SUBPROCESS_TIMEOUT

log = logging.getLogger(__name__)


def which(tool: str) -> Optional[str]:
    """Return absolute path to a tool if found on PATH."""
    return shutil.which(tool)


def run(cmd: List[str], capture_output=True, check=False, timeout: int = SUBPROCESS_TIMEOUT, input_text: Optional[str] = None):
    """
    Run a subprocess command safely and return CompletedProcess or None on error.
    This function won't raise on non-zero exit unless check=True and returned CompletedProcess will be given.
    """
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
        log.warning("Command failed: %s -> %s", ' '.join(cmd), e)
        return None
    except subprocess.TimeoutExpired as e:
        log.warning("Command timeout: %s -> %s", ' '.join(cmd), e)
        return None
    except FileNotFoundError:
        log.debug("Tool not found for command: %s", cmd[0])
        return None


@backoff.on_exception(backoff.expo, Exception, max_tries=3, jitter=None)
def make_request(url: str, timeout: int = 10, method: str = "GET", **kwargs) -> Optional[requests.Response]:
    """
    HTTP request with retries and a sane User-Agent.
    Blocking — wrap with run_in_executor for async usage.
    """
    headers = kwargs.pop('headers', {})
    headers.setdefault('User-Agent', USER_AGENT)
    try:
        method = method.upper()
        if method == 'GET':
            return requests.get(url, timeout=timeout, headers=headers, **kwargs)
        elif method == 'HEAD':
            return requests.head(url, timeout=timeout, headers=headers, **kwargs)
        elif method == 'POST':
            return requests.post(url, timeout=timeout, headers=headers, **kwargs)
        else:
            # Generic request
            return requests.request(method, url, timeout=timeout, headers=headers, **kwargs)
    except requests.RequestException as e:
        log.debug("Request failed %s %s", url, e)
        return None


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
