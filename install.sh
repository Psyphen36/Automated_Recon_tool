#!/usr/bin/env bash
set -e

TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/OWASP/Amass/v4/...@master"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/hakluke/hakrawler@latest"
)

for tool in "${TOOLS[@]}"; do
  echo "[*] Installing $tool"
  go install -v "$tool"
done

echo "[✔] All tools installed successfully!"