#!/usr/bin/env bash
set -e

TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/owasp-amass/amass/v4/...@master"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/dark-warlord14/jsleak@latest"
  "github.com/gwen001/github-subdomains@latest"
  "github.com/sa7mon/S3Scanner@latest"
  "github.com/jobertabma/vhostscan@latest"
  "github.com/s0md3v/corsy@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/rbsec/sslscan@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

)

for tool in "${TOOLS[@]}"; do
  echo "[*] Installing $tool"
  go install -v "$tool"
done

echo "[✔] All tools installed successfully!"