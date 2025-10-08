# 🧠 Recon Tools Installation (Linux)

This guide helps you install all the essential recon tools using **Go**.  
Each tool is listed with its `go install` command, dependencies (if any), and short notes.

---

## ⚙️ Prerequisites

Before installing, make sure you have **Go ≥ 1.22** installed and `$GOPATH/bin` is in your `PATH`.

```bash
sudo apt install golang-go -y
export PATH=$PATH:$(go env GOPATH)/bin
````

---

## 📦 Tools Installation In One Go

### Install it in one go
To install all tools at once run:

```bash
chmod +x install_recon_tools.sh
./install_recon_tools.sh
```
also before running the tool make sure to install the necesary python packages by simply going to the folder and running:
```
python3 -m venv recon_tool_env
```
then
```
source recon_tool_env/bin/activate
```
after activating the python environment install the packages from pip by using:
```
pip3 install -r requirements.txt
```

If you do the installation and setup properly you can now be able to run cli.py without any errors you can either check the command flags by using `python3 cli.py -h` or run this directly instead:
```
❯ python3 cli.py -t domain.com -w /usr/share/SecLists/Discovery/Web-Content/combined_directories.txt --screenshots --advanced --fuzz
```
the output should be something similar to this:
```
2025-10-08 15:30:03,657 INFO Initialized Recon for domain.com -> advanced_recon_results/domain.com
2025-10-08 15:30:03,661 INFO [*] Starting advanced reconnaissance pipeline
2025-10-08 15:30:03,661 INFO [*] Running passive enumeration (subfinder / assetfinder / amass)
2025-10-08 15:30:03,661 INFO   - Running subfinder: /home/ozz/go/bin/subfinder -d domain.com -silent
2025-10-08 15:30:18,706 INFO   - Running assetfinder: /home/ozz/go/bin/assetfinder --subs-only domain.com
2025-10-08 15:30:22,817 INFO   - Running amass: /home/ozz/go/bin/amass enum -passive -d domain.com -norecursive
```
---
## 📦 Manually installing the tool one by one

### 🕵️ Subfinder

Passive subdomain enumeration tool.

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

### 🌐 Assetfinder

Discovers subdomains using public data sources.

```bash
go install github.com/tomnomnom/assetfinder@latest
```

---

### 🛰️ Amass

Powerful subdomain enumeration and network mapping tool.

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

> **Note:** Amass requires Go ≥ 1.22.
> You can also install it from Debian packages or prebuilt binaries if compilation fails.

---

### 🔀 Shuffledns

Fast DNS resolver and brute-forcer using **massdns**.

```bash
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
```

> **Dependency:** [massdns](https://github.com/blechschmidt/massdns) must be installed:
>
> ```bash
> git clone https://github.com/blechschmidt/massdns.git
> cd massdns
> make
> sudo cp bin/massdns /usr/local/bin/
> ```

---

### 🧩 Dnsx

Fast DNS resolver & toolkit.

```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

---

### 🌍 Httpx

HTTP toolkit to probe URLs and gather information (status codes, titles, tech stack, etc.).

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

### 📜 Gau (GetAllUrls)

Fetches known URLs from AlienVault’s OTX, Wayback Machine, etc.

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

### 🕰️ Waybackurls

Extracts URLs from the Wayback Machine for a given domain.

```bash
go install github.com/tomnomnom/waybackurls@latest
```

---

### 🆕 Anew

Appends lines to a file only if they’re unique — great for recon automation.

```bash
go install github.com/tomnomnom/anew@latest
```

---

### 🚀 Naabu

Fast port scanner written in Go.

```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

> **Tip:** Requires root privileges for full SYN scans.
>
> Example usage:
>
> ```bash
> sudo naabu -host example.com
> ```

---

### 🧨 FFUF

Fast web fuzzer for content discovery.

```bash
go install github.com/ffuf/ffuf@latest
```

---

### 🕸️ Hakrawler

Fast web crawler built for hackers.

```bash
go install github.com/hakluke/hakrawler@latest
```

---

## 🧰 Post-Installation

After installation, confirm all tools are in your `$PATH`:

```bash
echo $PATH | grep $(go env GOPATH)/bin
```

Then verify:

```bash
subfinder -h
assetfinder -h
amass -h
httpx -h
```

If they’re not found, add this line to your `~/.bashrc` or `~/.zshrc`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```


## ✅ Final Check

Run:

```bash
subfinder -version
naabu -version
ffuf -version
```

If all return valid versions — you’re good to go 🎯

---

### 🧾 Credits

* [ProjectDiscovery](https://github.com/projectdiscovery)
* [Tomnomnom](https://github.com/tomnomnom)
* [Hakluke](https://github.com/hakluke)
* [OWASP Amass](https://github.com/OWASP/Amass)
* [LC](https://github.com/lc/gau)
