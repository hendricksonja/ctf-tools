# CTF Toolbox Reference

A quick-reference guide for common tools used in Capture the Flag challenges.  
Designed as a GitHub-friendly README for students.

---

## Table of Contents

1. [How to Use This Document](#how-to-use-this-document)
2. [Tool Index by Category](#tool-index-by-category)
3. [Core CLI Utilities](#core-cli-utilities)
   - [strings](#strings)
   - [file](#file)
   - [xxd](#xxd)
   - [grep](#grep)
   - [sed](#sed)
   - [awk](#awk)
   - [hexdump](#hexdump)
   - [tar / zip / unzip](#tar--zip--unzip)
   - [nc (netcat)](#nc-netcat)
   - [curl / wget](#curl--wget)
4. [Network Recon & Scanning](#network-recon--scanning)
   - [nmap](#nmap)
   - [masscan](#masscan)
   - [traceroute / mtr](#traceroute--mtr)
5. [Web Exploitation](#web-exploitation)
   - [Burp Suite](#burp-suite)
   - [ffuf](#ffuf)
   - [sqlmap](#sqlmap)
   - [wfuzz](#wfuzz)
   - [Postman / HTTPie](#postman--httpie)
6. [Crypto & Encoding](#crypto--encoding)
   - [CyberChef](#cyberchef)
   - [hashcat](#hashcat)
   - [John the Ripper](#john-the-ripper)
   - [openssl](#openssl)
7. [Reverse Engineering](#reverse-engineering)
   - [Ghidra](#ghidra)
   - [IDA Free](#ida-free)
   - [radare2 / rizin](#radare2--rizin)
   - [strings (again)](#strings-for-reverse-engineering)
8. [Binary Exploitation (Pwn)](#binary-exploitation-pwn)
   - [gdb + pwndbg / GEF](#gdb--pwndbg--gef)
   - [pwntools](#pwntools)
   - [ROPgadget / Ropper](#ropgadget--ropper)
9. [Forensics & Stego](#forensics--stego)
   - [Wireshark](#wireshark)
   - [tshark](#tshark)
   - [binwalk](#binwalk)
   - [Steghide / zsteg / stegsolve](#steghide--zsteg--stegsolve)
   - [Volatility / Volatility3](#volatility--volatility3)
   - [exiftool](#exiftool)
10. [Misc Utilities & Automation](#misc-utilities--automation)
    - [Python](#python)
    - [jq](#jq)
    - [git](#git)

---

## How to Use This Document

- **Search by tag**: Look for `Tags:` lines under each tool, e.g. `Tags: recon, web`.
- **Search by problem type**: Try searching for `web`, `crypto`, `forensics`, `reverse`, `pwn`, `stego`.
- **Copy-paste examples**: Most tools have a “Typical uses” or “Example commands” section with copy-ready commands.
- **Docs links**: Each tool has a `Docs:` line with official documentation, manual pages, or GitHub repos.

---

## Tool Index by Category

Quick index of tools by primary category (many tools fit multiple):

- **Recon / Network**  
  `nmap`, `masscan`, `traceroute`, `mtr`, `nc`, `curl`, `wget`

- **Web**  
  Burp Suite, `ffuf`, `wfuzz`, `sqlmap`, Postman, HTTPie, `curl`, `wget`

- **Crypto / Encoding / Hashes**  
  CyberChef, `openssl`, `hashcat`, John the Ripper, `xxd`, `hexdump`

- **Reverse Engineering**  
  Ghidra, IDA Free, radare2/rizin, `strings`, `file`, `xxd`, `hexdump`

- **Pwn / Binary Exploitation**  
  `gdb` (+ pwndbg/GEF), `pwntools`, ROPgadget, Ropper, `nc`

- **Forensics / Stego**  
  Wireshark, `tshark`, `binwalk`, Steghide, zsteg, stegsolve, Volatility, `exiftool`, `tar`, `zip`, `unzip`

- **General CLI**  
  `strings`, `file`, `grep`, `sed`, `awk`, `jq`, `python`, `git`

---

## Core CLI Utilities

### strings

> Extracts printable strings from binary files.  
> **Docs:** [GNU `strings` manual](https://sourceware.org/binutils/docs/binutils/strings.html)

- **Tags:** `general`, `forensics`, `reverse`, `stego`
- **Typical uses:**
  - Quickly search binaries, images, and dumps for `CTF{` or other flag formats.
  - Find hidden clues, hardcoded passwords, or URLs.

**Common options:**

- `strings file.bin` – default usage.
- `strings -n 3 file.bin` – only show strings of length ≥ 3.
- `strings -t x file.bin` – show offset (in hex) of each string.

**Example:**

```bash
# Look for something that looks like a flag
strings suspect.bin | grep -i 'ctf{'

# Show strings with offsets, then grep for "key"
strings -t x dump.raw | grep -i key
````

---

### file

> Identifies file type based on magic bytes.
> **Docs:** [`file` command man page](https://man7.org/linux/man-pages/man1/file.1.html)

* **Tags:** `general`, `forensics`, `reverse`
* **Typical uses:**

  * Determine if an unknown blob is a PNG, ELF, pcap, compressed archive, etc.
  * Notice when a file has the wrong extension (e.g., `.jpg` that is really a `zip`).

**Example:**

```bash
file mystery.dat
# Output might be: "mystery.dat: PNG image data, 800 x 600, 8-bit/color..."
```

---

### xxd

> Hex dump tool (and reverse).
> **Docs:** [`xxd` manual](https://manpages.debian.org/jessie/vim-common/xxd.1.en.html)

* **Tags:** `general`, `reverse`, `crypto`, `forensics`
* **Typical uses:**

  * Inspect raw bytes and offsets.
  * Patch single bytes for quick modifications.

**Common options:**

* `xxd file.bin` – hex dump with offsets.
* `xxd -g 1 file.bin` – group bytes individually (useful for patching).
* `xxd -r` – reverse (hex to binary).

**Examples:**

```bash
# Hex dump
xxd -g 1 challenge.bin | head

# Patch one byte at offset 0x13 from 0x75 to 0x74
xxd -g 1 challenge.bin | sed '...'  # (or use a hex editor)
# For a quick inline patch, you might:
printf '\x74' | dd of=challenge.bin bs=1 seek=$((0x13)) count=1 conv=notrunc
```

---

### grep

> Searches text using regular expressions.
> **Docs:** [GNU `grep` manual](https://www.gnu.org/software/grep/manual/grep.html)

* **Tags:** `general`, `forensics`, `reverse`, `crypto`
* **Typical uses:**

  * Filter large outputs for interesting lines.
  * Search for patterns like `CTF{`, `flag`, `password`, or regexes.

**Common options:**

* `grep pattern file` – basic search.
* `grep -i pattern file` – case-insensitive.
* `grep -r pattern dir/` – recursive.
* `grep -E 'regex' file` – extended regex.

**Examples:**

```bash
# Case-insensitive search for possible flags
strings big_dump.bin | grep -i 'ctf{'

# Recursive search in all logs
grep -ri 'password' .
```

---

### sed

> Stream editor for simple text transformations.
> **Docs:** [GNU `sed` manual](https://www.gnu.org/software/sed/manual/sed.html)

* **Tags:** `general`, `forensics`, `crypto`
* **Typical uses:**

  * Replace or delete characters.
  * Strip fixed prefixes from lines, reformat data for another tool.

**Common patterns:**

* `sed 's/OLD/NEW/g' file` – replace `OLD` with `NEW`.
* `sed 's/^..../' file` – remove first 4 characters from each line.
* `sed '1,10d' file` – delete first 10 lines.

**Examples:**

```bash
# Replace all colons with newlines (e.g., from hex:aa:bb style)
echo "aa:bb:cc:dd" | sed 's/:/\n/g'

# Remove "0x" prefixes from a list of hex values
cat hexlist.txt | sed 's/^0x//'
```

---

### awk

> Powerful line-based processing and reporting.
> **Docs:** [GNU `gawk` manual](https://www.gnu.org/software/gawk/manual/gawk.html)

* **Tags:** `general`, `forensics`, `crypto`, `reverse`
* **Typical uses:**

  * Extract specific columns from structured data.
  * Perform simple arithmetic or conditionals.

**Common patterns:**

* `awk '{print $1}' file` – print first column.
* `awk -F, '{print $2}' file.csv` – comma-separated fields.
* `awk '$3 > 100 {print $1, $3}' file` – conditional filtering.

**Example:**

```bash
# Extract the second column of a space-separated list
cat data.txt | awk '{print $2}'

# From a CSV: print usernames with score > 9000
awk -F, '$3 > 9000 {print $1}' scores.csv
```

---

### hexdump

> Another way to inspect raw bytes.
> **Docs:** [`hexdump` man page](https://man7.org/linux/man-pages/man1/hexdump.1.html)

* **Tags:** `general`, `reverse`, `forensics`
* **Typical uses:**

  * Quick hex view of a file.
  * Look at specific ranges with `-n` (length) or `-s` (skip).

**Example:**

```bash
hexdump -C mystery.bin | head
# -C gives canonical hex+ASCII output
```

---

### tar / zip / unzip

> Archive and extract files.
> **Docs:** [GNU `tar` manual](https://www.gnu.org/software/tar/manual/) · [Info-ZIP `zip`](https://infozip.sourceforge.net/Zip.html) · [Info-ZIP `unzip`](https://infozip.sourceforge.net/UnZip.html)

* **Tags:** `forensics`, `general`
* **Typical uses:**

  * Extract multi-layer archives (common in forensics/misc).
  * Combine with `file` and `binwalk` when weird archives appear.

**Examples:**

```bash
# Extract a tar archive
tar -xf archive.tar

# Extract a zip archive
unzip archive.zip

# Create a zip (for your own packaging)
zip out.zip file1 file2 dir/*
```

---

### nc (netcat)

> “Swiss army knife” for TCP/UDP sockets.
> **Docs:** [`nc` (netcat-openbsd) man page](https://manpages.debian.org/unstable/netcat-openbsd/nc.1.en.html)

* **Tags:** `pwn`, `recon`, `web`, `misc`
* **Typical uses:**

  * Connect to remote CTF services.
  * Set up a quick listener for reverse shells or debug output.

**Examples:**

```bash
# Connect to a remote pwn challenge
nc challenge.ctf.net 31337

# Simple TCP listener
nc -lvp 4444
```

---

### curl / wget

> Command-line HTTP clients.
> **Docs:** [`curl` docs](https://curl.se/docs/) · [GNU Wget manual](https://www.gnu.org/software/wget/manual/wget.html)

* **Tags:** `web`, `recon`, `forensics`
* **Typical uses:**

  * Interact with web APIs.
  * Download challenge files.
  * Replay crafted HTTP requests.

**Examples:**

```bash
# Basic GET request
curl http://example.com/

# Send POST data
curl -X POST -d "user=test&pass=1234" http://target/login

# Add headers (cookies, user-agent, etc.)
curl -H "Cookie: admin=1" http://target/secret

# Download a file
wget http://example.com/challenge.tar.gz
```

---

## Network Recon & Scanning

### nmap

> Network scanner and service enumerator.
> **Docs:** [Nmap.org](https://nmap.org/) · [Nmap Reference Guide](https://nmap.org/book/man.html)

* **Tags:** `recon`, `network`, `web`
* **Typical uses:**

  * Find open ports and services.
  * Detect service versions and OS fingerprints.

**Common scans:**

```bash
# Fast scan of common ports
nmap -sC -sV target     # -sC: default scripts, -sV: version detect

# All TCP ports
nmap -p- target

# Top 1000 ports, aggressive detection
nmap -A target
```

---

### masscan

> Extremely fast port scanner.
> **Docs:** [`masscan` GitHub](https://github.com/robertdavidgraham/masscan)

* **Tags:** `recon`, `network`
* **Typical uses:**

  * Scan a large range quickly (useful in big “internet-wide scan” style challenges).

**Example:**

```bash
# Scan all ports quickly (be careful on the internet)
sudo masscan -p1-65535 10.0.0.0/24 --rate 10000
```

---

### traceroute / mtr

> Trace hops between you and the target.
> **Docs:** [`traceroute` man page](https://man7.org/linux/man-pages/man8/traceroute.8.html) · [`mtr` home](https://www.bitwizard.nl/mtr/)

* **Tags:** `recon`, `network`
* **Typical uses:**

  * Occasionally used in networking challenges to inspect paths, TTL behavior, etc.

**Examples:**

```bash
traceroute target.com
mtr target.com
```

---

## Web Exploitation

### Burp Suite

> Intercepting proxy for web pentesting.
> **Docs:** [PortSwigger Burp Suite](https://portswigger.net/burp) · [Burp documentation](https://portswigger.net/burp/documentation)

* **Tags:** `web`, `recon`, `auth`, `xss`, `sqli`
* **Typical uses:**

  * Intercept and modify HTTP(S) requests.
  * Replay and fuzz parameters with Repeater/Intruder.

**Key components:**

* **Proxy** – intercept browser traffic.
* **Repeater** – manually tweak and resend requests.
* **Intruder** – fuzz parameters or automate pattern testing.

---

### ffuf

> Fast web fuzzer.
> **Docs:** [`ffuf` GitHub](https://github.com/ffuf/ffuf)

* **Tags:** `web`, `recon`
* **Typical uses:**

  * Discover hidden directories, files, parameters, and virtual hosts.

**Examples:**

```bash
# Directory brute force
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Fuzz parameter values
ffuf -u 'http://target/page?id=FUZZ' -w ids.txt

# VHost discovery (Host header)
ffuf -u http://target/ -H 'Host: FUZZ.target' -w subdomains.txt
```

---

### sqlmap

> Automated SQL injection exploitation tool.
> **Docs:** [sqlmap.org](https://sqlmap.org/)

* **Tags:** `web`, `sqli`
* **Typical uses:**

  * Detect and exploit SQL injection via GET/POST/cookies.
  * Dump DB contents or read files.

**Examples:**

```bash
# Simple test on a vulnerable URL
sqlmap -u "http://target/item.php?id=1" --batch

# Use a captured request file from Burp
sqlmap -r request.txt --batch

# Enumerate databases and dump a specific table
sqlmap -u "http://target/item.php?id=1" --dbs
sqlmap -u "http://target/item.php?id=1" -D ctfdb -T users --dump
```

---

### wfuzz

> Web fuzzer similar to ffuf, with flexible payloads.
> **Docs:** [`wfuzz` GitHub](https://github.com/xmendez/wfuzz)

* **Tags:** `web`, `recon`
* **Typical uses:**

  * Fuzz parameters, headers, and parts of URL with multiple payload types.

**Example:**

```bash
wfuzz -c -z file,wordlist.txt --hc 404 http://target/FUZZ
```

---

### Postman / HTTPie

> Friendly HTTP clients.
> **Docs:** [Postman](https://www.postman.com/) · [HTTPie docs](https://httpie.io/docs)

* **Tags:** `web`, `api`, `forensics`
* **Typical uses:**

  * Craft complex API requests with JSON bodies and headers (Postman).
  * Quick terminal-based API testing (HTTPie).

**Example (HTTPie):**

```bash
http POST http://target/api/login user=admin pass=admin
http GET http://target/api/data Authorization:"Bearer TOKEN"
```

---

## Crypto & Encoding

### CyberChef

> Browser-based “Cyber Swiss Army Knife”.
> **Docs:** [CyberChef app](https://gchq.github.io/CyberChef/)

* **Tags:** `crypto`, `encoding`, `forensics`, `misc`
* **Typical uses:**

  * Decode/encode Base64, hex, URL, ROT, XOR, etc.
  * Apply multiple operations in a pipeline to peel layers of obfuscation.

*No CLI; open it in a browser, paste data, and experiment with operations.*

---

### hashcat

> GPU-accelerated password cracker.
> **Docs:** [hashcat.net](https://hashcat.net/hashcat/)

* **Tags:** `crypto`, `passwords`, `forensics`
* **Typical uses:**

  * Crack hash challenges (MD5, SHA-1, bcrypt, NTLM, etc.).

**Example:**

```bash
# Simple wordlist attack on MD5 hashes
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# NTLM (e.g., Windows LM/NTLM)
hashcat -m 1000 -a 0 ntlm_hashes.txt wordlist.txt
```

---

### John the Ripper

> Classic password cracker.
> **Docs:** [Openwall John the Ripper](https://www.openwall.com/john/)

* **Tags:** `crypto`, `passwords`, `forensics`
* **Typical uses:**

  * Crack Linux `/etc/shadow` hashes, archive passwords, etc.

**Examples:**

```bash
# Prepare a zip for cracking
zip2john secret.zip > secret.hash
john secret.hash --wordlist=rockyou.txt

# Linux password hashes
john shadow.hashes --wordlist=rockyou.txt
```

---

### openssl

> General-purpose crypto toolkit.
> **Docs:** [OpenSSL docs](https://www.openssl.org/docs/)

* **Tags:** `crypto`, `encoding`, `forensics`
* **Typical uses:**

  * Generate hashes.
  * Encrypt/decrypt with simple ciphers.
  * Inspect TLS certs.

**Examples:**

```bash
# Calculate SHA256 hash
echo -n "test" | openssl dgst -sha256

# Base64 encode/decode
echo -n "secret" | openssl enc -base64
echo "c2VjcmV0" | openssl enc -d -base64

# Inspect a certificate
openssl x509 -in cert.pem -text -noout
```

---

## Reverse Engineering

### Ghidra

> Full-featured reverse engineering suite.
> **Docs:** [Ghidra official site](https://ghidra-sre.org)

* **Tags:** `reverse`, `pwn`
* **Typical uses:**

  * Decompile binaries to C-like pseudocode.
  * Rename functions and variables to understand logic.

---

### IDA Free

> Disassembler with limited free version.
> **Docs:** [IDA Free](https://hex-rays.com/ida-free)

* **Tags:** `reverse`, `pwn`
* **Typical uses:**

  * Analyze binaries; follow cross-references and call graphs.

---

### radare2 / rizin

> Scriptable reversing frameworks.
> **Docs:** [radare2](https://rada.re/n/radare2.html) · [rizin](https://rizin.re/)

* **Tags:** `reverse`, `pwn`, `forensics`
* **Typical uses:**

  * Command-line-driven analysis and patching.
  * Great when disassembly is needed on headless systems.

---

### strings (for reverse engineering)

> Lightweight first-pass reversing helper (see [strings](#strings)).
> **Docs:** [GNU `strings` manual](https://sourceware.org/binutils/docs/binutils/strings.html)

* **Tags:** `reverse`
* **Typical uses:**

  * Find messages, error strings, and potential format strings.
  * Get quick hints before firing up a heavy GUI.

---

## Binary Exploitation (Pwn)

### gdb + pwndbg / GEF

> Debugger + pwn-focused plugins.
> **Docs:** [GDB](https://www.gnu.org/software/gdb/) · [`pwndbg` GitHub](https://github.com/pwndbg/pwndbg) · [`GEF` docs](https://hugsy.github.io/gef/)

* **Tags:** `pwn`, `reverse`
* **Typical uses:**

  * Step through code, inspect registers and memory.
  * Visualize stack, heap, and GOT/PLT.

**Example:**

```bash
gdb ./vuln
# Inside gdb:
run
break *main
info registers
x/40xw $rsp
```

---

### pwntools

> Python framework for pwn scripts.
> **Docs:** [pwntools docs](https://docs.pwntools.com/en/stable/) · [pwntools GitHub](https://github.com/Gallopsled/pwntools)

* **Tags:** `pwn`, `automation`
* **Typical uses:**

  * Interact with local/remote binaries (`process`, `remote`).
  * Build ROP chains, encode/decode values, parse ELF/libc.

**Example:**

```python
from pwn import *

p = remote('challenge.ctf.net', 31337)
payload = b'A' * 40 + p64(0xdeadbeef)
p.sendline(payload)
p.interactive()
```

---

### ROPgadget / Ropper

> Tools to find gadgets and build ROP chains.
> **Docs:** [ROPgadget GitHub](https://github.com/JonathanSalwan/ROPgadget) · [Ropper GitHub](https://github.com/sashs/Ropper)

* **Tags:** `pwn`, `reverse`
* **Typical uses:**

  * Search binaries for useful gadgets (`pop rdi; ret`, etc.).
  * Help construct ROP chains to call functions like `system("/bin/sh")`.

**Examples:**

```bash
# Find gadgets using ROPgadget
ROPgadget --binary ./vuln | grep "pop rdi"

# Find gadgets using ropper
ropper --file ./vuln --search "pop rdi"
```

---

## Forensics & Stego

### Wireshark

> GUI network protocol analyzer.
> **Docs:** [Wireshark.org](https://www.wireshark.org/)

* **Tags:** `forensics`, `network`
* **Typical uses:**

  * Inspect `.pcap` files.
  * Follow TCP streams to read plaintext credentials or flags.

**Common tricks:**

* Use **Follow TCP Stream**.
* Filter with `http`, `dns`, `tcp.port == 80`, `frame contains "CTF{"`.

---

### tshark

> CLI version of Wireshark.
> **Docs:** [TShark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html)

* **Tags:** `forensics`, `network`, `automation`
* **Typical uses:**

  * Filter and extract fields from pcaps in scripts.

**Examples:**

```bash
# List HTTP hosts
tshark -r capture.pcap -Y http.host -T fields -e http.host | sort -u

# Search for flag-like strings
tshark -r capture.pcap -V | grep -i 'ctf{'
```

---

### binwalk

> Firmware and binary extraction tool.
> **Docs:** [`binwalk` GitHub](https://github.com/ReFirmLabs/binwalk)

* **Tags:** `forensics`, `stego`, `reverse`
* **Typical uses:**

  * Extract embedded files (images, archives, file systems) from a binary blob.

**Examples:**

```bash
# Scan file
binwalk firmware.bin

# Extract everything
binwalk -e firmware.bin
```

---

### Steghide / zsteg / stegsolve

> Steganography helpers for images and other media.
> **Docs:** [Steghide](https://steghide.sourceforge.net/) · [zsteg GitHub](https://github.com/zed-0xff/zsteg) · [stegsolve info](https://www.aldeid.com/wiki/Stegsolve)

* **Tags:** `stego`, `forensics`
* **Typical uses:**

  * Extract hidden data from images or audio.

**Examples:**

```bash
# Steghide extraction (password often hinted in challenge)
steghide extract -sf image.jpg

# zsteg for PNG/BMP LSB tricks
zsteg image.png

# stegsolve (GUI) for viewing bit planes and color channels
java -jar StegSolve.jar
```

---

### Volatility / Volatility3

> Memory forensics frameworks.
> **Docs:** [Volatility Foundation](https://volatilityfoundation.org/) · [Volatility3 GitHub](https://github.com/volatilityfoundation/volatility3)

* **Tags:** `forensics`
* **Typical uses:**

  * Analyze RAM dumps to find processes, command lines, keystrokes, etc.

**Example:**

```bash
# (Plugins and syntax depend on OS/Volatility version)
vol.py -f memdump.raw windows.pslist
vol.py -f memdump.raw windows.cmdline
```

---

### exiftool

> Metadata viewer/editor for images and many file types.
> **Docs:** [ExifTool home](https://exiftool.org/)

* **Tags:** `forensics`, `stego`
* **Typical uses:**

  * Read EXIF metadata from images, documents, etc.
  * Metadata often hides hints or even whole flags.

**Example:**

```bash
exiftool suspect.jpg
```

---

## Misc Utilities & Automation

### Python

> Scripting language for automation, quick solvers, and glue code.
> **Docs:** [Python.org](https://www.python.org/)

* **Tags:** `misc`, `automation`, `crypto`, `pwn`, `web`
* **Typical uses:**

  * Decode custom encodings.
  * Automate repetitive tasks.
  * Talk to sockets, build custom crypto, etc.

**Example:**

```bash
python3 -c "import base64; print(base64.b64decode('aGVsbG8='))"
```

---

### jq

> Command-line JSON processor.
> **Docs:** [jq manual](https://jqlang.org/manual/)

* **Tags:** `web`, `api`, `forensics`, `misc`
* **Typical uses:**

  * Parse JSON from APIs or logs.
  * Filter/transform JSON documents.

**Example:**

```bash
curl -s http://target/api/data | jq '.items[] | {id, name}'
```

---

### git

> Version control system.
> **Docs:** [git-scm.com](https://git-scm.com/)

* **Tags:** `misc`, `dev`, `forensics`
* **Typical uses:**

  * Manage your own exploit scripts and notes.
  * Inspect `.git` folders leaked on web servers (`/.git/` challenges).

**Example:**

```bash
git clone https://github.com/your-team/ctf-scripts.git
```

---

> **Tip for students:** When stuck, think:
>
> * *What kind of challenge is this?* (web, pwn, crypto, reverse, forensics, stego, misc)
> * Search this document for that category or tag.
> * Try the suggested tools and example commands before giving up.

```


