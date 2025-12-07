Here’s a clean `docs/cheatsheet.md` you can drop in:

````markdown
# CTF Tools Cheat Sheet

Quick, high-signal reference for common CTF actions.  
For detailed explanations and links to docs, see the main **CTF Toolbox** page.

---

## 0. What Kind of Challenge Is This?

| You see / get...                                  | Likely category            | Start with these tools                           |
|---------------------------------------------------|----------------------------|--------------------------------------------------|
| URL / web app                                     | Web                        | Burp Suite, `ffuf`, `sqlmap`, `curl`, HTTPie    |
| Binary (no source)                                | Pwn / Reverse              | `file`, `strings`, Ghidra, `gdb`, pwntools      |
| PCAP / `.pcapng`                                  | Forensics / Network        | Wireshark, `tshark`, `strings`                  |
| Image / audio file                                | Stego / Forensics          | `file`, `exiftool`, Steghide, zsteg, binwalk    |
| Weird encoded text / random symbols               | Crypto / Misc              | CyberChef, `xxd`, `openssl`, Python             |
| Hashes / password dump                            | Crypto / Passwords         | hashcat, John the Ripper                        |
| Memory dump                                       | Forensics                  | Volatility / Volatility3                        |
| “Connect to host:port and interact”               | Pwn / Misc                 | `nc`, `nmap`, pwntools                          |

---

## 1. Absolute Core CLI

### `file` – Identify what a thing is

```bash
file mystery.dat
````

Use when: you have any unknown file.
Helps you decide: image? binary? archive? pcap? text?

---

### `strings` – Hunt for obvious clues/flags

```bash
strings suspect.bin | grep -i 'ctf{'
strings -t x dump.raw | grep -i key
```

Use when: you have a binary, dump, or weird file and just want to see readable text.

---

### `xxd` / `hexdump` – Look at raw bytes

```bash
xxd -g 1 challenge.bin | head
hexdump -C challenge.bin | head
```

Use when: you need to see offsets + bytes (patching, custom encodings, weird headers).

---

### `grep` – Filter big outputs

```bash
grep -ri 'password' .
strings big_dump.bin | grep -i 'ctf{'
```

Use when: you’re buried in output and want to find the interesting lines.

---

### `sed` / `awk` – Quick text reshaping

```bash
# Replace ':' with newlines
echo "aa:bb:cc:dd" | sed 's/:/\n/g'

# Second column of a space-separated file
awk '{print $2}' data.txt
```

Use when: you need to clean or re-format data to feed into another tool.

---

## 2. Web & HTTP

### Burp Suite – Intercept + tamper

Typical workflow:

1. Set browser proxy to Burp.
2. Browse the challenge site.
3. Send interesting requests to **Repeater** / **Intruder**.

Use Burp to:

* See all parameters, cookies, headers.
* Flip booleans like `admin=false` → `admin=true`.
* Replay login requests or JSON API calls.

---

### `ffuf` – Fuzz paths and parameters

```bash
# Find hidden paths/directories
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Fuzz ID parameter
ffuf -u 'http://target/item?id=FUZZ' -w ids.txt
```

Use when: you suspect `/admin`, `/backup`, `/secret.php`, etc.
Watch for non-404 responses or different response sizes.

---

### `sqlmap` – Easy SQLi wins

```bash
sqlmap -u "http://target/item.php?id=1" --batch
# Using a Burp request
sqlmap -r request.txt --batch
```

Use when: a parameter looks injectable (`id=1`, `page=2`), especially if errors or weird behavior appear when you add `'` or `ORDER BY` tricks.

---

### `curl` / HTTPie – Replaying HTTP

```bash
# curl
curl -X POST -d "user=admin&pass=admin" http://target/login
curl -H "Cookie: admin=1" http://target/secret

# HTTPie
http POST http://target/login user=admin pass=admin
http GET http://target/secret Cookie:"admin=1"
```

Use when: you want scriptable, repeatable HTTP requests without a browser.

---

## 3. Pwn & Binary Exploitation

### `nc` – Connect to the service

```bash
nc challenge.ctf.net 31337
```

Use when: the prompt says “Connect with netcat to host:port.”

---

### `gdb` + pwndbg/GEF – Understand what the binary does

```bash
gdb ./vuln
# Inside gdb:
run
break *main
info registers
x/40xw $rsp
```

Use when: you need to see stack layout, crashes, or how your input affects registers.

---

### pwntools – Script your exploit

```python
from pwn import *

p = remote('challenge.ctf.net', 31337)
payload = b'A' * 40 + p64(0xdeadbeef)
p.sendline(payload)
p.interactive()
```

Use when: you’re past manual testing and want a repeatable exploit that works locally and remotely.

---

### Quick pwn checklist

1. `file ./vuln` (check 32/64-bit, PIE, NX, etc.).
2. Optionally `checksec ./vuln` if available.
3. Run with various input sizes; notice crashes.
4. Use `gdb` to find the offset to the return address.
5. Build an exploit script with pwntools.

---

## 4. Reverse Engineering

### Quick triage

```bash
file mystery
strings mystery | head
```

If it’s an ELF/PE and expects input:

* Try running it with random input.
* Then open in Ghidra or IDA Free to see the validation logic.

---

### Ghidra – See the logic in (almost) C

Basic flow:

1. Import binary → analyze.
2. Find `main`.
3. Look for string references (menu text, errors, “wrong password”), comparisons, and calls to `strcmp` / `memcmp`.

Use when: binary is not trivial and you need to understand the algorithm or flag check.

---

## 5. Forensics & Stego

### Wireshark / `tshark` – PCAP analysis

GUI (Wireshark):

* Open the pcap file.
* Try filters: `http`, `dns`, `tcp.port == 80`, `frame contains "CTF{"}`.
* Right-click → “Follow TCP Stream” to see conversations.

CLI (`tshark`):

```bash
# Unique HTTP hosts
tshark -r capture.pcap -Y http.host -T fields -e http.host | sort -u

# Grep for flags
tshark -r capture.pcap -V | grep -i 'ctf{'
```

---

### `exiftool` – Metadata / hidden hints

```bash
exiftool suspect.jpg
```

Use when: you have an image or document and suspect metadata (Author, Comment, GPS, etc.) might contain a clue or flag.

---

### Steghide / zsteg – Stego basics

```bash
# Steghide (needs password – often hinted in challenge)
steghide extract -sf image.jpg

# zsteg for PNG/BMP
zsteg image.png
```

Use when: the challenge strongly hints that something is hidden inside an image.

---

### binwalk – Embedded stuff in binaries/images/firmware

```bash
binwalk firmware.bin      # See what’s inside
binwalk -e firmware.bin   # Extract everything it finds
```

Use when: you suspect embedded archives/filesystems/images inside a big blob.

---

## 6. Crypto, Encoding, and Weird Text

### CyberChef – “Try all the things” in a browser

Paste the suspicious string and try:

* Magic
* From Base64
* From Hex
* ROT13 / Caesar
* XOR (single-byte or brute-force)
* URL decoding

Use when: text looks encoded/obfuscated and you don’t know where to start.

---

### `openssl` – Hashes and Base64 from CLI

```bash
# SHA256
echo -n "test" | openssl dgst -sha256

# Base64 encode
echo -n "secret" | openssl enc -base64

# Base64 decode
echo "c2VjcmV0" | openssl enc -d -base64
```

Use when: you need quick hashes or base64 without opening CyberChef.

---

### hashcat / John – Password cracking

```bash
# hashcat, MD5 with wordlist
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# John, zip passwords
zip2john secret.zip > secret.hash
john secret.hash --wordlist=rockyou.txt
```

Use when: the challenge gives you hashes or encrypted archives and expects cracking.

---

## 7. JSON, APIs, and Automation

### `jq` – JSON wrangler

```bash
curl -s http://target/api/data | jq '.items[] | {id, name}'
```

Use when: an API returns complex JSON and you want to extract specific fields.

---

### Python one-liners

```bash
# Base64 decode
python3 -c "import base64; print(base64.b64decode('aGVsbG8='))"

# Simple XOR with 0x42
python3 -c "print(bytes([b ^ 0x42 for b in bytes.fromhex('414243')]))"
```

Use when: a challenge uses a simple/custom encoding; Python is faster than doing it by hand.

---

## 8. Minimal Workflow When Stuck

1. Identify the artifact
   Use `file`, `strings`, `hexdump`, `exiftool`.

2. Categorize
   web / pwn / reverse / forensics / stego / crypto.

3. Pick 1–2 tools from the table at the top
   Try the obvious commands first.

4. Only then go deeper
   Ghidra, pwntools scripts, custom Python, etc.

When you get lost, come back to this cheat sheet and the full toolbox.

```
::contentReference[oaicite:0]{index=0}
```
